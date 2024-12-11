package frost_dkg_multisig

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"tee-dao/comm"
	"tee-dao/logger"
	"time"
	"unsafe"
)

// Participant struct holds fields for DKG and signing and uses Communicator as the communication layer.
type Participant struct {
	name                      string
	id                        int
	numParticipants           int
	minSigner                 int
	idNameMap                 map[int]string
	config                    *comm.Config
	communicator              *comm.Communicator // Communication layer
	context                   []byte
	tag                       []byte
	commitments               map[int]*Secp256k1FrostVssCommitments
	secretShares              map[int]*Secp256k1FrostKeygenSecretShare
	sequence                  int // Sequence number for the message signature
	initiator                 map[int]int
	signingMessage            map[int][]byte
	readyForPreprocessingNum  map[int]int
	nonces                    map[int]*Secp256k1FrostNonce
	nonceCommitments          map[int]map[int]Secp256k1FrostNonceCommitment
	readyForSignNum           map[int]map[int]int
	keypair                   *Secp256k1FrostKeypair
	publicKeys                map[int]Secp256k1FrostPubkey
	signatureShares           map[int]map[int]*Secp256k1FrostSignatureShare
	aggregatedSig             map[int][]byte
	signatureChan             chan []byte
	dkgLeader                 string
	isDKGLeader               bool // Whether this participant is the leader
	dkgCompleted              bool // Flag to indicate if DKG is complete
	readyForInitPreprocessing bool
	preprocessingComplete     bool           // Flag to indicate if preprocessing is complete
	wg                        sync.WaitGroup // New WaitGroup for message loop
	ctx                       context.Context
	cancel                    context.CancelFunc
	logger                    *slog.Logger
}

// NewParticipant initializes a new participant with communicator.
func NewParticipant(dkgLeader string, config *comm.Config, isDKGLeader bool, id int, numParticipants int, minSigner int, signContext []byte, tag []byte) (*Participant, error) {
	idNameMapping := make(map[int]string)
	for _, peer := range config.Peers {
		idNameMapping[peer.ID] = peer.Name
	}
	idNameMapping[config.ID] = config.Name // Include self in the mapping as well

	commLayer, err := comm.NewCommunicator(config)
	if err != nil {
		return nil, err
	}

	// Initialize context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	p := &Participant{
		name:                      config.Name,
		id:                        id,
		numParticipants:           numParticipants,
		minSigner:                 minSigner,
		idNameMap:                 idNameMapping,
		config:                    config,
		communicator:              commLayer,
		context:                   signContext,
		tag:                       tag,
		commitments:               make(map[int]*Secp256k1FrostVssCommitments),
		secretShares:              make(map[int]*Secp256k1FrostKeygenSecretShare),
		sequence:                  0,
		initiator:                 make(map[int]int),
		signingMessage:            make(map[int][]byte),
		readyForPreprocessingNum:  make(map[int]int),
		nonces:                    make(map[int]*Secp256k1FrostNonce),
		nonceCommitments:          make(map[int]map[int]Secp256k1FrostNonceCommitment),
		readyForSignNum:           make(map[int]map[int]int),
		keypair:                   &Secp256k1FrostKeypair{},
		publicKeys:                make(map[int]Secp256k1FrostPubkey),
		signatureShares:           make(map[int]map[int]*Secp256k1FrostSignatureShare),
		aggregatedSig:             make(map[int][]byte),
		signatureChan:             make(chan []byte),
		dkgLeader:                 dkgLeader,
		isDKGLeader:               isDKGLeader,
		dkgCompleted:              false,
		readyForInitPreprocessing: false,
		preprocessingComplete:     false,
		wg:                        sync.WaitGroup{},
		ctx:                       ctx,
		cancel:                    cancel,
		logger:                    logger.New(slog.LevelInfo).With("participant", config.Name),
	}

	// Register custom message handlers
	p.communicator.RegisterHandler("DKGSecretShare", DKGSecretShare, p.handleDKGSecretShare)
	p.communicator.RegisterHandler("ReadyForPreprocessing", ReadyForPreprocessing, p.handleReadyForPreprocessing)
	p.communicator.RegisterHandler("PreprocessingRequest", PreprocessingRequest, p.handlePreprocessingRequest)
	p.communicator.RegisterHandler("NonceCommitmentExchange", NonceCommitmentExchange, p.handleNonceCommitmentExchange)
	p.communicator.RegisterHandler("ReadyForSign", ReadyForSign, p.handleReadyForSign)
	p.communicator.RegisterHandler("SignRequest", SignRequest, p.handleSignRequest)
	p.communicator.RegisterHandler("SignatureShareResponse", SignatureShareResponse, p.handleSignatureShareResponse)

	// Register the RPC services for client requests
	rpcService := &SignatureService{participant: p}
	err = p.communicator.RegisterRPCService(rpcService)
	if err != nil {
		return nil, err
	}

	return p, nil
}

// Start initializes and starts the communicator
func (p *Participant) Start() error {

	// Add to the WaitGroup for handling messages
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.communicator.Start()

		// Listen indefinitely for messages or until context is canceled
		<-p.ctx.Done()
		p.logger.Info("Participant stopped listening for messages.")
	}()

	time.Sleep(10 * time.Second)
	p.initiateDKG()
	return nil
}

// Close shuts down the communicator
func (p *Participant) Close() error {
	// Cancel the context to stop the message handling loop
	p.cancel()

	// Close the communicator
	if p.communicator != nil {
		p.communicator.Close()
	}

	// Wait for all goroutines in the WaitGroup to finish
	p.wg.Wait()
	p.logger.Info("Participant shut down.")
	return nil
}

// sendMessage sends a message to a specific participant.
func (p *Participant) sendMessage(peerName string, msg comm.Message) error {
	messageBytes, err := msg.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize message: %v", err)
	}
	return p.communicator.SendMessage(peerName, messageBytes)
}

// broadcast sends a message to all other participants.
func (p *Participant) broadcast(msg comm.Message) error {
	messageBytes, err := msg.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize message: %v", err)
	}
	return p.communicator.Broadcast(messageBytes)
}

// Function to get ID by name
func (p *Participant) GetIDByName(name string) (int, bool) {
	for id, n := range p.idNameMap {
		if n == name {
			return id, true
		}
	}
	return 0, false // or any appropriate zero-value for ID
}

// initiateDKG starts the DKG process for the participant
func (p *Participant) initiateDKG() {
	p.logger.Info("Starting DKG...")

	commitments := &Secp256k1FrostVssCommitments{}
	sharesByParticipant := make([]Secp256k1FrostKeygenSecretShare, p.numParticipants)

	// Call DKG Begin
	p.logger.With("func", "initiateDKG").Debug("Generating secret key share", "id", p.id, "numParticipants", p.numParticipants, "minSigner", p.minSigner, "shares", sharesByParticipant, "commitments", commitments)
	result := KeygenDKGBegin(
		&commitments,              // Each participant's commitment
		sharesByParticipant,       // Secret shares for each participant
		uint32(p.numParticipants), // Number of participants
		uint32(p.minSigner),       // Threshold for signing
		uint32(p.id+1),            // Generator index (participant's index)
		p.context,                 // Context for the DKG
	)
	if result != 1 {
		p.logger.With("func", "initiateDKG").Error("Failed in DKG Begin")
		return
	}
	p.logger.With("func", "initiateDKG").Debug("Secret key share generated", "shares", sharesByParticipant, "commitments", commitments)
	result = KeygenDKGCommitmentValidate(
		&commitments, // Peer’s commitment
		p.context,
	)
	if result != 1 {
		p.logger.With("func", "initiateDKG").Error("Failed in commitment validation")
		return
	}

	// Send the generated secret share for other participants
	// Exchange secret shares between participants
	for i := 0; i < p.numParticipants; i++ {
		if i == p.id {
			// Store the generated secret share and commitment for self
			p.secretShares[p.id] = &sharesByParticipant[p.id]
			p.commitments[p.id] = commitments
		} else {
			shareWithCommitment := &SecretShareWithCommitment{sharesByParticipant[i], commitments}
			serializedShareWithCommitment, err := shareWithCommitment.Serialize()
			if err != nil {
				p.logger.With("func", "initiateDKG").Error("Failed to serialize share with commitment", "err", err)
				return
			}

			p.logger.Info("Send share with commitment", "to", p.idNameMap[i])
			shareWithCommitmentMsg := comm.Message{
				MsgType:  DKGSecretShare,
				Data:     serializedShareWithCommitment,
				From:     p.name,
				To:       p.idNameMap[i],
				CreateAt: time.Now(),
			}
			if err := p.sendMessage(p.idNameMap[i], shareWithCommitmentMsg); err != nil {
				p.logger.With("func", "initiateDKG").Error("Failed to send share with commitment", "to", p.idNameMap[i], "err", err)
				return
			}
		}
	}
}

// completeDKG signals that DKG is complete, setting dkgCompleted flag and sending ReadyForSign
func (p *Participant) completeDKG() {
	p.dkgCompleted = true
	p.readyForPreprocessingNum[p.id]++
	p.publicKeys[p.id] = p.keypair.PublicKeys
	p.logger.Info("Completed DKG")

	p.logger.With("func", "completeDKG").Debug("Broadcasting ReadyForPreprocessing")
	// Send ReadyForPreprocessing message to the leader
	var publicKey Secp256k1FrostPubkey
	result := PubkeyFromKeypair(&publicKey, p.keypair)
	if result != 1 {
		p.logger.With("func", "completeDKG").Error("Error in creating public key")
		return
	}

	p.logger.With("func", "completeDKG").Debug("Generated public key", "public key", publicKey)
	dkgComplete := &DKGComplete{
		PublicKey: publicKey,
		Complete:  true,
	}
	serializedDKGComplete, err := dkgComplete.Serialize()
	if err != nil {
		p.logger.With("func", "completeDKG").Error("Failed to serialize DKG complete", "err", err)
		return
	}

	readyMsg := comm.Message{
		MsgType:  ReadyForPreprocessing,
		Data:     serializedDKGComplete,
		From:     p.name,
		To:       "",
		CreateAt: time.Now(),
	}
	if err := p.broadcast(readyMsg); err != nil {
		p.logger.With("func", "completeDKG").Error("Failed to broadcast ReadyForPreprocessing", "err", err)
		return
	}
}

// initiatePreprocessing generate the nonce and sends commitment to all participants
func (p *Participant) initiatePreprocessing(message []byte) {
	p.logger.Info("Initiating preprocessing process")

	// Send PreprocessingRequest to all participants
	preprocessingRequest := &PreprocessingSequence{
		Sequence: p.sequence,
	}
	serializedPreprocessingRequest, err := preprocessingRequest.Serialize()
	if err != nil {
		p.logger.With("func", "initiatePreprocessing").Error("Failed to serialize preprocessing request", "err", err)
		return
	}

	preprocessingRequestMsg := comm.Message{
		MsgType:  PreprocessingRequest,
		Data:     serializedPreprocessingRequest,
		From:     p.name,
		To:       "",
		CreateAt: time.Now(),
	}
	if err := p.broadcast(preprocessingRequestMsg); err != nil {
		p.logger.With("func", "initiatePreprocessing").Error("Failed to broadcast PreprocessingRequest", "err", err)
		return
	}

	// Generate nonce and send commitment to all participants
	var nonce = &Secp256k1FrostNonce{}
	result := CreateNonce(&nonce, p.keypair)
	if result != 1 {
		p.logger.With("func", "initiatePreprocessing").Error("Error in creating nonce in participant")
		return
	}
	p.logger.With("func", "initiatePreprocessing").Debug("Generate nonce and commitment", "Nonce", nonce, "Size", unsafe.Sizeof(*nonce))
	nonceCommitment := &NonceCommitment{p.sequence, nonce.Commitments}
	serializedNonceCommitment, err := nonceCommitment.Serialize()
	if err != nil {
		p.logger.With("func", "initiatePreprocessing").Error("Failed to serialize nonce commitment", "err", err)
		return
	}
	p.logger.With("func", "initiatePreprocessing").Debug("Generate nonce commitment msg", "nonce commitment", nonceCommitment)

	nonceCommitmentMsg := comm.Message{
		MsgType:  NonceCommitmentExchange,
		Data:     serializedNonceCommitment,
		From:     p.name,
		To:       "",
		CreateAt: time.Now(),
	}
	if err := p.broadcast(nonceCommitmentMsg); err != nil {
		p.logger.With("func", "initiatePreprocessing").Error("Failed to broadcast nonce commitment", "err", err)
		return
	}

	// Store the nonce for future signing
	p.initiator[p.sequence] = p.id
	p.signingMessage[p.sequence] = message
	p.nonces[p.sequence] = nonce
	p.nonceCommitments[p.sequence] = make(map[int]Secp256k1FrostNonceCommitment)
	p.nonceCommitments[p.sequence][p.id] = nonceCommitment.NonceCommitment
	p.sequence++
}

// completePreprocessing signals that preprocessing is complete, setting ReadyForSignNum flag and sending ReadyForSign
func (p *Participant) completePreprocessing(sequence int) {
	p.preprocessingComplete = true
	p.logger.Info("Completed preprocessing")

	// If the participant is the initiator, increment the ReadyForSignNum and return
	initiatorID, exist := p.initiator[sequence]
	if !exist {
		p.logger.With("func", "completePreprocessing").Error("Initiator not found for sequence", "sequence", sequence)
		return
	}
	if p.id == initiatorID {
		if p.readyForSignNum[sequence] == nil {
			p.readyForSignNum[sequence] = make(map[int]int)
		}
		p.readyForSignNum[sequence][p.id]++
		return
	}

	p.logger.Info("Sending ReadyForSign to initiator", "initiator", initiatorID)
	// Send ReadyForSign message to the initiator
	preprocessingComplete := &PreprocessingComplete{
		Sequence: sequence,
		Complete: true,
	}
	serializedPreprocessingComplete, err := preprocessingComplete.Serialize()
	if err != nil {
		p.logger.With("func", "completePreprocessing").Error("Failed to serialize preprocessing complete", "err", err)
		return
	}

	initiatorName := p.idNameMap[initiatorID]
	readyMsg := comm.Message{
		MsgType:  ReadyForSign,
		Data:     serializedPreprocessingComplete,
		From:     p.name,
		To:       initiatorName,
		CreateAt: time.Now(),
	}
	if err := p.sendMessage(initiatorName, readyMsg); err != nil {
		p.logger.With("func", "completePreprocessing").Error("Failed to send ReadyForSign to initiator", "initiator", initiatorName, "err", err)
		return
	}
}

// initiateSigning generates a random message and sends SignRequest to all participants
func (p *Participant) initiateSigning(sequence int) {
	msg, exist := p.signingMessage[sequence]
	if !exist {
		p.logger.With("func", "initiateSigning").Error("Message not found for sequence", "sequence", sequence)
		return
	}
	var msgHash [32]byte
	result := TaggedSha256(&msgHash, p.tag, msg)
	if result != 1 {
		p.logger.With("func", "initiateSigning").Error("Error in creating tagged msg hash")
		return
	}
	p.logger.With("func", "initiateSigning").Debug("Initiating signing process")

	// Randomly choose the minimum signers to send the SignRequest
	signers := []int{p.id}
	for i := 0; i < p.minSigner-1; i++ {
		for {
			randomSigner := rand.IntN(p.numParticipants)
			contains := false
			for _, signer := range signers {
				if signer == randomSigner {
					contains = true
					break
				}
			}
			if !contains {
				signers = append(signers, randomSigner)
				break
			}
		}
	}

	signMessage := &SignMessage{
		Sequence: sequence,
		Signers:  signers,
		Msg_hash: msgHash,
	}
	serializedSignMessage, err := signMessage.Serialize()
	if err != nil {
		p.logger.With("func", "initiateSigning").Error("Failed to serialize sign message", "err", err)
		return
	}

	for _, signer := range signers {
		if signer == p.id {
			continue
		}
		signerName := p.idNameMap[signer]
		signRequest := comm.Message{
			MsgType:  SignRequest,
			Data:     serializedSignMessage,
			From:     p.name,
			To:       signerName,
			CreateAt: time.Now(),
		}
		if err := p.sendMessage(signerName, signRequest); err != nil {
			p.logger.With("func", "initiateSigning").Error("Failed to send SignRequest", "to", signerName, "err", err)
			return
		}
	}
	p.logger.Info("Sent SignRequest to singers", "signers", signers)

	var nonceCommitment []Secp256k1FrostNonceCommitment
	if p.nonceCommitments[sequence] == nil {
		p.logger.With("func", "initiateSigning").Error("Nonce commitment not found for sequence", "sequence", sequence)
		return
	}
	for i := 0; i < p.minSigner; i++ {
		signerID := signers[i]
		if commitment, exist := p.nonceCommitments[sequence][signerID]; exist {
			nonceCommitment = append(nonceCommitment, commitment)
			if len(nonceCommitment) == len(p.nonceCommitments[sequence]) {
				break
			}
		} else {
			p.logger.With("func", "initiateSigning").Error("Nonce commitment not found for signer", "signer", signerID)
			return
		}
	}

	// Generate and send the signature share
	p.logger.With("func", "initiateSigning").Debug("Generating signature share", "msgHash", signMessage.Msg_hash, "minSigner", p.minSigner, "key pair", p.keypair, "nonces", p.nonces[signMessage.Sequence], "nonce commitment", nonceCommitment)
	var signatureShare Secp256k1FrostSignatureShare
	result = Sign(
		&signatureShare,
		msgHash[:],
		uint32(p.minSigner),
		p.keypair,
		p.nonces[sequence],
		nonceCommitment,
	)

	if result != 1 {
		p.logger.With("func", "initiateSigning").Error("Error in signing message")
		return
	}
	p.logger.With("func", "initiateSigning").Debug("Generated signature share", "signature share", signatureShare)
	if p.signatureShares[sequence] == nil {
		p.signatureShares[sequence] = make(map[int]*Secp256k1FrostSignatureShare)
	}
	p.signatureShares[sequence][p.id] = &signatureShare
}

// handleDKGSecretShare handles the DKG secret share message by verifying and storing the share.
func (p *Participant) handleDKGSecretShare(msg comm.Message) {
	p.logger.Info("Handling DKG Secret Share", "from", msg.From)

	// Deserialize the secret share directly
	var shareWithCommitment SecretShareWithCommitment
	if err := shareWithCommitment.Deserialize(msg.Data); err != nil {
		p.logger.With("func", "handleDKGSecretShare").Error("Failed to deserialize DKG secret share", "err", err)
		return
	}

	p.logger.With("func", "handleDKGSecretShare").Debug("Got DKG Secret share", "share", shareWithCommitment.SecretShare, "commitments", shareWithCommitment.Commitments)

	// Verify and store the share and commitment
	result := KeygenDKGCommitmentValidate(
		&shareWithCommitment.Commitments, // Peer’s commitment
		p.context,
	)
	if result != 1 {
		p.logger.With("func", "handleDKGSecretShare").Error("Invalid generator index in DKG secret share", "from", msg.From)
		return
	}

	senderID, exist := p.GetIDByName(msg.From)
	if !exist {
		p.logger.With("func", "handleDKGSecretShare").Error("Participant does not exist", "from", msg.From)
		return
	}
	p.logger.With("func", "handleDKGSecretShare").Debug("Stored DKG secret share with commitment", "from", msg.From)
	p.secretShares[senderID] = &shareWithCommitment.SecretShare
	p.commitments[senderID] = shareWithCommitment.Commitments

	// Check if received enough secret shares to finalize DKG
	if len(p.secretShares) == p.numParticipants {
		// Convert the secret shares and commitments map to slices
		sharesByParticipant := make([]Secp256k1FrostKeygenSecretShare, p.numParticipants)
		for i := 0; i < p.numParticipants; i++ {
			sharesByParticipant[i] = *p.secretShares[i]
			p.logger.With("func", "handleDKGSecretShare").Debug("Shares", "index", i, "sharesByParticipant", sharesByParticipant[i])
		}
		commitmentsPointers := make([]*Secp256k1FrostVssCommitments, p.numParticipants)
		for i := 0; i < p.numParticipants; i++ {
			commitmentsPointers[i] = p.commitments[i]
			p.logger.With("func", "handleDKGSecretShare").Debug("Commitments", "index", i, "commitments", commitmentsPointers[i])
		}

		p.logger.With("func", "handleDKGSecretShare").Debug("Finalizing DKG", "shares", sharesByParticipant, "commitments", commitmentsPointers, "id", p.id, "numParticipants", p.numParticipants)
		result = KeygenDKGFinalize(
			p.keypair,
			uint32(p.id+1),
			uint32(p.numParticipants),
			sharesByParticipant,
			commitmentsPointers,
		)
		if result != 1 {
			p.logger.With("func", "handleDKGSecretShare").Error("Error in DKG Finalize")
			return
		}
		p.logger.With("func", "handleDKGSecretShare").Debug("Finalized DKG", "keypair", p.keypair)
		p.completeDKG()
	}
}

// handleReadyForPreprocessing processes ReadyForPreprocessing messages from participants, and once all are ready, initiates signing
func (p *Participant) handleReadyForPreprocessing(msg comm.Message) {
	p.logger.With("func", "handleReadyForPreprocessing").Debug("Received ReadyForPreprocessing", "from", msg.From)

	// Deserialize the DKGComplete directly
	var dkgComplete DKGComplete
	if err := dkgComplete.Deserialize(msg.Data); err != nil {
		p.logger.With("func", "handleReadyForPreprocessing").Error("Failed to deserialize DKG complete", "err", err)
		return
	}

	// Check if DKG is complete
	if !dkgComplete.Complete {
		p.logger.With("func", "handleReadyForPreprocessing").Error("DKG is not complete. Ignoring ReadyForPreprocessing", "from", msg.From)
		return
	}

	senderID, exist := p.GetIDByName(msg.From)
	if !exist {
		p.logger.With("func", "handleReadyForPreprocessing").Error("Participant does not exist", "from", msg.From)
		return
	}

	p.logger.With("func", "handleReadyForPreprocessing").Debug("Store public key", "from", msg.From, "public key", dkgComplete.PublicKey)
	p.readyForPreprocessingNum[senderID]++
	p.publicKeys[senderID] = dkgComplete.PublicKey

	// Check if enough participants have sent ReadyForPreprocessing
	// TODO: In demo, we are assuming all participants have sent nonce commitments. Actually, only the minimum signers are needed but all the signer should have a consensus on the same set.
	if len(p.readyForPreprocessingNum) == p.numParticipants && p.dkgCompleted {
		p.logger.Info("All participants are ready. Waiting for client signing request.")
		p.readyForInitPreprocessing = true
	}
}

// handleReadyForSign processes ReadyForSign messages from participants, and once all are ready, initiates signing
func (p *Participant) handleReadyForSign(msg comm.Message) {
	p.logger.With("func", "handleReadyForSign").Debug("Received ReadyForSign", "from", msg.From)

	// Deserialize the PreprocessingComplete directly
	var preprocessingComplete PreprocessingComplete
	if err := preprocessingComplete.Deserialize(msg.Data); err != nil {
		p.logger.With("func", "handleReadyForSign").Error("Failed to deserialize preprocessing complete", "err", err)
		return
	}

	// Check if the participant is the initiator
	initiatorID, exist := p.initiator[preprocessingComplete.Sequence]
	if !exist {
		p.logger.With("func", "handleReadyForSign").Error("Initiator not found for sequence", "sequence", preprocessingComplete.Sequence)
		return
	}
	if p.id != initiatorID {
		p.logger.With("func", "handleReadyForSign").Error("Participant is not the initiator. Ignoring ReadyForSign", "from", msg.From)
		return
	}

	// Check if preprocessing is complete
	if !preprocessingComplete.Complete {
		p.logger.With("func", "handleReadyForSign").Error("Preprocessing is not complete. Ignoring ReadyForSign", "from", msg.From)
		return
	}

	senderID, exist := p.GetIDByName(msg.From)
	if !exist {
		p.logger.With("func", "handleReadyForSign").Error("Participant does not exist", "from", msg.From)
		return
	}

	if p.readyForSignNum[preprocessingComplete.Sequence] == nil {
		p.readyForSignNum[preprocessingComplete.Sequence] = make(map[int]int)
	}
	p.readyForSignNum[preprocessingComplete.Sequence][senderID]++

	// Check if enough participants have sent ReadyForSign
	// TODO: In demo, we are assuming all participants have sent nonce commitments. Actually, only the minimum signers are needed but all the signer should have a consensus on the same set.
	if len(p.readyForSignNum[preprocessingComplete.Sequence]) == p.numParticipants && p.preprocessingComplete {
		p.logger.Info("All participants are ready. Initiator initiating signing process.")
		p.initiateSigning(preprocessingComplete.Sequence)
	}
}

// handlePreprocessingRequest handles a request to preprocessing by generating a nonce and send the commitment.
func (p *Participant) handlePreprocessingRequest(msg comm.Message) {
	p.logger.With("func", "handlePreprocessingRequest").Debug("Received Preprocessing Request", "from", msg.From)

	// Deserialize PreprocessingRequest
	var preprocessingRequest PreprocessingSequence
	if err := preprocessingRequest.Deserialize(msg.Data); err != nil {
		p.logger.With("func", "handlePreprocessingRequest").Error("Failed to deserialize preprocessing request", "err", err)
		return
	}

	// Store the initiator for future signing
	initiatorID, exist := p.GetIDByName(msg.From)
	if !exist {
		p.logger.With("func", "handlePreprocessingRequest").Error("Participant does not exist", "from", msg.From)
		return
	}
	p.initiator[preprocessingRequest.Sequence] = initiatorID

	// Generate nonce and send commitment to all participants
	var nonce = &Secp256k1FrostNonce{}
	result := CreateNonce(&nonce, p.keypair)
	if result != 1 {
		p.logger.With("func", "handlePreprocessingRequest").Error("Error in creating nonce")
		return
	}
	p.logger.With("func", "handlePreprocessingRequest").Debug("Generate nonce and commitment", "Nonce", nonce, "Size", unsafe.Sizeof(*nonce))
	nonceCommitment := &NonceCommitment{preprocessingRequest.Sequence, nonce.Commitments}
	serializedNonceCommitment, err := nonceCommitment.Serialize()
	if err != nil {
		p.logger.With("func", "handlePreprocessingRequest").Error("Failed to serialize nonce commitment", "err", err)
		return
	}
	p.logger.With("func", "handlePreprocessingRequest").Debug("Generate Nonce commitment msg", "nonceCommitment", nonceCommitment)

	nonceCommitmentMsg := comm.Message{
		MsgType:  NonceCommitmentExchange,
		Data:     serializedNonceCommitment,
		From:     p.name,
		To:       "",
		CreateAt: time.Now(),
	}
	if err := p.broadcast(nonceCommitmentMsg); err != nil {
		p.logger.With("func", "handlePreprocessingRequest").Error("Failed to broadcast nonce commitment", "err", err)
		return
	}

	// Store the nonce for future signing
	p.nonces[preprocessingRequest.Sequence] = nonce
	if p.nonceCommitments[preprocessingRequest.Sequence] == nil {
		p.nonceCommitments[preprocessingRequest.Sequence] = make(map[int]Secp256k1FrostNonceCommitment)
		p.sequence = preprocessingRequest.Sequence + 1
	}
	p.nonceCommitments[preprocessingRequest.Sequence][p.id] = nonceCommitment.NonceCommitment
	p.logger.With("func", "handlePreprocessingRequest").Debug("Stored nonce commitment", "from", msg.From, "sequence", preprocessingRequest.Sequence)
}

// handleNonceExchange processes nonce exchange messages by verifying and storing the nonce.
func (p *Participant) handleNonceCommitmentExchange(msg comm.Message) {
	p.logger.With("func", "handleNonceCommitmentExchange").Debug("Received Nonce Commitment Exchange", "from", msg.From)

	// Deserialize the NonceCommitment directly
	var nonceCommitment NonceCommitment
	if err := nonceCommitment.Deserialize(msg.Data); err != nil {
		p.logger.With("func", "handleNonceCommitmentExchange").Error("Failed to deserialize nonce commitment", "err", err)
		return
	}

	senderID, exist := p.GetIDByName(msg.From)
	if !exist {
		p.logger.With("func", "handleNonceCommitmentExchange").Error("Participant does not exist", "from", msg.From)
		return
	}

	// Store the NonceCommitment for future signing
	if p.nonceCommitments[nonceCommitment.Sequence] == nil {
		p.nonceCommitments[nonceCommitment.Sequence] = make(map[int]Secp256k1FrostNonceCommitment)
	}
	p.nonceCommitments[nonceCommitment.Sequence][senderID] = nonceCommitment.NonceCommitment
	p.logger.With("func", "handleNonceCommitmentExchange").Debug("Stored nonce commitment", "from", msg.From, "sequence", nonceCommitment.Sequence, "commitment", nonceCommitment.NonceCommitment)

	// Check if received enough nonces to start signing
	// TODO: In demo, we are assuming all participants have sent nonce commitments. Actually, only the minimum signers are needed but all the signer should have a consensus on the same set.
	if len(p.nonceCommitments[nonceCommitment.Sequence]) == p.numParticipants {
		p.logger.Info("Received enough nonces. Completed preprocessing.")
		p.completePreprocessing(nonceCommitment.Sequence)
	}
}

// handleSignRequest handles a request to sign a message by generating a signature share.
func (p *Participant) handleSignRequest(msg comm.Message) {
	p.logger.With("func", "handleSignRequest").Debug("Received Sign Request", "from", msg.From)

	// Deserialize SignMessage
	var signMessage SignMessage
	if err := signMessage.Deserialize(msg.Data); err != nil {
		p.logger.With("func", "handleSignRequest").Error("Failed to deserialize sign message", "err", err)
		return
	}

	var nonceCommitment []Secp256k1FrostNonceCommitment
	if p.nonceCommitments[signMessage.Sequence] == nil {
		p.logger.With("func", "handleSignRequest").Error("Nonce commitment not found for sequence", "sequence", signMessage.Sequence)
		return
	}
	for i := 0; i < p.minSigner; i++ {
		signerID := signMessage.Signers[i]
		if commitment, exist := p.nonceCommitments[signMessage.Sequence][signerID]; exist {
			nonceCommitment = append(nonceCommitment, commitment)
			if len(nonceCommitment) == len(p.nonceCommitments[signMessage.Sequence]) {
				break
			}
		} else {
			p.logger.With("func", "handleSignRequest").Error("Nonce commitment not found for signer", "signer", signerID)
			return
		}
	}

	// Generate and send the signature share
	p.logger.With("func", "handleSignRequest").Debug("Generating signature share", "msgHash", signMessage.Msg_hash, "minSigner", p.minSigner, "key pair", p.keypair, "nonces", p.nonces[signMessage.Sequence], "nonce commitment", nonceCommitment)
	var signatureShare Secp256k1FrostSignatureShare
	result := Sign(
		&signatureShare,
		signMessage.Msg_hash[:],
		uint32(p.minSigner),
		p.keypair,
		p.nonces[signMessage.Sequence],
		nonceCommitment,
	)

	if result != 1 {
		p.logger.With("func", "handleSignRequest").Error("Error in signing message")
		return
	}
	p.logger.With("func", "handleSignRequest").Debug("Generated signature share", "msgHash", signMessage.Msg_hash, "signature share", signatureShare)

	share := &SignatureShare{signMessage.Sequence, signMessage.Msg_hash, signatureShare}
	serializedShare, err := share.Serialize()
	if err != nil {
		p.logger.With("func", "handleSignRequest").Error("Failed to serialize signature share", "err", err)
		return
	}

	responseMsg := comm.Message{
		MsgType:  SignatureShareResponse,
		Data:     serializedShare,
		From:     p.name,
		To:       msg.From,
		CreateAt: time.Now(),
	}
	if err := p.sendMessage(msg.From, responseMsg); err != nil {
		p.logger.With("func", "handleSignRequest").Error("Failed to send signature share", "to", msg.From, "err", err)
		return
	}
	p.logger.With("func", "handleSignRequest").Debug("Sent signature share", "to", msg.From)
}

// handleSignatureShare processes signature shares from other participants, aggregating if this is the initiator.
func (p *Participant) handleSignatureShareResponse(msg comm.Message) {
	p.logger.With("func", "handleSignatureShareResponse").Debug("Handling Signature Share", "from", msg.From)

	// Deserialize the signature share
	var receivedSignatureShare SignatureShare
	if err := receivedSignatureShare.Deserialize(msg.Data); err != nil {
		p.logger.With("func", "handleSignatureShareResponse").Error("Failed to deserialize signature share", "err", err)
		return
	}

	// Check if the participant is the initiator
	initiatorID, exist := p.initiator[receivedSignatureShare.Sequence]
	if !exist {
		p.logger.With("func", "handleSignatureShareResponse").Error("Initiator not found for sequence", "sequence", receivedSignatureShare.Sequence)
		return
	}
	if p.id != initiatorID {
		p.logger.With("func", "handleSignatureShareResponse").Error("Received signature share, but not the initiator.")
		return
	}
	if aggregateSig, exist := p.aggregatedSig[receivedSignatureShare.Sequence]; exist && aggregateSig != nil {
		p.logger.With("func", "handleSignatureShareResponse").Debug("Already have the signature. Ignore the message", "received", len(p.signatureShares[receivedSignatureShare.Sequence]), "required", p.minSigner)
		return
	}
	// If the participant is the initiator, aggregate the signature shares
	senderID, exist := p.GetIDByName(msg.From)
	if !exist {
		p.logger.With("func", "handleSignatureShareResponse").Error("Participant does not exist", "from", msg.From)
		return
	}
	if p.signatureShares[receivedSignatureShare.Sequence] == nil {
		p.signatureShares[receivedSignatureShare.Sequence] = make(map[int]*Secp256k1FrostSignatureShare)
	}
	p.signatureShares[receivedSignatureShare.Sequence][senderID] = &receivedSignatureShare.SignatureShare
	if len(p.signatureShares[receivedSignatureShare.Sequence]) < p.minSigner {
		p.logger.With("func", "handleSignatureShareResponse").Debug("Received signature shares and more signature shares are required. Waiting for the remaining", "received", len(p.signatureShares[receivedSignatureShare.Sequence]), "required", p.minSigner)
		return
	}

	// If the initiator has enough shares, generate the final signature
	var signatureShares []Secp256k1FrostSignatureShare
	var nonceCommitments []Secp256k1FrostNonceCommitment
	var publicKeys []Secp256k1FrostPubkey // Group public key (to be derived)
	for i := 0; i < p.numParticipants; i++ {
		if signatureShare, exist := p.signatureShares[receivedSignatureShare.Sequence][i]; exist {
			signatureShares = append(signatureShares, *signatureShare)
			p.logger.With("func", "handleSignatureShareResponse").Debug("Added signature share", "from", i)
			nonceCommitments = append(nonceCommitments, p.nonceCommitments[receivedSignatureShare.Sequence][i])
			p.logger.With("func", "handleSignatureShareResponse").Debug("Added nonce commitment", "from", i)
			publicKeys = append(publicKeys, p.publicKeys[i])
			if len(signatureShares) == p.minSigner {
				break
			}
		}
	}

	var aggregateSignature [64]byte
	p.logger.With("func", "handleSignatureShareResponse").Debug("Aggregating signature", "msg hash", receivedSignatureShare.Msg_hash, "signature shares", signatureShares, "nonce commitments", nonceCommitments, "public keys", publicKeys)
	result := Aggregate(aggregateSignature[:], receivedSignatureShare.Msg_hash[:], p.keypair, publicKeys, nonceCommitments, signatureShares, uint32(p.minSigner))
	if result != 1 {
		p.logger.With("func", "handleSignatureShareResponse").Error("Error in aggregating signature")
		return
	}
	p.logger.With("func", "handleSignatureShareResponse").Debug("Aggregated signature", "signature", aggregateSignature)

	result = Verify(aggregateSignature[:], receivedSignatureShare.Msg_hash[:], &p.keypair.PublicKeys)
	if result == 1 {
		p.logger.With("func", "handleSignatureShareResponse").Debug("Signature verified successfully!")
	} else {
		p.logger.With("func", "handleSignatureShareResponse").Debug("Signature verification failed")
	}

	p.aggregatedSig[receivedSignatureShare.Sequence] = aggregateSignature[:]
	p.signatureChan <- aggregateSignature[:]
}
