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
	Name                     string
	ID                       int
	NumParticipants          int
	MinSigner                int
	IDNameMap                map[int]string
	Config                   *comm.Config
	Communicator             *comm.Communicator // Communication layer
	Context                  []byte
	Tag                      []byte
	Commitments              map[int]*Secp256k1FrostVssCommitments
	SecretShares             map[int]*Secp256k1FrostKeygenSecretShare
	ReadyForPreprocessingNum map[int]int
	Nonces                   map[int]*Secp256k1FrostNonce
	NonceCommitments         map[int]map[int]Secp256k1FrostNonceCommitment
	ReadyForSignNum          map[int]map[int]int
	Keypair                  *Secp256k1FrostKeypair
	PublicKeys               map[int]Secp256k1FrostPubkey
	SignatureShares          map[int]map[int]*Secp256k1FrostSignatureShare
	AggregatedSig            map[int][]byte
	CurrentLeader            string
	IsLeader                 bool           // Whether this participant is the leader
	Sequence                 int            // Sequence number for the message
	DKGCompleted             bool           // Flag to indicate if DKG is complete
	PreprocessingComplete    bool           // Flag to indicate if preprocessing is complete
	wg                       sync.WaitGroup // New WaitGroup for message loop
	ctx                      context.Context
	cancel                   context.CancelFunc
	logger                   *slog.Logger
}

// NewParticipant initializes a new participant with communicator.
func NewParticipant(leader string, config *comm.Config, isLeader bool, id int, numParticipants int, minSigner int, signContext []byte, tag []byte) (*Participant, error) {
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
		Name:                     config.Name,
		ID:                       id,
		NumParticipants:          numParticipants,
		MinSigner:                minSigner,
		IDNameMap:                idNameMapping,
		Config:                   config,
		Communicator:             commLayer,
		Context:                  signContext,
		Tag:                      tag,
		Commitments:              make(map[int]*Secp256k1FrostVssCommitments),
		SecretShares:             make(map[int]*Secp256k1FrostKeygenSecretShare),
		ReadyForPreprocessingNum: make(map[int]int),
		Nonces:                   make(map[int]*Secp256k1FrostNonce),
		NonceCommitments:         make(map[int]map[int]Secp256k1FrostNonceCommitment),
		ReadyForSignNum:          make(map[int]map[int]int),
		Keypair:                  &Secp256k1FrostKeypair{},
		PublicKeys:               make(map[int]Secp256k1FrostPubkey),
		SignatureShares:          make(map[int]map[int]*Secp256k1FrostSignatureShare),
		AggregatedSig:            make(map[int][]byte),
		CurrentLeader:            leader,
		IsLeader:                 isLeader,
		Sequence:                 0,
		DKGCompleted:             false,
		PreprocessingComplete:    false,
		wg:                       sync.WaitGroup{},
		ctx:                      ctx,
		cancel:                   cancel,
		logger:                   logger.New(slog.LevelInfo).With("participant", config.Name),
	}

	// Register custom message handlers
	p.Communicator.RegisterHandler("DKGSecretShare", DKGSecretShare, p.handleDKGSecretShare)
	p.Communicator.RegisterHandler("ReadyForPreprocessing", ReadyForPreprocessing, p.handleReadyForPreprocessing)
	p.Communicator.RegisterHandler("PreprocessingRequest", PreprocessingRequest, p.handlePreprocessingRequest)
	p.Communicator.RegisterHandler("NonceCommitmentExchange", NonceCommitmentExchange, p.handleNonceCommitmentExchange)
	p.Communicator.RegisterHandler("ReadyForSign", ReadyForSign, p.handleReadyForSign)
	p.Communicator.RegisterHandler("SignRequest", SignRequest, p.handleSignRequest)
	p.Communicator.RegisterHandler("SignatureShareResponse", SignatureShareResponse, p.handleSignatureShareResponse)

	return p, nil
}

// start initializes and starts the communicator
func (p *Participant) Start() error {

	// Add to the WaitGroup for handling messages
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.Communicator.Start()

		// Listen indefinitely for messages or until context is canceled
		<-p.ctx.Done()
		p.logger.Info("Participant stopped listening for messages.")
	}()

	time.Sleep(10 * time.Second)
	p.initiateDKG()
	return nil
}

// close shuts down the communicator
func (p *Participant) Close() error {
	// Cancel the context to stop the message handling loop
	p.cancel()

	// Close the communicator
	if p.Communicator != nil {
		p.Communicator.Close()
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
	return p.Communicator.SendMessage(peerName, messageBytes)
}

// broadcast sends a message to all other participants.
func (p *Participant) broadcast(msg comm.Message) error {
	messageBytes, err := msg.Serialize()
	if err != nil {
		return fmt.Errorf("failed to serialize message: %v", err)
	}
	return p.Communicator.Broadcast(messageBytes)
}

// Function to get ID by name
func (p *Participant) GetIDByName(name string) (int, bool) {
	for id, n := range p.IDNameMap {
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
	sharesByParticipant := make([]Secp256k1FrostKeygenSecretShare, p.NumParticipants)

	// Call DKG Begin
	p.logger.With("func", "initiateDKG").Debug("Generating secret key share", "ID", p.ID, "NumParticipants", p.NumParticipants, "MinSigner", p.MinSigner, "shares", sharesByParticipant, "commitments", commitments)
	result := KeygenDKGBegin(
		&commitments,              // Each participant's commitment
		sharesByParticipant,       // Secret shares for each participant
		uint32(p.NumParticipants), // Number of participants
		uint32(p.MinSigner),       // Threshold for signing
		uint32(p.ID+1),            // Generator index (participant's index)
		p.Context,                 // Context for the DKG
	)
	if result != 1 {
		p.logger.With("func", "initiateDKG").Error("Failed in DKG Begin")
		return
	}
	p.logger.With("func", "initiateDKG").Debug("Secret key share generated", "shares", sharesByParticipant, "commitments", commitments)
	result = KeygenDKGCommitmentValidate(
		&commitments, // Peer’s commitment
		p.Context,
	)
	if result != 1 {
		p.logger.With("func", "initiateDKG").Error("Failed in commitment validation")
		return
	}

	// Send the generated secret share for other participants
	// Exchange secret shares between participants
	for i := 0; i < p.NumParticipants; i++ {
		if i == p.ID {
			// Store the generated secret share and commitment for self
			p.SecretShares[p.ID] = &sharesByParticipant[p.ID]
			p.Commitments[p.ID] = commitments
		} else {
			shareWithCommitment := &SecretShareWithCommitment{sharesByParticipant[i], commitments}
			serializedShareWithCommitment, err := shareWithCommitment.Serialize()
			if err != nil {
				p.logger.With("func", "initiateDKG").Error("Failed to serialize share with commitment", "err", err)
				return
			}

			p.logger.Info("Broadcast share with commitment")
			shareWithCommitmentMsg := comm.Message{
				MsgType:  DKGSecretShare,
				Data:     serializedShareWithCommitment,
				From:     p.Name,
				To:       p.IDNameMap[i],
				CreateAt: time.Now(),
			}
			if err := p.sendMessage(p.IDNameMap[i], shareWithCommitmentMsg); err != nil {
				p.logger.With("func", "initiateDKG").Error("Failed to send share with commitment", "to", p.IDNameMap[i], "err", err)
				return
			}
		}
	}
}

// completeDKG signals that DKG is complete, setting DKGCompleted flag and sending ReadyForSign
func (p *Participant) completeDKG() {
	p.DKGCompleted = true
	p.ReadyForPreprocessingNum[p.ID]++
	p.PublicKeys[p.ID] = p.Keypair.PublicKeys
	p.logger.Info("Completed DKG")

	if p.IsLeader {
		return
	}

	p.logger.Debug("Sending ReadyForPreprocessing to leader", "leader", p.CurrentLeader)
	// Send ReadyForPreprocessing message to the leader
	var publicKey Secp256k1FrostPubkey
	result := PubkeyFromKeypair(&publicKey, p.Keypair)
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
		From:     p.Name,
		To:       p.CurrentLeader,
		CreateAt: time.Now(),
	}
	if err := p.sendMessage(p.CurrentLeader, readyMsg); err != nil {
		p.logger.With("func", "completeDKG").Error("Failed to send ReadyForPreprocessing to leader", "leader", p.CurrentLeader, "err", err)
		return
	}
}

// initiatePreprocessing generate the nonce and sends commitment to all participants
func (p *Participant) initiatePreprocessing() {
	p.logger.Info("Initiating preprocessing process")

	// Send PreprocessingRequest to all participants
	preprocessingRequest := &PreprocessingSequence{
		Sequence: p.Sequence,
	}
	serializedPreprocessingRequest, err := preprocessingRequest.Serialize()
	if err != nil {
		p.logger.With("func", "initiatePreprocessing").Error("Failed to serialize preprocessing request", "err", err)
		return
	}

	preprocessingRequestMsg := comm.Message{
		MsgType:  PreprocessingRequest,
		Data:     serializedPreprocessingRequest,
		From:     p.Name,
		To:       "",
		CreateAt: time.Now(),
	}
	if err := p.broadcast(preprocessingRequestMsg); err != nil {
		p.logger.With("func", "initiatePreprocessing").Error("Failed to broadcast PreprocessingRequest", "err", err)
		return
	}

	// Generate nonce and send commitment to all participants
	var nonce = &Secp256k1FrostNonce{}
	result := CreateNonce(&nonce, p.Keypair)
	if result != 1 {
		p.logger.With("func", "initiatePreprocessing").Error("Error in creating nonce in participant")
		return
	}
	p.logger.With("func", "initiatePreprocessing").Debug("Generate nonce and commitment", "Nonce", nonce, "Size", unsafe.Sizeof(*nonce))
	nonceCommitment := &NonceCommitment{p.Sequence, nonce.Commitments}
	serializedNonceCommitment, err := nonceCommitment.Serialize()
	if err != nil {
		p.logger.With("func", "initiatePreprocessing").Error("Failed to serialize nonce commitment", "err", err)
		return
	}
	p.logger.With("func", "initiatePreprocessing").Debug("Generate nonce commitment msg", "nonce commitment", nonceCommitment)

	nonceCommitmentMsg := comm.Message{
		MsgType:  NonceCommitmentExchange,
		Data:     serializedNonceCommitment,
		From:     p.Name,
		To:       "",
		CreateAt: time.Now(),
	}
	if err := p.broadcast(nonceCommitmentMsg); err != nil {
		p.logger.With("func", "initiatePreprocessing").Error("Failed to broadcast nonce commitment", "err", err)
		return
	}

	// Store the nonce for future signing
	p.Nonces[p.Sequence] = nonce
	p.NonceCommitments[p.Sequence] = make(map[int]Secp256k1FrostNonceCommitment)
	p.NonceCommitments[p.Sequence][p.ID] = nonceCommitment.NonceCommitment
	p.Sequence++
}

// completePreprocessing signals that preprocessing is complete, setting ReadyForSignNum flag and sending ReadyForSign
func (p *Participant) completePreprocessing(sequence int) {
	p.PreprocessingComplete = true
	p.logger.Info("Completed preprocessing")

	if p.IsLeader {
		if p.ReadyForSignNum[sequence] == nil {
			p.ReadyForSignNum[sequence] = make(map[int]int)
		}
		p.ReadyForSignNum[sequence][p.ID]++
		return
	}

	p.logger.Info("Sending ReadyForSign to leader", "leader", p.CurrentLeader)
	// Send ReadyForSign message to the leader
	preprocessingComplete := &PreprocessingComplete{
		Sequence: sequence,
		Complete: true,
	}
	serializedPreprocessingComplete, err := preprocessingComplete.Serialize()
	if err != nil {
		p.logger.With("func", "completePreprocessing").Error("Failed to serialize preprocessing complete", "err", err)
		return
	}

	readyMsg := comm.Message{
		MsgType:  ReadyForSign,
		Data:     serializedPreprocessingComplete,
		From:     p.Name,
		To:       p.CurrentLeader,
		CreateAt: time.Now(),
	}
	if err := p.sendMessage(p.CurrentLeader, readyMsg); err != nil {
		p.logger.With("func", "completePreprocessing").Error("Failed to send ReadyForSign to leader", "leader", p.CurrentLeader, "err", err)
		return
	}
}

// initiateSigning generates a random message and sends SignRequest to all participants
func (p *Participant) initiateSigning(sequence int) {
	randomMsg := []byte("Random message for signing") // Generate a real random message in production
	var msgHash [32]byte
	result := TaggedSha256(&msgHash, p.Tag, randomMsg)
	if result != 1 {
		p.logger.With("func", "initiateSigning").Error("Error in creating tagged msg hash")
		return
	}
	p.logger.With("func", "initiateSigning").Debug("Initiating signing process")

	// Randomly choose the minimum signers to send the SignRequest
	signers := []int{p.ID}
	for i := 0; i < p.MinSigner-1; i++ {
		for {
			randomSigner := rand.IntN(p.NumParticipants)
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
		if signer == p.ID {
			continue
		}
		signerName := p.IDNameMap[signer]
		signRequest := comm.Message{
			MsgType:  SignRequest,
			Data:     serializedSignMessage,
			From:     p.Name,
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
	if p.NonceCommitments[sequence] == nil {
		p.logger.With("func", "initiateSigning").Error("Nonce commitment not found for sequence", "sequence", sequence)
		return
	}
	for i := 0; i < p.MinSigner; i++ {
		signerID := signers[i]
		if commitment, exist := p.NonceCommitments[sequence][signerID]; exist {
			nonceCommitment = append(nonceCommitment, commitment)
			if len(nonceCommitment) == len(p.NonceCommitments[sequence]) {
				break
			}
		} else {
			p.logger.With("func", "initiateSigning").Error("Nonce commitment not found for signer", "signer", signerID)
			return
		}
	}

	// Generate and send the signature share
	p.logger.With("func", "handleSignRequest").Debug("Generating signature share", "msgHash", signMessage.Msg_hash, "MinSigner", p.MinSigner, "key pair", p.Keypair, "nonces", p.Nonces[signMessage.Sequence], "nonce commitment", nonceCommitment)
	var signatureShare Secp256k1FrostSignatureShare
	result = Sign(
		&signatureShare,
		msgHash[:],
		uint32(p.MinSigner),
		p.Keypair,
		p.Nonces[sequence],
		nonceCommitment,
	)

	if result != 1 {
		p.logger.With("func", "initiateSigning").Error("Error in signing message")
		return
	}
	p.logger.With("func", "initiateSigning").Debug("Generated signature share", "signature share", signatureShare)
	if p.SignatureShares[sequence] == nil {
		p.SignatureShares[sequence] = make(map[int]*Secp256k1FrostSignatureShare)
	}
	p.SignatureShares[sequence][p.ID] = &signatureShare
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
		p.Context,
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
	p.SecretShares[senderID] = &shareWithCommitment.SecretShare
	p.Commitments[senderID] = shareWithCommitment.Commitments

	// Check if received enough secret shares to finalize DKG
	if len(p.SecretShares) == p.NumParticipants {
		// Convert the secret shares and commitments map to slices
		sharesByParticipant := make([]Secp256k1FrostKeygenSecretShare, p.NumParticipants)
		for i := 0; i < p.NumParticipants; i++ {
			sharesByParticipant[i] = *p.SecretShares[i]
			p.logger.With("func", "handleDKGSecretShare").Debug("Shares", "index", i, "sharesByParticipant", sharesByParticipant[i])
		}
		commitmentsPointers := make([]*Secp256k1FrostVssCommitments, p.NumParticipants)
		for i := 0; i < p.NumParticipants; i++ {
			commitmentsPointers[i] = p.Commitments[i]
			p.logger.With("func", "handleDKGSecretShare").Debug("Commitments", "index", i, "commitments", commitmentsPointers[i])
		}

		p.logger.With("func", "handleDKGSecretShare").Debug("Finalizing DKG", "shares", sharesByParticipant, "commitments", commitmentsPointers, "ID", p.ID, "NumParticipants", p.NumParticipants)
		result = KeygenDKGFinalize(
			p.Keypair,
			uint32(p.ID+1),
			uint32(p.NumParticipants),
			sharesByParticipant,
			commitmentsPointers,
		)
		if result != 1 {
			p.logger.With("func", "handleDKGSecretShare").Error("Error in DKG Finalize")
			return
		}
		p.logger.With("func", "handleDKGSecretShare").Debug("Finalized DKG", "keypair", p.Keypair)
		p.completeDKG()
	}
}

// handleReadyForPreprocessing processes ReadyForPreprocessing messages from participants, and once all are ready, initiates signing
func (p *Participant) handleReadyForPreprocessing(msg comm.Message) {
	if !p.IsLeader {
		p.logger.With("func", "handleReadyForPreprocessing").Error("Participant is not the leader. Ignoring ReadyForPreprocessing", "from", msg.From)
		return
	}
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
	p.ReadyForPreprocessingNum[senderID]++
	p.PublicKeys[senderID] = dkgComplete.PublicKey

	// Check if enough participants have sent ReadyForPreprocessing
	// TODO: In demo, we are assuming all participants have sent nonce commitments. Actually, only the minimum signers are needed but all the signer should have a consensus on the same set.
	if len(p.ReadyForPreprocessingNum) == p.NumParticipants && p.DKGCompleted {
		p.logger.Info("All participants are ready. Leader initiating preprocessing process.")
		p.initiatePreprocessing()
	}
}

// handleReadyForSign processes ReadyForSign messages from participants, and once all are ready, initiates signing
func (p *Participant) handleReadyForSign(msg comm.Message) {
	if !p.IsLeader {
		p.logger.With("func", "handleReadyForSign").Error("Participant is not the leader. Ignoring ReadyForSign", "from", msg.From)
		return
	}
	p.logger.With("func", "handleReadyForSign").Debug("Received ReadyForSign", "from", msg.From)

	// Deserialize the PreprocessingComplete directly
	var preprocessingComplete PreprocessingComplete
	if err := preprocessingComplete.Deserialize(msg.Data); err != nil {
		p.logger.With("func", "handleReadyForSign").Error("Failed to deserialize preprocessing complete", "err", err)
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

	if p.ReadyForSignNum[preprocessingComplete.Sequence] == nil {
		p.ReadyForSignNum[preprocessingComplete.Sequence] = make(map[int]int)
	}
	p.ReadyForSignNum[preprocessingComplete.Sequence][senderID]++

	// Check if enough participants have sent ReadyForSign
	// TODO: In demo, we are assuming all participants have sent nonce commitments. Actually, only the minimum signers are needed but all the signer should have a consensus on the same set.
	if len(p.ReadyForSignNum[preprocessingComplete.Sequence]) == p.NumParticipants && p.PreprocessingComplete {
		p.logger.Info("All participants are ready. Leader initiating signing process.")
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

	// Generate nonce and send commitment to all participants
	var nonce = &Secp256k1FrostNonce{}
	result := CreateNonce(&nonce, p.Keypair)
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
		From:     p.Name,
		To:       "",
		CreateAt: time.Now(),
	}
	if err := p.broadcast(nonceCommitmentMsg); err != nil {
		p.logger.With("func", "handlePreprocessingRequest").Error("Failed to broadcast nonce commitment", "err", err)
		return
	}

	// Store the nonce for future signing
	p.Nonces[preprocessingRequest.Sequence] = nonce
	if p.NonceCommitments[preprocessingRequest.Sequence] == nil {
		p.NonceCommitments[preprocessingRequest.Sequence] = make(map[int]Secp256k1FrostNonceCommitment)
	}
	p.NonceCommitments[preprocessingRequest.Sequence][p.ID] = nonceCommitment.NonceCommitment
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
	if p.NonceCommitments[nonceCommitment.Sequence] == nil {
		p.NonceCommitments[nonceCommitment.Sequence] = make(map[int]Secp256k1FrostNonceCommitment)
	}
	p.NonceCommitments[nonceCommitment.Sequence][senderID] = nonceCommitment.NonceCommitment
	p.logger.With("func", "handleNonceCommitmentExchange").Debug("Stored nonce commitment", "from", msg.From, "sequence", nonceCommitment.Sequence, "commitment", nonceCommitment.NonceCommitment)

	// Check if received enough nonces to start signing
	// TODO: In demo, we are assuming all participants have sent nonce commitments. Actually, only the minimum signers are needed but all the signer should have a consensus on the same set.
	if len(p.NonceCommitments[nonceCommitment.Sequence]) == p.NumParticipants {
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
	if p.NonceCommitments[signMessage.Sequence] == nil {
		p.logger.With("func", "handleSignRequest").Error("Nonce commitment not found for sequence", "sequence", signMessage.Sequence)
		return
	}
	for i := 0; i < p.MinSigner; i++ {
		signerID := signMessage.Signers[i]
		if commitment, exist := p.NonceCommitments[signMessage.Sequence][signerID]; exist {
			nonceCommitment = append(nonceCommitment, commitment)
			if len(nonceCommitment) == len(p.NonceCommitments[signMessage.Sequence]) {
				break
			}
		} else {
			p.logger.With("func", "handleSignRequest").Error("Nonce commitment not found for signer", "signer", signerID)
			return
		}
	}

	// Generate and send the signature share
	p.logger.With("func", "handleSignRequest").Debug("Generating signature share", "msgHash", signMessage.Msg_hash, "MinSigner", p.MinSigner, "key pair", p.Keypair, "nonces", p.Nonces[signMessage.Sequence], "nonce commitment", nonceCommitment)
	var signatureShare Secp256k1FrostSignatureShare
	result := Sign(
		&signatureShare,
		signMessage.Msg_hash[:],
		uint32(p.MinSigner),
		p.Keypair,
		p.Nonces[signMessage.Sequence],
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
		From:     p.Name,
		To:       msg.From,
		CreateAt: time.Now(),
	}
	if err := p.sendMessage(msg.From, responseMsg); err != nil {
		p.logger.With("func", "handleSignRequest").Error("Failed to send signature share", "to", msg.From, "err", err)
		return
	}
	p.logger.With("func", "handleSignRequest").Debug("Sent signature share", "to", msg.From)
}

// handleSignatureShare processes signature shares from other participants, aggregating if this is the leader.
func (p *Participant) handleSignatureShareResponse(msg comm.Message) {
	p.logger.With("func", "handleSignatureShareResponse").Debug("Handling Signature Share", "from", msg.From)

	// Deserialize the signature share
	var receivedSignatureShare SignatureShare
	if err := receivedSignatureShare.Deserialize(msg.Data); err != nil {
		p.logger.With("func", "handleSignatureShareResponse").Error("Failed to deserialize signature share", "err", err)
		return
	}

	if !p.IsLeader {
		p.logger.With("func", "handleSignatureShareResponse").Error("Received signature share, but not the leader.")
		return
	}
	if aggregateSig, exist := p.AggregatedSig[receivedSignatureShare.Sequence]; exist && aggregateSig != nil {
		p.logger.With("func", "handleSignatureShareResponse").Debug("Received more signature shares than required. Ignore the message", "received", len(p.SignatureShares[receivedSignatureShare.Sequence]), "required", p.MinSigner)
		return
	}
	// If leader, aggregate the signature shares
	senderID, exist := p.GetIDByName(msg.From)
	if !exist {
		p.logger.With("func", "handleSignatureShareResponse").Error("Participant does not exist", "from", msg.From)
		return
	}
	if p.SignatureShares[receivedSignatureShare.Sequence] == nil {
		p.SignatureShares[receivedSignatureShare.Sequence] = make(map[int]*Secp256k1FrostSignatureShare)
	}
	p.SignatureShares[receivedSignatureShare.Sequence][senderID] = &receivedSignatureShare.SignatureShare
	if len(p.SignatureShares[receivedSignatureShare.Sequence]) < p.MinSigner {
		p.logger.With("func", "handleSignatureShareResponse").Debug("Received signature shares and more signature shares are required. Waiting for the remaining", "received", len(p.SignatureShares[receivedSignatureShare.Sequence]), "required", p.MinSigner)
		return
	}

	// If enough shares, generate the final signature
	var signatureShares []Secp256k1FrostSignatureShare
	var nonceCommitments []Secp256k1FrostNonceCommitment
	var publicKeys []Secp256k1FrostPubkey // Group public key (to be derived)
	for i := 0; i < p.NumParticipants; i++ {
		if signatureShare, exist := p.SignatureShares[receivedSignatureShare.Sequence][i]; exist {
			signatureShares = append(signatureShares, *signatureShare)
			p.logger.With("func", "handleSignatureShareResponse").Debug("Added signature share", "from", i)
			nonceCommitments = append(nonceCommitments, p.NonceCommitments[receivedSignatureShare.Sequence][i])
			p.logger.With("func", "handleSignatureShareResponse").Debug("Added nonce commitment", "from", i)
			publicKeys = append(publicKeys, p.PublicKeys[i])
			if len(signatureShares) == p.MinSigner {
				break
			}
		}
	}

	var aggregateSignature [64]byte
	p.logger.With("func", "handleSignatureShareResponse").Debug("Aggregating signature", "msg hash", receivedSignatureShare.Msg_hash, "signature shares", signatureShares, "nonce commitments", nonceCommitments, "public keys", publicKeys)
	result := Aggregate(aggregateSignature[:], receivedSignatureShare.Msg_hash[:], p.Keypair, publicKeys, nonceCommitments, signatureShares, uint32(p.MinSigner))
	if result != 1 {
		p.logger.With("func", "handleSignatureShareResponse").Error("Error in aggregating signature")
		return
	}
	p.logger.With("func", "handleSignatureShareResponse").Debug("Aggregated signature", "signature", aggregateSignature)

	result = Verify(aggregateSignature[:], receivedSignatureShare.Msg_hash[:], &p.Keypair.PublicKeys)
	if result == 1 {
		p.logger.With("func", "handleSignatureShareResponse").Debug("Signature verified successfully!")
	} else {
		p.logger.With("func", "handleSignatureShareResponse").Debug("Signature verification failed")
	}

	p.AggregatedSig[p.Sequence] = aggregateSignature[:]
}
