package frost_dkg_multisig

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"tee-dao/comm"
	"tee-dao/logger"
	"unsafe"

	pb "tee-dao/rpc"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// Request is a struct to store the request message and response channel for client
type Request struct {
	Message  []byte
	Response chan []byte
	Sequence int // Sequence number is set by the server
}

// InitiatorSequence is a struct to store the initiator and sequence number pair
type InitiatorSequence struct {
	Initiator int
	Sequence  int
}

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
	readyForPreprocessingNum  map[int]int
	sequence                  int              // My Sequence number for the message signature request
	requests                  map[int]*Request // Map of requests for signing
	mu                        sync.Mutex
	signingMessage            map[InitiatorSequence][]byte
	nonces                    map[InitiatorSequence]*Secp256k1FrostNonce
	nonceCommitments          map[InitiatorSequence]map[int]Secp256k1FrostNonceCommitment
	readyForSignNum           map[InitiatorSequence]map[int]int
	keypair                   *Secp256k1FrostKeypair
	publicKeys                map[int]Secp256k1FrostPubkey
	signatureShares           map[InitiatorSequence]map[int]*Secp256k1FrostSignatureShare
	aggregatedSig             map[InitiatorSequence][]byte
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
		requests:                  make(map[int]*Request),
		signingMessage:            make(map[InitiatorSequence][]byte),
		readyForPreprocessingNum:  make(map[int]int),
		nonces:                    make(map[InitiatorSequence]*Secp256k1FrostNonce),
		nonceCommitments:          make(map[InitiatorSequence]map[int]Secp256k1FrostNonceCommitment),
		readyForSignNum:           make(map[InitiatorSequence]map[int]int),
		keypair:                   &Secp256k1FrostKeypair{},
		publicKeys:                make(map[int]Secp256k1FrostPubkey),
		signatureShares:           make(map[InitiatorSequence]map[int]*Secp256k1FrostSignatureShare),
		aggregatedSig:             make(map[InitiatorSequence][]byte),
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
	p.communicator.RegisterHandler("DKGSecretShare", DKGSecretShare, p.handleDKGSecretShare)                      //initiateDKG send
	p.communicator.RegisterHandler("ReadyForPreprocessing", ReadyForPreprocessing, p.handleReadyForPreprocessing) //completeDKG send
	p.communicator.RegisterHandler("PreprocessingRequest", PreprocessingRequest, p.handlePreprocessingRequest)
	p.communicator.RegisterHandler("NonceCommitmentExchange", NonceCommitmentExchange, p.handleNonceCommitmentExchange)
	p.communicator.RegisterHandler("ReadyForSign", ReadyForSign, p.handleReadyForSign)
	p.communicator.RegisterHandler("SignRequest", SignRequest, p.handleSignRequest)
	p.communicator.RegisterHandler("SignatureShareResponse", SignatureShareResponse, p.handleSignatureShareResponse)

	// Register the node communication service for client requests
	nodeCommService := &comm.NodeCommService{Communicator: p.communicator}
	err = p.communicator.RegisterRPCService(nodeCommService)
	if err != nil {
		p.logger.Error("Failed to register node communication service", "err", err)
		return nil, err
	}

	// Register the signature services for client requests
	sigService := &SignatureService{participant: p}
	err = p.communicator.RegisterRPCService(sigService)
	if err != nil {
		p.logger.Error("Failed to register signature service", "err", err)
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

// HandleRequest handles the client request for signature generation
func (p *Participant) HandleRequest(request *Request) error {
	// Store the request in the map
	p.mu.Lock()
	request.Sequence = p.sequence
	p.requests[p.sequence] = request
	p.sequence++
	p.mu.Unlock()

	p.logger.Info("Handling request", "sequence", request.Sequence)
	// Process the request
	err := p.initiatePreprocessing(request)
	if err != nil {
		p.logger.With("func", "HandleRequest").Error("Failed to process request", "err", err)
		return err
	}
	return nil
}

// sendMessage sends a message to a specific participant.
func (p *Participant) sendMessage(peerName string, msg *pb.NodeMsg) error {
	return p.communicator.SendMessage(peerName, msg)
}

// broadcast sends a message to all other participants.
func (p *Participant) broadcast(msg *pb.NodeMsg) error {
	return p.communicator.Broadcast(msg)
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
func (p *Participant) initiateDKG() error {
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
		return errors.New("failed in DKG Begin")
	}
	p.logger.With("func", "initiateDKG").Debug("Secret key share generated", "shares", sharesByParticipant, "commitments", commitments)
	result = KeygenDKGCommitmentValidate(
		&commitments, // Peer’s commitment
		p.context,
	)
	if result != 1 {
		p.logger.With("func", "initiateDKG").Error("Failed in commitment validation")
		return errors.New("failed in commitment validation")
	}

	err := p.receiveShareWithCommitment(p.id, sharesByParticipant[p.id], *commitments)
	if err != nil {
		p.logger.With("func", "initiateDKG").Error("Failed to store DKG secret share", "err", err)
		return err
	}

	// Send the generated secret share for other participants
	// Exchange secret shares between participants
	for i := 0; i < p.numParticipants; i++ {
		if i == p.id {
			continue
		} else {
			shareWithCommitment := &SecretShareWithCommitment{sharesByParticipant[i], commitments}
			serializedShareWithCommitment, err := shareWithCommitment.Serialize()
			if err != nil {
				p.logger.With("func", "initiateDKG").Error("Failed to serialize share with commitment", "err", err)
				return err
			}

			p.logger.Info("Send share with commitment", "to", p.idNameMap[i])
			shareWithCommitmentMsg := &pb.NodeMsg{
				MsgType:  DKGSecretShare,
				Data:     serializedShareWithCommitment,
				From:     p.name,
				To:       p.idNameMap[i],
				CreateAt: timestamppb.Now(),
			}
			if err := p.sendMessage(p.idNameMap[i], shareWithCommitmentMsg); err != nil {
				p.logger.With("func", "initiateDKG").Error("Failed to send share with commitment", "to", p.idNameMap[i], "err", err)
				return err
			}
		}
	}
	return nil
}

// completeDKG signals that DKG is complete, setting dkgCompleted flag and sending ReadyForSign
func (p *Participant) completeDKG() error {
	p.dkgCompleted = true
	err := p.receivePublicKey(p.id, p.keypair.PublicKeys)
	if err != nil {
		p.logger.With("func", "completeDKG").Error("Failed to store public key", "err", err)
		return err
	}
	p.logger.Info("Completed DKG")

	p.logger.With("func", "completeDKG").Debug("Broadcasting ReadyForPreprocessing")
	// Send ReadyForPreprocessing message to the leader
	var publicKey Secp256k1FrostPubkey
	result := PubkeyFromKeypair(&publicKey, p.keypair)
	if result != 1 {
		p.logger.With("func", "completeDKG").Error("Error in creating public key")
		return errors.New("error in creating public key")
	}

	p.logger.With("func", "completeDKG").Debug("Generated public key", "public key", publicKey)
	dkgComplete := &DKGComplete{
		PublicKey: publicKey,
		Complete:  true,
	}
	serializedDKGComplete, err := dkgComplete.Serialize()
	if err != nil {
		p.logger.With("func", "completeDKG").Error("Failed to serialize DKG complete", "err", err)
		return err
	}

	readyMsg := &pb.NodeMsg{
		MsgType:  ReadyForPreprocessing,
		Data:     serializedDKGComplete,
		From:     p.name,
		To:       "",
		CreateAt: timestamppb.Now(),
	}
	if err := p.broadcast(readyMsg); err != nil {
		p.logger.With("func", "completeDKG").Error("Failed to broadcast ReadyForPreprocessing", "err", err)
		return err
	}
	return nil
}

// initiatePreprocessing generate the nonce and sends commitment to all participants
func (p *Participant) initiatePreprocessing(request *Request) error {
	p.logger.Info("Initiating preprocessing process")

	// Send PreprocessingRequest to all participants
	initiatorSequence := InitiatorSequence{p.id, request.Sequence}
	preprocessingRequest := &PreprocessingSequence{
		InitiatorSequence: initiatorSequence,
	}
	serializedPreprocessingRequest, err := preprocessingRequest.Serialize()
	if err != nil {
		p.logger.With("func", "initiatePreprocessing").Error("Failed to serialize preprocessing request", "err", err)
		return err
	}

	// Generate nonce and send commitment to all participants
	var nonce = &Secp256k1FrostNonce{}
	result := CreateNonce(&nonce, p.keypair)
	if result != 1 {
		p.logger.With("func", "initiatePreprocessing").Error("Error in creating nonce in participant")
		return errors.New("error in creating nonce")
	}
	p.logger.With("func", "initiatePreprocessing").Debug("Generate nonce and commitment", "Nonce", nonce, "Size", unsafe.Sizeof(*nonce))
	nonceCommitment := &NonceCommitment{initiatorSequence, nonce.Commitments}
	serializedNonceCommitment, err := nonceCommitment.Serialize()
	if err != nil {
		p.logger.With("func", "initiatePreprocessing").Error("Failed to serialize nonce commitment", "err", err)
		return err
	}
	p.logger.With("func", "initiatePreprocessing").Debug("Generate nonce commitment msg", "nonce commitment", nonceCommitment)

	// Store the nonce for future signing
	p.signingMessage[initiatorSequence] = request.Message
	p.nonces[initiatorSequence] = nonce
	err = p.receiveNonceCommitment(p.id, initiatorSequence, nonce.Commitments)
	if err != nil {
		p.logger.With("func", "initiatePreprocessing").Error("Failed to store nonce commitment", "err", err)
		return err
	}

	preprocessingRequestMsg := &pb.NodeMsg{
		MsgType:  PreprocessingRequest,
		Data:     serializedPreprocessingRequest,
		From:     p.name,
		To:       "",
		CreateAt: timestamppb.Now(),
	}
	if err := p.broadcast(preprocessingRequestMsg); err != nil {
		p.logger.With("func", "initiatePreprocessing").Error("Failed to broadcast PreprocessingRequest", "err", err)
		return err
	}

	nonceCommitmentMsg := &pb.NodeMsg{
		MsgType:  NonceCommitmentExchange,
		Data:     serializedNonceCommitment,
		From:     p.name,
		To:       "",
		CreateAt: timestamppb.Now(),
	}
	if err := p.broadcast(nonceCommitmentMsg); err != nil {
		p.logger.With("func", "initiatePreprocessing").Error("Failed to broadcast nonce commitment", "err", err)
		return err
	}

	return nil
}

// completePreprocessing signals that preprocessing is complete, setting ReadyForSignNum flag and sending ReadyForSign
func (p *Participant) completePreprocessing(initiatorSequence InitiatorSequence) error {
	p.preprocessingComplete = true
	p.logger.Info("Completed preprocessing")

	// If the participant is the initiator, increment the ReadyForSignNum and return
	if p.id == initiatorSequence.Initiator {
		p.logger.With("func", "completePreprocessing").Debug("Initiator Increments ReadyForSignNum")
		if p.readyForSignNum[initiatorSequence] == nil {
			p.readyForSignNum[initiatorSequence] = make(map[int]int)
		}
		p.readyForSignNum[initiatorSequence][p.id]++
		// TODO: not sure if is no error here
		return nil
	}

	p.logger.With("func", "completePreprocessing").Debug("Broadcasting ReadyForSign")
	// Send ReadyForSign message to the initiator
	preprocessingComplete := &PreprocessingComplete{
		InitiatorSequence: initiatorSequence,
		Complete:          true,
	}
	serializedPreprocessingComplete, err := preprocessingComplete.Serialize()
	if err != nil {
		p.logger.With("func", "completePreprocessing").Error("Failed to serialize preprocessing complete", "err", err)
		return err
	}

	initiatorName := p.idNameMap[initiatorSequence.Initiator]
	readyMsg := &pb.NodeMsg{
		MsgType:  ReadyForSign,
		Data:     serializedPreprocessingComplete,
		From:     p.name,
		To:       initiatorName,
		CreateAt: timestamppb.Now(),
	}
	if err := p.sendMessage(initiatorName, readyMsg); err != nil {
		p.logger.With("func", "completePreprocessing").Error("Failed to send ReadyForSign to initiator", "initiator", initiatorName, "err", err)
		return err
	}
	return nil
}

// initiateSigning generates a random message and sends SignRequest to all participants
func (p *Participant) initiateSigning(initiatorSequence InitiatorSequence) error {
	msg, exist := p.signingMessage[initiatorSequence]
	if !exist {
		p.logger.With("func", "initiateSigning").Error("Message not found for initiatorSequence", "initiatorSequence", initiatorSequence)
		return errors.New("message not found")
	}
	var msgHash [32]byte
	result := TaggedSha256(&msgHash, p.tag, msg)
	if result != 1 {
		p.logger.With("func", "initiateSigning").Error("Error in creating tagged msg hash")
		return errors.New("error in creating tagged msg hash")
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

	var nonceCommitment []Secp256k1FrostNonceCommitment
	if p.nonceCommitments[initiatorSequence] == nil {
		p.logger.With("func", "initiateSigning").Error("Nonce commitment not found for initiatorSequence", "initiatorSequence", initiatorSequence)
		return errors.New("nonce commitment not found")
	}
	for i := 0; i < p.minSigner; i++ {
		signerID := signers[i]
		if commitment, exist := p.nonceCommitments[initiatorSequence][signerID]; exist {
			nonceCommitment = append(nonceCommitment, commitment)
			if len(nonceCommitment) == len(p.nonceCommitments[initiatorSequence]) {
				break
			}
		} else {
			p.logger.With("func", "initiateSigning").Error("Nonce commitment not found for signer", "signer", signerID)
			return errors.New("nonce commitment not found")
		}
	}

	// Generate and send the signature share
	p.logger.With("func", "initiateSigning").Debug("Generating signature share", "msgHash", msgHash, "minSigner", p.minSigner, "key pair", p.keypair, "nonces", p.nonces[initiatorSequence], "nonce commitment", nonceCommitment)
	var signatureShare Secp256k1FrostSignatureShare
	result = Sign(
		&signatureShare,
		msgHash[:],
		uint32(p.minSigner),
		p.keypair,
		p.nonces[initiatorSequence],
		nonceCommitment,
	)

	if result != 1 {
		p.logger.With("func", "initiateSigning").Error("Error in signing message")
		return errors.New("error in signing message")
	}
	p.logger.With("func", "initiateSigning").Debug("Generated signature share", "signature share", signatureShare)
	if p.signatureShares[initiatorSequence] == nil {
		p.signatureShares[initiatorSequence] = make(map[int]*Secp256k1FrostSignatureShare)
	}
	p.signatureShares[initiatorSequence][p.id] = &signatureShare

	p.logger.Info("Sent SignRequest to singers", "signers", signers)
	signMessage := &SignMessage{
		InitiatorSequence: initiatorSequence,
		Signers:           signers,
		Msg_hash:          msgHash,
	}
	serializedSignMessage, err := signMessage.Serialize()
	if err != nil {
		p.logger.With("func", "initiateSigning").Error("Failed to serialize sign message", "err", err)
		return err
	}

	for _, signer := range signers {
		if signer == p.id {
			continue
		}
		signerName := p.idNameMap[signer]
		signRequest := &pb.NodeMsg{
			MsgType:  SignRequest,
			Data:     serializedSignMessage,
			From:     p.name,
			To:       signerName,
			CreateAt: timestamppb.Now(),
		}
		if err := p.sendMessage(signerName, signRequest); err != nil {
			p.logger.With("func", "initiateSigning").Error("Failed to send SignRequest", "to", signerName, "err", err)
			return err
		}
	}

	return nil
}

// receiveNonceCommitment receives the nonce commitment from the participant and stores it
func (p *Participant) receiveNonceCommitment(participantId int, initiatorSequence InitiatorSequence, nonceCommitment Secp256k1FrostNonceCommitment) error {
	p.logger.With("func", "receiveNonceCommitment").Debug("Received nonce commitment", "initiatorSequence", initiatorSequence, "from", participantId, "commitment", nonceCommitment)
	if p.nonceCommitments[initiatorSequence] == nil {
		p.nonceCommitments[initiatorSequence] = make(map[int]Secp256k1FrostNonceCommitment)
	}
	p.nonceCommitments[initiatorSequence][participantId] = nonceCommitment
	p.logger.With("func", "receiveNonceCommitment").Debug("Length of nonce commitments", "length", len(p.nonceCommitments[initiatorSequence]))

	// Check if received enough nonce commitments to finalize preprocessing
	if len(p.nonceCommitments[initiatorSequence]) == p.numParticipants {
		p.logger.With("func", "receiveNonceCommitment").Debug("All participants have sent nonce commitments", "num", len(p.nonceCommitments[initiatorSequence]), "participants", p.numParticipants)
		p.completePreprocessing(initiatorSequence)
	} else {
		p.logger.With("func", "receiveNonceCommitment").Debug("Not all participants have sent nonce commitments", "num", len(p.nonceCommitments[initiatorSequence]), "participants", p.numParticipants)
	}
	return nil
}

// receiveShareWithCommitment receives the share with commitment from the participant and stores it
func (p *Participant) receiveShareWithCommitment(participantId int, secretShare Secp256k1FrostKeygenSecretShare, commitments Secp256k1FrostVssCommitments) error {
	p.logger.With("func", "receiveShareWithCommitment").Debug("Received share with commitment", "from", participantId, "share", secretShare, "commitment", commitments)
	p.secretShares[participantId] = &secretShare
	p.commitments[participantId] = &commitments

	// Check if received enough secret shares to finalize DKG
	if len(p.secretShares) == p.numParticipants {
		// Convert the secret shares and commitments map to slices
		sharesByParticipant := make([]Secp256k1FrostKeygenSecretShare, p.numParticipants)
		for i := 0; i < p.numParticipants; i++ {
			sharesByParticipant[i] = *p.secretShares[i]
			p.logger.With("func", "receiveShareWithCommitment").Debug("Shares", "index", i, "sharesByParticipant", sharesByParticipant[i])
		}
		commitmentsPointers := make([]*Secp256k1FrostVssCommitments, p.numParticipants)
		for i := 0; i < p.numParticipants; i++ {
			commitmentsPointers[i] = p.commitments[i]
			p.logger.With("func", "receiveShareWithCommitment").Debug("Commitments", "index", i, "commitments", commitmentsPointers[i])
		}

		p.logger.With("func", "receiveShareWithCommitment").Debug("Finalizing DKG", "shares", sharesByParticipant, "commitments", commitmentsPointers, "id", p.id, "numParticipants", p.numParticipants)
		result := KeygenDKGFinalize(
			p.keypair,
			uint32(p.id+1),
			uint32(p.numParticipants),
			sharesByParticipant,
			commitmentsPointers,
		)
		if result != 1 {
			p.logger.With("func", "receiveShareWithCommitment").Error("Error in DKG Finalize")
			return errors.New("error in DKG Finalize")
		}
		p.logger.With("func", "receiveShareWithCommitment").Debug("Finalized DKG", "keypair", p.keypair)
		err := p.completeDKG()
		if err != nil {
			p.logger.With("func", "receiveShareWithCommitment").Error("Failed to complete DKG", "err", err)
			return err
		}
	} else {
		p.logger.With("func", "receiveShareWithCommitment").Debug("Not all participants have sent DKG secret shares", "num", len(p.secretShares), "participants", p.numParticipants)
	}
	return nil
}

// receivePublicKey receives the public key from the participant and stores it
func (p *Participant) receivePublicKey(participantId int, publicKey Secp256k1FrostPubkey) error {
	p.logger.With("func", "receivePublicKey").Debug("Received public key", "from", participantId, "public key", publicKey)
	p.readyForPreprocessingNum[participantId]++
	p.publicKeys[participantId] = publicKey

	// Check if received enough public keys to finalize preprocessing
	if len(p.publicKeys) == p.numParticipants {
		p.logger.With("func", "receivePublicKey").Debug("All participants have sent public keys", "num", len(p.publicKeys), "participants", p.numParticipants)
		p.readyForInitPreprocessing = true
	} else {
		p.logger.With("func", "receivePublicKey").Debug("Not all participants have sent public keys", "num", len(p.publicKeys), "participants", p.numParticipants)
	}

	// Check if all participants are ready for preprocessing
	if len(p.readyForPreprocessingNum) == p.numParticipants && p.dkgCompleted {
		p.logger.Info("All participants are ready. Waiting for client signing request.")
		p.readyForInitPreprocessing = true
	} else {
		if len(p.readyForPreprocessingNum) != p.numParticipants {
			p.logger.With("func", "receivePublicKey").Debug("Not all participants are ready for preprocessing. ReadyForPreprocessingNum", "num", len(p.readyForPreprocessingNum), "participants", p.numParticipants)
		} else {
			p.logger.With("func", "receivePublicKey").Error("DKG is not complete")
		}
	}

	return nil
}

// handleDKGSecretShare handles the DKG secret share message by verifying and storing the share.
func (p *Participant) handleDKGSecretShare(msg *pb.NodeMsg) error {
	p.logger.Info("Handling DKG Secret Share", "from", msg.From)

	// Deserialize the secret share directly
	var shareWithCommitment SecretShareWithCommitment
	if err := shareWithCommitment.Deserialize(msg.Data); err != nil {
		p.logger.With("func", "handleDKGSecretShare").Error("Failed to deserialize DKG secret share", "err", err)
		return err
	}

	p.logger.With("func", "handleDKGSecretShare").Debug("Got DKG Secret share", "share", shareWithCommitment.SecretShare, "commitments", shareWithCommitment.Commitments)

	// Verify and store the share and commitment
	result := KeygenDKGCommitmentValidate(
		&shareWithCommitment.Commitments, // Peer’s commitment
		p.context,
	)
	if result != 1 {
		p.logger.With("func", "handleDKGSecretShare").Error("Invalid generator index in DKG secret share", "from", msg.From)
		return errors.New("invalid generator index in DKG secret share")
	}

	senderID, exist := p.GetIDByName(msg.From)
	if !exist {
		p.logger.With("func", "handleDKGSecretShare").Error("Participant does not exist", "from", msg.From)
		return errors.New("Participant does not exist")
	}
	err := p.receiveShareWithCommitment(senderID, shareWithCommitment.SecretShare, *shareWithCommitment.Commitments)
	if err != nil {
		p.logger.With("func", "handleDKGSecretShare").Error("Failed to store DKG secret share", "err", err)
		return err
	}
	return nil
}

// handleReadyForPreprocessing processes ReadyForPreprocessing messages from participants, and once all are ready, initiates signing
func (p *Participant) handleReadyForPreprocessing(msg *pb.NodeMsg) error {
	p.logger.With("func", "handleReadyForPreprocessing").Debug("Received ReadyForPreprocessing", "from", msg.From)

	// Deserialize the DKGComplete directly
	var dkgComplete DKGComplete
	if err := dkgComplete.Deserialize(msg.Data); err != nil {
		p.logger.With("func", "handleReadyForPreprocessing").Error("Failed to deserialize DKG complete", "err", err)
		return err
	}

	// Check if DKG is complete
	if !dkgComplete.Complete {
		p.logger.With("func", "handleReadyForPreprocessing").Error("DKG is not complete. Ignoring ReadyForPreprocessing", "from", msg.From)
		return errors.New("DKG is not complete")
	}

	senderID, exist := p.GetIDByName(msg.From)
	if !exist {
		p.logger.With("func", "handleReadyForPreprocessing").Error("Participant does not exist", "from", msg.From)
		return errors.New("Participant does not exist")
	}

	// Store the public key
	err := p.receivePublicKey(senderID, dkgComplete.PublicKey)
	if err != nil {
		p.logger.With("func", "handleReadyForPreprocessing").Error("Failed to store public key", "err", err)
		return err
	}
	return nil
}

// handleReadyForSign processes ReadyForSign messages from participants, and once all are ready, initiates signing
func (p *Participant) handleReadyForSign(msg *pb.NodeMsg) error {
	p.logger.With("func", "handleReadyForSign").Debug("Received ReadyForSign", "from", msg.From)

	// Deserialize the PreprocessingComplete directly
	var preprocessingComplete PreprocessingComplete
	if err := preprocessingComplete.Deserialize(msg.Data); err != nil {
		p.logger.With("func", "handleReadyForSign").Error("Failed to deserialize preprocessing complete", "err", err)
		return err
	}

	// Check if the participant is the initiator
	if p.id != preprocessingComplete.InitiatorSequence.Initiator {
		p.logger.With("func", "handleReadyForSign").Error("Participant is not the initiator. Ignoring ReadyForSign", "from", msg.From)
		return errors.New("participant is not the initiator")
	}

	// Check if preprocessing is complete
	if !preprocessingComplete.Complete {
		p.logger.With("func", "handleReadyForSign").Error("Preprocessing is not complete. Ignoring ReadyForSign", "from", msg.From)
		return errors.New("preprocessing is not complete")
	}

	senderID, exist := p.GetIDByName(msg.From)
	if !exist {
		p.logger.With("func", "handleReadyForSign").Error("Participant does not exist", "from", msg.From)
		return errors.New("participant does not exist")
	}

	if p.readyForSignNum[preprocessingComplete.InitiatorSequence] == nil {
		p.readyForSignNum[preprocessingComplete.InitiatorSequence] = make(map[int]int)
	}
	p.readyForSignNum[preprocessingComplete.InitiatorSequence][senderID]++

	// Check if enough participants have sent ReadyForSign
	// TODO: In demo, we are assuming all participants have sent nonce commitments. Actually, only the minimum signers are needed but all the signer should have a consensus on the same set.
	if len(p.readyForSignNum[preprocessingComplete.InitiatorSequence]) == p.numParticipants && p.preprocessingComplete {
		p.logger.Info("All participants are ready. Initiator initiating signing process.")
		p.initiateSigning(preprocessingComplete.InitiatorSequence)
	} else {
		if len(p.readyForSignNum[preprocessingComplete.InitiatorSequence]) != p.numParticipants {
			p.logger.With("func", "handleReadyForSign").Debug("Not all participants are ready for sign. ReadyForSignNum", "num", len(p.readyForSignNum[preprocessingComplete.InitiatorSequence]), "participants", p.numParticipants)
		} else {
			p.logger.With("func", "handleReadyForSign").Error("Preprocessing is not complete")
		}
	}

	return nil
}

// handlePreprocessingRequest handles a request to preprocessing by generating a nonce and send the commitment.
func (p *Participant) handlePreprocessingRequest(msg *pb.NodeMsg) error {
	p.logger.With("func", "handlePreprocessingRequest").Debug("Received Preprocessing Request", "from", msg.From)

	// Deserialize PreprocessingRequest
	var preprocessingRequest PreprocessingSequence
	if err := preprocessingRequest.Deserialize(msg.Data); err != nil {
		p.logger.With("func", "handlePreprocessingRequest").Error("Failed to deserialize preprocessing request", "err", err)
		return err
	}

	// Generate nonce and send commitment to all participants
	var nonce = &Secp256k1FrostNonce{}
	result := CreateNonce(&nonce, p.keypair)
	if result != 1 {
		p.logger.With("func", "handlePreprocessingRequest").Error("Error in creating nonce")
		return errors.New("error in creating nonce")
	}
	p.logger.With("func", "handlePreprocessingRequest").Debug("Generate nonce and commitment", "Nonce", nonce, "Size", unsafe.Sizeof(*nonce))
	nonceCommitment := &NonceCommitment{preprocessingRequest.InitiatorSequence, nonce.Commitments}
	serializedNonceCommitment, err := nonceCommitment.Serialize()
	if err != nil {
		p.logger.With("func", "handlePreprocessingRequest").Error("Failed to serialize nonce commitment", "err", err)
		return err
	}
	p.logger.With("func", "handlePreprocessingRequest").Debug("Generate Nonce commitment msg", "nonceCommitment", nonceCommitment)

	nonceCommitmentMsg := &pb.NodeMsg{
		MsgType:  NonceCommitmentExchange,
		Data:     serializedNonceCommitment,
		From:     p.name,
		To:       "",
		CreateAt: timestamppb.Now(),
	}
	if err := p.broadcast(nonceCommitmentMsg); err != nil {
		p.logger.With("func", "handlePreprocessingRequest").Error("Failed to broadcast nonce commitment", "err", err)
		return err
	}

	// Store the nonce for future signing
	p.nonces[preprocessingRequest.InitiatorSequence] = nonce
	err = p.receiveNonceCommitment(p.id, preprocessingRequest.InitiatorSequence, nonce.Commitments)
	if err != nil {
		p.logger.With("func", "handlePreprocessingRequest").Error("Failed to store nonce commitment", "err", err)
		return err
	}

	return nil
}

// handleNonceExchange processes nonce exchange messages by verifying and storing the nonce.
func (p *Participant) handleNonceCommitmentExchange(msg *pb.NodeMsg) error {
	p.logger.With("func", "handleNonceCommitmentExchange").Debug("Received Nonce Commitment Exchange", "from", msg.From)

	// Deserialize the NonceCommitment directly
	var nonceCommitment NonceCommitment
	if err := nonceCommitment.Deserialize(msg.Data); err != nil {
		p.logger.With("func", "handleNonceCommitmentExchange").Error("Failed to deserialize nonce commitment", "err", err)
		return err
	}

	senderID, exist := p.GetIDByName(msg.From)
	if !exist {
		p.logger.With("func", "handleNonceCommitmentExchange").Error("Participant does not exist", "from", msg.From)
		return errors.New("Participant does not exist")
	}

	// Store the NonceCommitment for future signing
	err := p.receiveNonceCommitment(senderID, nonceCommitment.InitiatorSequence, nonceCommitment.NonceCommitment)
	if err != nil {
		p.logger.With("func", "handleNonceCommitmentExchange").Error("Failed to store nonce commitment", "err", err)
		return err
	}

	return nil
}

// handleSignRequest handles a request to sign a message by generating a signature share.
func (p *Participant) handleSignRequest(msg *pb.NodeMsg) error {
	p.logger.With("func", "handleSignRequest").Debug("Received Sign Request", "from", msg.From)

	// Deserialize SignMessage
	var signMessage SignMessage
	if err := signMessage.Deserialize(msg.Data); err != nil {
		p.logger.With("func", "handleSignRequest").Error("Failed to deserialize sign message", "err", err)
		return err
	}

	var nonceCommitment []Secp256k1FrostNonceCommitment
	if p.nonceCommitments[signMessage.InitiatorSequence] == nil {
		p.logger.With("func", "handleSignRequest").Error("Nonce commitment not found for initiatorSequence", "initiatorSequence", signMessage.InitiatorSequence)
		return errors.New("nonce commitment not found")
	}
	for i := 0; i < p.minSigner; i++ {
		signerID := signMessage.Signers[i]
		if commitment, exist := p.nonceCommitments[signMessage.InitiatorSequence][signerID]; exist {
			nonceCommitment = append(nonceCommitment, commitment)
			if len(nonceCommitment) == len(p.nonceCommitments[signMessage.InitiatorSequence]) {
				break
			}
		} else {
			p.logger.With("func", "handleSignRequest").Error("Nonce commitment not found for signer", "signer", signerID)
			return errors.New("nonce commitment not found")
		}
	}

	// Generate and send the signature share
	p.logger.With("func", "handleSignRequest").Debug("Generating signature share", "msgHash", signMessage.Msg_hash, "minSigner", p.minSigner, "key pair", p.keypair, "nonces", p.nonces[signMessage.InitiatorSequence], "nonce commitment", nonceCommitment)
	var signatureShare Secp256k1FrostSignatureShare
	result := Sign(
		&signatureShare,
		signMessage.Msg_hash[:],
		uint32(p.minSigner),
		p.keypair,
		p.nonces[signMessage.InitiatorSequence],
		nonceCommitment,
	)

	if result != 1 {
		p.logger.With("func", "handleSignRequest").Error("Error in signing message")
		return errors.New("error in signing message")
	}
	p.logger.With("func", "handleSignRequest").Debug("Generated signature share", "msgHash", signMessage.Msg_hash, "signature share", signatureShare)

	share := &SignatureShare{signMessage.InitiatorSequence, signMessage.Msg_hash, signatureShare}
	serializedShare, err := share.Serialize()
	if err != nil {
		p.logger.With("func", "handleSignRequest").Error("Failed to serialize signature share", "err", err)
		return err
	}

	responseMsg := &pb.NodeMsg{
		MsgType:  SignatureShareResponse,
		Data:     serializedShare,
		From:     p.name,
		To:       msg.From,
		CreateAt: timestamppb.Now(),
	}
	if err := p.sendMessage(msg.From, responseMsg); err != nil {
		p.logger.With("func", "handleSignRequest").Error("Failed to send signature share", "to", msg.From, "err", err)
		return err
	}
	p.logger.With("func", "handleSignRequest").Debug("Sent signature share", "to", msg.From)

	return nil
}

// handleSignatureShare processes signature shares from other participants, aggregating if this is the initiator.
func (p *Participant) handleSignatureShareResponse(msg *pb.NodeMsg) error {
	p.logger.With("func", "handleSignatureShareResponse").Debug("Handling Signature Share", "from", msg.From)

	// Deserialize the signature share
	var receivedSignatureShare SignatureShare
	if err := receivedSignatureShare.Deserialize(msg.Data); err != nil {
		p.logger.With("func", "handleSignatureShareResponse").Error("Failed to deserialize signature share", "err", err)
		return err
	}

	// Check if the participant is the initiator
	if p.id != receivedSignatureShare.InitiatorSequence.Initiator {
		p.logger.With("func", "handleSignatureShareResponse").Error("Received signature share, but not the initiator.")
		return errors.New("received signature share, but not the initiator")
	}
	if aggregateSig, exist := p.aggregatedSig[receivedSignatureShare.InitiatorSequence]; exist && aggregateSig != nil {
		p.logger.With("func", "handleSignatureShareResponse").Debug("Already have the signature. Ignore the message", "received", len(p.signatureShares[receivedSignatureShare.InitiatorSequence]), "required", p.minSigner)
		return nil
	}
	// If the participant is the initiator, aggregate the signature shares
	senderID, exist := p.GetIDByName(msg.From)
	if !exist {
		p.logger.With("func", "handleSignatureShareResponse").Error("Participant does not exist", "from", msg.From)
		return errors.New("Participant does not exist")
	}
	if p.signatureShares[receivedSignatureShare.InitiatorSequence] == nil {
		p.signatureShares[receivedSignatureShare.InitiatorSequence] = make(map[int]*Secp256k1FrostSignatureShare)
	}
	p.signatureShares[receivedSignatureShare.InitiatorSequence][senderID] = &receivedSignatureShare.SignatureShare
	if len(p.signatureShares[receivedSignatureShare.InitiatorSequence]) < p.minSigner {
		p.logger.With("func", "handleSignatureShareResponse").Debug("Received signature shares and more signature shares are required. Waiting for the remaining", "received", len(p.signatureShares[receivedSignatureShare.InitiatorSequence]), "required", p.minSigner)
	}

	// If the initiator has enough shares, generate the final signature
	var signatureShares []Secp256k1FrostSignatureShare
	var nonceCommitments []Secp256k1FrostNonceCommitment
	var publicKeys []Secp256k1FrostPubkey // Group public key (to be derived)
	for i := 0; i < p.numParticipants; i++ {
		if signatureShare, exist := p.signatureShares[receivedSignatureShare.InitiatorSequence][i]; exist {
			signatureShares = append(signatureShares, *signatureShare)
			p.logger.With("func", "handleSignatureShareResponse").Debug("Added signature share", "from", i)
			nonceCommitments = append(nonceCommitments, p.nonceCommitments[receivedSignatureShare.InitiatorSequence][i])
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
		return errors.New("error in aggregating signature")
	}
	p.logger.Info("Aggregated signature", "signature", aggregateSignature, "initiatorSequence", receivedSignatureShare.InitiatorSequence)

	result = Verify(aggregateSignature[:], receivedSignatureShare.Msg_hash[:], &p.keypair.PublicKeys)
	if result == 1 {
		p.logger.With("func", "handleSignatureShareResponse").Debug("Signature verified successfully!")
	} else {
		p.logger.With("func", "handleSignatureShareResponse").Debug("Signature verification failed")
	}

	p.aggregatedSig[receivedSignatureShare.InitiatorSequence] = aggregateSignature[:]
	p.mu.Lock()
	req, exist := p.requests[receivedSignatureShare.InitiatorSequence.Sequence]
	if !exist {
		p.logger.With("func", "handleSignatureShareResponse").Error("Request does not exist")
		return errors.New("Request does not exist")
	}
	delete(p.requests, receivedSignatureShare.InitiatorSequence.Sequence)
	p.mu.Unlock()

	// Send the aggregated signature to the client
	req.Response <- aggregateSignature[:]

	return nil
}
