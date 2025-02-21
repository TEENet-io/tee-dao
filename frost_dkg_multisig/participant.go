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
	Message  [32]byte    // Message to be signed (32-byte hash)
	Response chan []byte // Signature response (64-byte)
	Sequence int         // Sequence number is set by the server
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
	commitments               sync.Map // map[int]*Secp256k1FrostVssCommitments
	secretShares              sync.Map // map[int]*Secp256k1FrostKeygenSecretShare
	readyForPreprocessingNum  sync.Map // map[int]int
	sequence                  int      // My Sequence number for the message signature request
	mu                        sync.Mutex
	requests                  sync.Map // map[int]*Request
	signingMessage            sync.Map // map[InitiatorSequence][]byte
	nonces                    sync.Map // map[InitiatorSequence]*Secp256k1FrostNonce
	nonceCommitments          sync.Map // map[InitiatorSequence]map[int]Secp256k1FrostNonceCommitment
	readyForSignNum           sync.Map // map[InitiatorSequence]map[int]int
	keypair                   *Secp256k1FrostKeypair
	publicKeys                sync.Map // map[int]Secp256k1FrostPubkey
	signatureShares           sync.Map // map[InitiatorSequence]map[int]*Secp256k1FrostSignatureShare
	aggregatedSig             sync.Map // map[InitiatorSequence][]byte
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
		commitments:               sync.Map{},
		secretShares:              sync.Map{},
		sequence:                  0,
		requests:                  sync.Map{},
		signingMessage:            sync.Map{},
		readyForPreprocessingNum:  sync.Map{},
		nonces:                    sync.Map{},
		nonceCommitments:          sync.Map{},
		readyForSignNum:           sync.Map{},
		keypair:                   &Secp256k1FrostKeypair{},
		publicKeys:                sync.Map{},
		signatureShares:           sync.Map{},
		aggregatedSig:             sync.Map{},
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

// countSyncMapElements counts the number of elements in a sync.Map.
func countSyncMapElements(m *sync.Map) int {
	count := 0
	m.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// HandleRequest handles the client request for signature generation
func (p *Participant) HandleRequest(request *Request) error {
	// Store the request in the map
	p.mu.Lock()
	request.Sequence = p.sequence
	p.sequence++
	p.mu.Unlock()

	p.requests.Store(request.Sequence, request)

	p.logger.Info("Handling request", "sequence", request.Sequence)
	// Process the request
	err := p.initiatePreprocessing(request)
	if err != nil {
		p.logger.With("func", "HandleRequest").Error("Failed to process request", "err", err)
		return err
	}
	return nil
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
	p.signingMessage.Store(initiatorSequence, request.Message)
	p.nonces.Store(initiatorSequence, nonce)
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
		// Load or create the map for the initiator sequence
		readyMap, _ := p.readyForSignNum.LoadOrStore(initiatorSequence, &sync.Map{})
		readyMap.(*sync.Map).Store(p.id, 1)
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
	value, exist := p.signingMessage.Load(initiatorSequence)
	if !exist {
		p.logger.With("func", "initiateSigning").Error("Message not found for initiatorSequence", "initiatorSequence", initiatorSequence)
		return errors.New("message not found")
	}
	msgHash := value.([32]byte)
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
	if _, exist := p.nonceCommitments.Load(initiatorSequence); !exist {
		p.logger.With("func", "initiateSigning").Error("Nonce commitment not found for initiatorSequence", "initiatorSequence", initiatorSequence)
		return errors.New("nonce commitment not found")
	}
	for i := 0; i < p.minSigner; i++ {
		signerID := signers[i]
		commitmentMap, _ := p.nonceCommitments.Load(initiatorSequence)
		if commitmentValue, exist := commitmentMap.(*sync.Map).Load(signerID); exist {
			commitment := commitmentValue.(Secp256k1FrostNonceCommitment)
			nonceCommitment = append(nonceCommitment, commitment)
			if len(nonceCommitment) == countSyncMapElements(commitmentMap.(*sync.Map)) {
				break
			}
		} else {
			p.logger.With("func", "initiateSigning").Error("Nonce commitment not found for signer", "signer", signerID)
			return errors.New("nonce commitment not found")
		}
	}

	// Generate and send the signature share
	value, ok := p.nonces.Load(initiatorSequence)
	if !ok {
		p.logger.With("func", "initiateSigning").Error("Nonce not found for initiatorSequence", "initiatorSequence", initiatorSequence)
		return errors.New("nonce not found")
	}
	nonce := value.(*Secp256k1FrostNonce)
	p.logger.With("func", "initiateSigning").Debug("Generating signature share", "msgHash", msgHash, "minSigner", p.minSigner, "key pair", p.keypair, "nonces", nonce, "nonce commitment", nonceCommitment)
	var signatureShare Secp256k1FrostSignatureShare
	result := Sign(
		&signatureShare,
		msgHash[:],
		uint32(p.minSigner),
		p.keypair,
		nonce,
		nonceCommitment,
	)

	if result != 1 {
		p.logger.With("func", "initiateSigning").Error("Error in signing message")
		return errors.New("error in signing message")
	}
	p.logger.With("func", "initiateSigning").Debug("Generated signature share", "signature share", signatureShare)
	signatureShareMap, _ := p.signatureShares.LoadOrStore(initiatorSequence, &sync.Map{})
	signatureShareMap.(*sync.Map).Store(p.id, &signatureShare)

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
	nonceCommitmentMap, _ := p.nonceCommitments.LoadOrStore(initiatorSequence, &sync.Map{})
	nonceCommitmentMap.(*sync.Map).Store(participantId, nonceCommitment)
	commitmentsNum := countSyncMapElements(nonceCommitmentMap.(*sync.Map))
	p.logger.With("func", "receiveNonceCommitment").Debug("Length of nonce commitments", "length", commitmentsNum)

	// Check if received enough nonce commitments to finalize preprocessing
	if commitmentsNum == p.numParticipants {
		p.logger.With("func", "receiveNonceCommitment").Debug("All participants have sent nonce commitments", "num", commitmentsNum, "participants", p.numParticipants)
		p.completePreprocessing(initiatorSequence)
	} else {
		p.logger.With("func", "receiveNonceCommitment").Debug("Not all participants have sent nonce commitments", "num", commitmentsNum, "participants", p.numParticipants)
	}
	return nil
}

// receiveShareWithCommitment receives the share with commitment from the participant and stores it
func (p *Participant) receiveShareWithCommitment(participantId int, secretShare Secp256k1FrostKeygenSecretShare, commitments Secp256k1FrostVssCommitments) error {
	p.logger.With("func", "receiveShareWithCommitment").Debug("Received share with commitment", "from", participantId, "share", secretShare, "commitment", commitments)
	p.secretShares.Store(participantId, &secretShare)
	p.commitments.Store(participantId, &commitments)

	// Check if received enough secret shares to finalize DKG
	secretSharesNum := countSyncMapElements(&p.secretShares)
	if secretSharesNum == p.numParticipants {
		// Convert the secret shares and commitments map to slices
		sharesByParticipant := make([]Secp256k1FrostKeygenSecretShare, p.numParticipants)
		for i := 0; i < p.numParticipants; i++ {
			sharesValue, _ := p.secretShares.Load(i)
			shares := sharesValue.(*Secp256k1FrostKeygenSecretShare)
			sharesByParticipant[i] = *shares
			p.logger.With("func", "receiveShareWithCommitment").Debug("Shares", "index", i, "sharesByParticipant", sharesByParticipant[i])
		}
		commitmentsPointers := make([]*Secp256k1FrostVssCommitments, p.numParticipants)
		for i := 0; i < p.numParticipants; i++ {
			commitmentsValue, _ := p.commitments.Load(i)
			commitments := commitmentsValue.(*Secp256k1FrostVssCommitments)
			commitmentsPointers[i] = commitments
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
		isOdd := IsPubkeyOdd(&p.keypair.PublicKeys)
		p.logger.With("func", "receiveShareWithCommitment").Info("Is public key odd", "isOdd", isOdd)

		p.logger.With("func", "receiveShareWithCommitment").Debug("Finalized DKG", "keypair", p.keypair)
		err := p.completeDKG()
		if err != nil {
			p.logger.With("func", "receiveShareWithCommitment").Error("Failed to complete DKG", "err", err)
			return err
		}
	} else {
		p.logger.With("func", "receiveShareWithCommitment").Debug("Not all participants have sent DKG secret shares", "num", secretSharesNum, "participants", p.numParticipants)
	}
	return nil
}

// receivePublicKey receives the public key from the participant and stores it
func (p *Participant) receivePublicKey(participantId int, publicKey Secp256k1FrostPubkey) error {
	p.logger.With("func", "receivePublicKey").Debug("Received public key", "from", participantId, "public key", publicKey)
	p.readyForPreprocessingNum.Store(participantId, 1)
	p.publicKeys.Store(participantId, publicKey)

	// Check if received enough public keys to finalize preprocessing
	publicKeysNum := countSyncMapElements(&p.publicKeys)
	if publicKeysNum == p.numParticipants {
		p.logger.With("func", "receivePublicKey").Debug("All participants have sent public keys", "num", publicKeysNum, "participants", p.numParticipants)
		p.readyForInitPreprocessing = true
	} else {
		p.logger.With("func", "receivePublicKey").Debug("Not all participants have sent public keys", "num", publicKeysNum, "participants", p.numParticipants)
	}

	// Check if all participants are ready for preprocessing
	readyPreprocessNum := countSyncMapElements(&p.readyForPreprocessingNum)
	if readyPreprocessNum == p.numParticipants && p.dkgCompleted {
		p.logger.Info("All participants are ready. Waiting for client signing request.")
		p.readyForInitPreprocessing = true
	} else {
		if readyPreprocessNum != p.numParticipants {
			p.logger.With("func", "receivePublicKey").Debug("Not all participants are ready for preprocessing. ReadyForPreprocessingNum", "num", readyPreprocessNum, "participants", p.numParticipants)
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

	readySigMap, _ := p.readyForSignNum.LoadOrStore(preprocessingComplete.InitiatorSequence, &sync.Map{})
	readySigMap.(*sync.Map).Store(senderID, 1)

	// Check if enough participants have sent ReadyForSign
	// TODO: In demo, we are assuming all participants have sent nonce commitments. Actually, only the minimum signers are needed but all the signer should have a consensus on the same set.
	readySigNum := countSyncMapElements(readySigMap.(*sync.Map))
	if readySigNum == p.numParticipants && p.preprocessingComplete {
		p.logger.Info("All participants are ready. Initiator initiating signing process.")
		p.initiateSigning(preprocessingComplete.InitiatorSequence)
	} else {
		if readySigNum != p.numParticipants {
			p.logger.With("func", "handleReadyForSign").Debug("Not all participants are ready for sign. ReadyForSignNum", "num", readySigNum, "participants", p.numParticipants)
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
	p.nonces.Store(preprocessingRequest.InitiatorSequence, nonce)
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
	nonceCommitmentMap, exist := p.nonceCommitments.Load(signMessage.InitiatorSequence)
	if !exist {
		p.logger.With("func", "handleSignRequest").Error("Nonce commitment not found for initiatorSequence", "initiatorSequence", signMessage.InitiatorSequence)
		return errors.New("nonce commitment not found")
	}
	nonceCommitmentNum := countSyncMapElements(nonceCommitmentMap.(*sync.Map))
	for i := 0; i < p.minSigner; i++ {
		signerID := signMessage.Signers[i]
		if value, exist := nonceCommitmentMap.(*sync.Map).Load(signerID); exist {
			commitment := value.(Secp256k1FrostNonceCommitment)
			nonceCommitment = append(nonceCommitment, commitment)
			if len(nonceCommitment) == nonceCommitmentNum {
				break
			}
		} else {
			p.logger.With("func", "handleSignRequest").Error("Nonce commitment not found for signer", "signer", signerID)
			return errors.New("nonce commitment not found")
		}
	}

	// Generate and send the signature share
	value, _ := p.nonces.Load(signMessage.InitiatorSequence)
	nonce := value.(*Secp256k1FrostNonce)
	p.logger.With("func", "handleSignRequest").Debug("Generating signature share", "msgHash", signMessage.Msg_hash, "minSigner", p.minSigner, "key pair", p.keypair, "nonces", nonce, "nonce commitment", nonceCommitment)
	var signatureShare Secp256k1FrostSignatureShare
	result := Sign(
		&signatureShare,
		signMessage.Msg_hash[:],
		uint32(p.minSigner),
		p.keypair,
		nonce,
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

	if aggregateSig, exist := p.aggregatedSig.Load(receivedSignatureShare.InitiatorSequence); exist && aggregateSig != nil {
		p.logger.With("func", "handleSignatureShareResponse").Debug("Already have the signature. Ignore the message", "from", msg.From)
		return nil
	}
	// If the participant is the initiator, aggregate the signature shares
	senderID, exist := p.GetIDByName(msg.From)
	if !exist {
		p.logger.With("func", "handleSignatureShareResponse").Error("Participant does not exist", "from", msg.From)
		return errors.New("Participant does not exist")
	}
	signatureSharesMap, _ := p.signatureShares.LoadOrStore(receivedSignatureShare.InitiatorSequence, &sync.Map{})
	signatureSharesMap.(*sync.Map).Store(senderID, &receivedSignatureShare.SignatureShare)
	signatureSharesNum := countSyncMapElements(signatureSharesMap.(*sync.Map))
	if signatureSharesNum < p.minSigner {
		p.logger.With("func", "handleSignatureShareResponse").Debug("Received signature shares and more signature shares are required. Waiting for the remaining", "received", signatureSharesNum, "required", p.minSigner)
	}

	// If the initiator has enough shares, generate the final signature
	var signatureShares []Secp256k1FrostSignatureShare
	var nonceCommitments []Secp256k1FrostNonceCommitment
	var publicKeys []Secp256k1FrostPubkey // Group public key (to be derived)
	nonceCommitmentsMap, _ := p.nonceCommitments.Load(receivedSignatureShare.InitiatorSequence)
	for i := 0; i < p.numParticipants; i++ {
		if signatureShareValue, exist := signatureSharesMap.(*sync.Map).Load(i); exist {
			signatureShare := signatureShareValue.(*Secp256k1FrostSignatureShare)
			signatureShares = append(signatureShares, *signatureShare)
			p.logger.With("func", "handleSignatureShareResponse").Debug("Added signature share", "from", i)
			nonceCommitmentValue, _ := nonceCommitmentsMap.(*sync.Map).Load(i)
			nonceCommitment := nonceCommitmentValue.(Secp256k1FrostNonceCommitment)
			nonceCommitments = append(nonceCommitments, nonceCommitment)
			p.logger.With("func", "handleSignatureShareResponse").Debug("Added nonce commitment", "from", i)
			publicKeyValue, _ := p.publicKeys.Load(i)
			publicKey := publicKeyValue.(Secp256k1FrostPubkey)
			publicKeys = append(publicKeys, publicKey)
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

	// Store the aggregated signature
	p.aggregatedSig.Store(receivedSignatureShare.InitiatorSequence, aggregateSignature[:])
	req, exist := p.requests.Load(receivedSignatureShare.InitiatorSequence.Sequence)
	if !exist {
		p.logger.With("func", "handleSignatureShareResponse").Error("Request does not exist")
		return errors.New("Request does not exist")
	}
	p.requests.Delete(receivedSignatureShare.InitiatorSequence.Sequence)

	// Send the aggregated signature to the client
	req.(*Request).Response <- aggregateSignature[:]

	return nil
}
