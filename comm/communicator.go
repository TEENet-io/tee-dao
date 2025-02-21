package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"log/slog"
	"math/rand/v2"
	"os"
	"sync"
	"time"

	"tee-dao/logger"
	pb "tee-dao/rpc"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

var (
	ErrPeerNotFound = errors.New("peer not found")
)

type MessageHandler func(*pb.NodeMsg) error

// Communicator is the main struct that handles the communications between nodes
type Communicator struct {
	cfg *Config

	ctx    context.Context
	cancel context.CancelFunc

	clientCert  *tls.Certificate
	peerCACerts map[string][]byte
	peerInfo    map[string]*PeerConfig

	srv   *Server
	peers map[string]*Peer
	mu    sync.Mutex

	handlers map[uint32]MessageHandler

	logger *slog.Logger
	wg     sync.WaitGroup
}

func NewCommunicator(
	cfg *Config,
) (*Communicator, error) {
	// init logger
	commLogger := logger.New(logLvl).With("communicator", cfg.Name)

	// create a map of peer info
	peerInfo := make(map[string]*PeerConfig)
	for _, peer := range cfg.Peers {
		peerInfo[peer.Name] = &peer
	}

	// Load client certificate and private key
	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		commLogger.With("func", "NewCommunicator").Error("failed to load client certificate", slog.String("err", err.Error()))
		return nil, err
	}

	peerCACerts := make(map[string][]byte)
	for _, peer := range cfg.Peers {
		peerCACert, err := os.ReadFile(peer.CaCert)
		if err != nil {
			commLogger.With("func", "NewCommunicator").Error("failed to read peer CA certificate", slog.String("err", err.Error()))
			return nil, err
		}
		peerCACerts[peer.Name] = peerCACert
	}

	ctx, cancel := context.WithCancel(context.Background())

	comm := &Communicator{
		cfg:         cfg,
		ctx:         ctx,
		cancel:      cancel,
		clientCert:  &cert,
		peerCACerts: peerCACerts,
		peerInfo:    peerInfo,
		peers:       make(map[string]*Peer),
		handlers:    make(map[uint32]MessageHandler),
		logger:      commLogger,
	}

	comm.srv, err = NewServer(ctx, cfg)
	if err != nil {
		commLogger.With("func", "NewCommunicator").Error("failed to create server", slog.String("err", err.Error()))
		return nil, err
	}

	// Register base message handlers
	comm.RegisterHandler("Ping", MsgTypePing, comm.handlePing)

	return comm, nil
}

// RegisterHandler adds a handler for a specific message type.
func (c *Communicator) RegisterHandler(msgName string, msgType uint32, handler MessageHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handlers[msgType] = handler
	RegisterMessageType(msgType, msgName)
}

func (c *Communicator) RegisterRPCService(service interface{}) error {
	c.srv.RegisterRPC(service)
	return nil
}

func (c *Communicator) Close() {
	defer c.logger.Info("Stopped communicator")

	c.cancel()

	for _, peer := range c.peers {
		if peer != nil {
			peer.Close()
		}
	}

	if c.srv != nil {
		c.srv.Close()
	}

	c.wg.Wait()
}

func (c *Communicator) SelfName() string {
	return c.cfg.Name
}

func (c *Communicator) PeerNames() []string {
	var names []string
	for _, peer := range c.cfg.Peers {
		names = append(names, peer.Name)
	}
	return names
}

func (c *Communicator) Start() error {
	c.logger.Info("Starting communicator")

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.srv.ListenRPC()
	}()

	// connect to all peers
	for _, peerName := range c.PeerNames() {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.connect(c.SelfName(), peerName)
		}()
	}

	return nil
}

// SetPeer adds a new peer to the list of connected peers. It is thread-safe.
func (c *Communicator) SetPeer(peer *Peer) bool {
	defer c.mu.Unlock()
	c.mu.Lock()

	if currentPeer, ok := c.peers[peer.remote]; ok && currentPeer != nil && peer.nonce < currentPeer.nonce {
		c.logger.With("func", "SetPeer").Debug("peer connection already exists", slog.String("peer", peer.remote))
		return false
	}

	c.peers[peer.remote] = peer

	return true
}

// GetPeer gets the peer from the list of connected peers by name.
// It is thread-safe.
func (c *Communicator) GetPeer(name string) *Peer {
	defer c.mu.Unlock()
	c.mu.Lock()

	peer, ok := c.peers[name]
	if !ok {
		return nil
	}

	return peer
}

// RemovePeer removes the peer with the given name from the list of connected peers.
// It is thread-safe.
func (c *Communicator) RemovePeer(name string) {
	defer c.mu.Unlock()
	c.mu.Lock()

	delete(c.peers, name)
}

// connect dials the peer,
//
//	if success, sends the name to the peer,
//	adds the peer to the list of connected peers,
//	and if success, starts the listener.
func (c *Communicator) connect(selfName string, peerName string) error {
	conn, err := c.dial(peerName)
	if err != nil {
		return err
	}

	nonce := rand.Uint32()
	peer := NewPeer(nonce, conn, selfName, peerName)

	nonceBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(nonceBuf, peer.nonce) // Use BigEndian or LittleEndian as needed

	if !c.SetPeer(peer) {
		c.logger.With("func", "connect").Debug("failed to set peer, closing connection", slog.String("peer", peerName))
		peer.Close()
		return err
	}

	return nil
}

// handleMessage processes an incoming message by calling the registered handler.
func (c *Communicator) handleMessage(msg *pb.NodeMsg) error {
	c.mu.Lock()
	handler, exists := c.handlers[msg.MsgType]
	c.mu.Unlock()

	if exists {
		return handler(msg)
	} else {
		c.logger.With("func", "handleMessage").Debug("Received unknown message type", "type", msg.MsgType)
		return errors.New("unknown message type")
	}
}

// Handler for MsgTypePing
func (c *Communicator) handlePing(msg *pb.NodeMsg) error {
	c.logger.With("func", "handlePing").Debug("Received Ping message", "data", string(msg.Data))
	return nil
}

func (c *Communicator) dial(peerName string) (*grpc.ClientConn, error) {
	info := c.peerInfo[peerName]
	if info == nil {
		return nil, ErrPeerNotFound
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(c.peerCACerts[peerName])
	tlsConfig := &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{*c.clientCert},
	}

	keepaliveParams := keepalive.ClientParameters{
		Time:                10 * time.Minute, // send pings every 10 min if there is no activity
		Timeout:             30 * time.Second, // wait 30 second for ping ack before considering the connection dead
		PermitWithoutStream: true,             // send pings even without active streams
	}

	conn, err := grpc.NewClient(info.RpcAddress,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithConnectParams(grpc.ConnectParams{
			// Retry backoff parameters
			Backoff: backoff.Config{
				BaseDelay:  time.Second,       // Base delay is 1 second
				Multiplier: 1.6,               // Retry with exponential backoff
				Jitter:     0.2,               // add 20% jitter, i.e. +/- 10%
				MaxDelay:   120 * time.Second, // Maximum delay is 120 seconds
			},
			MinConnectTimeout: 5 * time.Second,
		}),
		grpc.WithKeepaliveParams(keepaliveParams),
	)
	if err != nil {
		c.logger.With("func", "dial").Error("failed to dial", slog.String("peer", peerName), slog.String("err", err.Error()))
		return nil, err
	}

	return conn, nil
}

func (c *Communicator) SendMessage(name string, msg *pb.NodeMsg) error {
	peer := c.GetPeer(name)
	if peer == nil {
		return ErrPeerNotFound
	}

	// create a client for node communication rpc
	client := pb.NewNodeCommClient(peer.conn)
	// Call RequestHandler with context and message
	_, err := client.RequestHandler(context.Background(), msg)

	// If got an error, log and retry
	if err != nil {
		c.logger.With("func", "SendMessage").Error("resending message", slog.String("dest", name), slog.String("err", err.Error()))
		return err
	}

	return nil
}

func (c *Communicator) Broadcast(msg *pb.NodeMsg) error {
	for _, name := range c.PeerNames() {
		peer := c.GetPeer(name)
		if peer == nil {
			continue
		}
		// create a client for node communication rpc
		client := pb.NewNodeCommClient(peer.conn)

		// Call RequestHandler with context and message
		_, err := client.RequestHandler(context.Background(), msg)

		// If got an error, log and retry
		if err != nil {
			c.logger.With("func", "Broadcast").Error("resending message", slog.String("dest", name), slog.String("err", err.Error()))
			return err
		}
	}
	return nil
}
