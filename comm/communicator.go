package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"time"

	"tee-dao/logger"
)

var (
	// Frequency to ping peers
	FreqToPing  = 5 * time.Second
	MsgChanSize = 100

	ErrPeerNotFound = errors.New("peer not found")
)

type MessageHandler func(Message)

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

	msgCh    chan []byte
	handlers map[MessageType]MessageHandler

	logger *slog.Logger
	wg     sync.WaitGroup
}

func NewCommunicator(
	cfg *Config,
) (*Communicator, error) {
	peerInfo := make(map[string]*PeerConfig)
	for _, peer := range cfg.Peers {
		peerInfo[peer.Name] = &peer
	}

	cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		return nil, err
	}

	peerCACerts := make(map[string][]byte)
	for _, peer := range cfg.Peers {
		peerCACert, err := os.ReadFile(peer.CACert)
		if err != nil {
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
		handlers:    make(map[MessageType]MessageHandler),
		msgCh:       make(chan []byte, MsgChanSize),
		logger:      logger.New(logLvl).With("communicator", cfg.Name),
	}

	comm.srv = NewServer(ctx, cfg, comm.handleConn)

	// Register base message handlers
	comm.RegisterHandler("Ping", MsgTypePing, comm.handlePing)

	return comm, nil
}

// RegisterHandler adds a handler for a specific message type.
func (c *Communicator) RegisterHandler(msgName string, msgType MessageType, handler MessageHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handlers[msgType] = handler
	RegisterMessageType(msgType, msgName)
}

func (c *Communicator) RegisterRPCService(service interface{}) error {
	return c.srv.RegisterRPC(service)
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

	// start the server
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.srv.ListenTLS()
	}()

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.srv.ListenRPC()
	}()

	// connect to all peers
	for _, name := range c.PeerNames() {
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			c.connect(name)
		}()
	}

	// start the heartbeat loop
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.heartbeatLoop()
	}()

	// start the message handler loop
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.handleMessageLoop()
	}()

	return nil
}

// SetPeer adds a new peer to the list of connected peers. It is thread-safe.
func (c *Communicator) SetPeer(peer *Peer) bool {
	defer c.mu.Unlock()
	c.mu.Lock()

	if currentPeer, ok := c.peers[peer.name]; ok && currentPeer != nil && peer.nonce < currentPeer.nonce {
		c.logger.With("func", "SetPeer").Debug("peer connection already exists", slog.String("peer", peer.name))
		return false
	}

	c.peers[peer.name] = peer

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

// heartbeatLoop periodically pings all connected peers to check if they are still alive.
// If a peer is not reachable, it will be removed from the list of connected peers and
// try to reconnect the peer.
func (c *Communicator) heartbeatLoop() {
	c.logger.Info("Starting heartbeat loop")
	defer c.logger.Info("Stopped heartbeat loop")

	peerNames := c.PeerNames()

	tickerPing := time.NewTicker(FreqToPing)
	defer tickerPing.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-tickerPing.C:
			for _, name := range peerNames {
				peer := c.GetPeer(name)
				if peer == nil { // peer does not exist, try to reconnect
					c.wg.Add(1)
					go func() {
						defer c.wg.Done()
						if err := c.connect(name); err != nil {
							c.logger.With("func", "hearbeatLoop").Error("failed to connect", slog.String("target", name), slog.String("err", err.Error()))
						}
					}()
				} else { // peer exists, ping it
					if err := peer.Ping(); err != nil { // if fail, remove the peer
						c.logger.With("func", "hearbeatLoop").Error("failed to ping", slog.String("target", name), slog.String("err", err.Error()))
						peer.Close()
						c.RemovePeer(name)
						// try to reconnect
						c.wg.Add(1)
						go func() {
							defer c.wg.Done()
							if err := c.connect(name); err != nil {
								c.logger.With("func", "hearbeatLoop").Error("failed to connect", slog.String("target", name), slog.String("err", err.Error()))
							}
						}()
					}
				}
			}
		}
	}
}

// connect
//
//	dials the peer,
//	if success, sends the name to the peer,
//	adds the peer to the list of connected peers,
//	and if success, starts the listener.
func (c *Communicator) connect(name string) error {
	conn, err := c.dial(name)
	if err != nil {
		return err
	}

	nonce := rand.Uint32()
	peer := NewPeer(c.ctx, name, nonce, conn, c.msgCh)

	nonceBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(nonceBuf, peer.nonce) // Use BigEndian or LittleEndian as needed

	// send setup message to the peer
	mySetupMsg := Message{
		MsgType:  MsgTypeSetUp,
		From:     c.cfg.Name,
		Data:     nonceBuf,
		CreateAt: time.Now(),
	}
	serializedMySetupMsg, err := mySetupMsg.Serialize()
	if err != nil {
		c.logger.With("func", "connect").Error("fail to serialize data, closing connection", slog.String("peer", name))
		peer.Close()
		return err
	}

	if err := peer.Write(serializedMySetupMsg); err != nil {
		c.logger.With("func", "connect").Error("fail to send setup message, closing connection", slog.String("peer", name))
		peer.Close()
		return err
	}

	if !c.SetPeer(peer) {
		c.logger.With("func", "connect").Debug("failed to set peer, closing connection", slog.String("peer", name))
		peer.Close()
		return err
	}

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		peer.Listen()
	}()

	return nil
}

func (c *Communicator) handleConn(ctx context.Context, conn net.Conn) {
	peer := NewPeer(ctx, "", 0, conn, c.msgCh)

	// receive setup message from the peer
	data, err := peer.Read()
	if err != nil {
		c.logger.With("func", "handleConn").Error("failed to read peer name, closing connection", slog.String("err", err.Error()))
		peer.Close()
		return
	}

	var peerSetupMsg Message
	if err := peerSetupMsg.Deserialize(data); err != nil {
		c.logger.With("func", "handleConn").Error("failed to deserialize data, closing connection", slog.String("err", err.Error()))
		peer.Close()
		return
	}

	peerNonce := binary.BigEndian.Uint32(peerSetupMsg.Data)
	peer.SetProperty(peerSetupMsg.From, peerNonce)

	// set the peer
	if !c.SetPeer(peer) {
		c.logger.With("func", "handleConn").Debug("failed to set peer, closing connection", slog.String("peer", peerSetupMsg.From))
		conn.Close()
		return
	}

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		peer.Listen()
	}()
}

func (c *Communicator) handleMessageLoop() {
	c.logger.Info("Starting message handler loop")
	defer c.logger.Info("Stopped message handler loop")

	for {
		select {
		case <-c.ctx.Done():
			return
		case msg := <-c.msgCh:
			c.handleMessage(msg)
		}
	}
}

// handleMessage processes an incoming message by calling the registered handler.
func (c *Communicator) handleMessage(data []byte) {
	var msg Message
	if err := msg.Deserialize(data); err != nil {
		c.logger.With("func", "handleMessage").Error("Failed to deserialize message", "data", string(data), "err", err)
		return
	}

	c.mu.Lock()
	handler, exists := c.handlers[msg.MsgType]
	c.mu.Unlock()

	if exists {
		handler(msg)
	} else {
		c.logger.With("func", "handleMessage").Debug("Received unknown message type", "type", msg.MsgType)
	}
}

// Handler for MsgTypePing
func (c *Communicator) handlePing(msg Message) {
	c.logger.With("func", "handlePing").Debug("Received Ping message", "data", string(msg.Data))
}

func (c *Communicator) dial(peerName string) (net.Conn, error) {
	info := c.peerInfo[peerName]
	if info == nil {
		return nil, ErrPeerNotFound
	}

	CACertPool := x509.NewCertPool()
	CACertPool.AppendCertsFromPEM(c.peerCACerts[peerName])
	tlsConfig := &tls.Config{
		RootCAs:      CACertPool,
		Certificates: []tls.Certificate{*c.clientCert},
	}

	conn, err := tls.Dial("tcp", info.Address, tlsConfig)
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func (c *Communicator) SendMessage(name string, data []byte) error {
	peer := c.GetPeer(name)
	if peer == nil {
		return ErrPeerNotFound
	}
	if err := peer.Write(data); err != nil {
		c.logger.With("func", "SendMessage").Error("failed to send message", slog.String("dest", peer.name), slog.String("err", err.Error()))
		return err
	}
	return nil
}

func (c *Communicator) Broadcast(data []byte) error {
	for _, name := range c.PeerNames() {
		peer := c.GetPeer(name)
		if peer == nil {
			continue
		}
		if err := peer.Write(data); err != nil {
			c.logger.With("func", "Broadcast").Error("failed to send message", slog.String("dest", peer.name), slog.String("err", err.Error()))
			return err
		}
	}
	return nil
}
