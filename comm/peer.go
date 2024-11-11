package comm

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"distributed-multisig/logger"
)

var (
	FreqToRead = 1 * time.Second
	MaxMsgSize = 2048
)

// Peer handles the TLS connection to a peer
type Peer struct {
	ctx context.Context

	// TODO: Each peer has a unique identifier, typically a string or a hashed address (e.g., peerID = SHA-256 hash of its network address).
	// Now use 'name' for demo.
	name  string
	nonce uint32
	conn  net.Conn
	mu    sync.Mutex

	// channel to send received messages to
	msgCh chan []byte

	logger *slog.Logger
}

func NewPeer(ctx context.Context, name string, nonce uint32, conn net.Conn, msgCh chan []byte) *Peer {
	peerlogger := logger.New(logLvl).
		With("peer", name).
		With("nonce", nonce).
		With("local", conn.LocalAddr().String()).
		With("remote", conn.RemoteAddr().String())

	return &Peer{
		ctx:    ctx,
		name:   name,
		nonce:  nonce,
		conn:   conn,
		msgCh:  msgCh,
		logger: peerlogger,
	}
}

// Listen listens for incoming messages from the peer. Once receving a message,
// it will send it to the message channel for handling.
func (p *Peer) Listen() {
	defer p.logger.Debug("stopped listening")

	p.logger.Debug("starting listening")

	ticker := time.NewTicker(FreqToRead)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			data, err := p.Read()
			if err != nil { // when nothing read, n == 0 && err == EOF
				continue
			}

			p.msgCh <- data
		}
	}
}

// Send sends a message to the peer
func (p *Peer) Write(data []byte) error {
	return p.safeWrite(data)
}

func (p *Peer) Read() ([]byte, error) {
	buf := make([]byte, MaxMsgSize)

	n, err := p.conn.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf[:n], nil
}

// Close closes the connection to the peer
func (p *Peer) Close() {
	defer p.logger.Debug("peer closed")

	if p.conn != nil {
		p.conn.Close()
	}
}

// Ping sends a ping message to the peer
func (p *Peer) Ping() error {
	msg := fmt.Sprintf("ping %s->%s", p.conn.LocalAddr().String(), p.conn.RemoteAddr().String())
	pingMsg := Message{
		MsgType:  MsgTypePing,
		From:     p.name,
		Data:     []byte(msg),
		CreateAt: time.Now(),
	}
	serializedPingMsg, err := pingMsg.Serialize()
	if err != nil {
		p.logger.With("func", "Ping").Error("fail to serialize data")
		return err
	}
	return p.Write(serializedPingMsg)
}

func (p *Peer) safeWrite(data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	_, err := p.conn.Write(data)
	return err
}

func (p *Peer) SetProperty(name string, nonce uint32) {
	p.name = name
	p.nonce = nonce
	p.logger = logger.New(logLvl).
		With("peer", name).
		With("nonce", nonce).
		With("local", p.conn.LocalAddr().String()).
		With("remote", p.conn.RemoteAddr().String())
}
