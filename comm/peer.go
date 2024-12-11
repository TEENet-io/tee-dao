package comm

import (
	"context"
	"log/slog"
	"fmt"
	"sync"
	"time"

	pb "tee-dao/rpc"
	"tee-dao/logger"

	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/grpc"
)

var (
	FreqToRead = 1 * time.Second
	MaxMsgSize = 2048
)

// Peer handles the TLS connection to a peer
type Peer struct {
	ctx context.Context

	// TODO: Each peer has a unique identifier, typically a string or a hashed address (e.g., peerID = SHA-256 hash of its network address).
	nonce uint32
	conn  *grpc.ClientConn
	local  string
	remote    string
	mu    sync.Mutex

	// channel to send received messages to
	msgCh chan []byte

	logger *slog.Logger
}

func NewPeer(ctx context.Context, nonce uint32, conn *grpc.ClientConn, local string, remote string, msgCh chan []byte) *Peer {
	peerlogger := logger.New(logLvl).
		With("nonce", nonce).
		With("local", local).
		With("remote", remote)

	return &Peer{
		ctx:    ctx,
		nonce:  nonce,
		conn:   conn,
		local:  local,
		remote: remote,
		msgCh:  msgCh,
		logger: peerlogger,
	}
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
	msg := fmt.Sprintf("ping %s->%s", p.local, p.remote)

	// create a client for node communication rpc
	client := pb.NewNodeCommClient(p.conn)

	// send ping message to the peer
	pingMsg := &pb.NodeMsg{
		MsgType:  MsgTypePing,
		From:     p.remote,
		Data:     []byte(msg),
		CreateAt: timestamppb.Now(),
	}
	_, err := client.RequestHandler(context.Background(), pingMsg)
	if err != nil {
		p.logger.With("func", "Ping").Error("fail to send ping message")
		return err
	}

	return nil
}

func (p *Peer) SetProperty(local string, remote string, nonce uint32) {
	p.local = local
	p.remote = remote
	p.nonce = nonce
	p.logger = logger.New(logLvl).
		With("nonce", nonce).
		With("local", local).
		With("remote", remote)
}
