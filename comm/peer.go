package comm

import (
	"context"
	"fmt"
	"log/slog"

	"tee-dao/logger"
	pb "tee-dao/rpc"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Peer handles the TLS connection to a peer
type Peer struct {
	// TODO: Each peer has a unique identifier, typically a string or a hashed address (e.g., peerID = SHA-256 hash of its network address).
	nonce  uint32
	conn   *grpc.ClientConn
	local  string
	remote string

	logger *slog.Logger
}

func NewPeer(nonce uint32, conn *grpc.ClientConn, local string, remote string) *Peer {
	peerlogger := logger.New(logLvl).
		With("nonce", nonce).
		With("local", local).
		With("remote", remote)

	return &Peer{
		nonce:  nonce,
		conn:   conn,
		local:  local,
		remote: remote,
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
	p.logger = logger.New(logLvl).
		With("nonce", nonce).
		With("local", local).
		With("remote", remote)
}
