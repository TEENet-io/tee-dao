package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"os"
	"sync"

	"distributed-multisig/logger"
)

type Server struct {
	cfg *Config
	ctx context.Context

	listener   net.Listener
	handleConn func(context.Context, net.Conn)

	logger *slog.Logger
	wg     sync.WaitGroup
}

func NewServer(
	ctx context.Context,
	cfg *Config,
	handleConn func(context.Context, net.Conn),
) *Server {
	return &Server{
		ctx:        ctx,
		cfg:        cfg,
		handleConn: handleConn,
		logger:     logger.New(logLvl).With("server", cfg.Name),
	}
}

func (srv *Server) Close() {
	defer srv.logger.Info("Stopped TLS server")

	if srv.listener != nil {
		srv.listener.Close()
	}

	srv.wg.Wait()
}

func (srv *Server) Listen() {
	srv.logger.Info("Starting TLS server")

	srv.logger.Debug("Loading server key pair",
		slog.String("cert", srv.cfg.Cert), slog.String("key", srv.cfg.Key))
	serverCert, err := tls.LoadX509KeyPair(srv.cfg.Cert, srv.cfg.Key)
	if err != nil {
		srv.logger.Error("Failed to load server certificate", slog.String("err", err.Error()))
		return
	}

	caCertPool := x509.NewCertPool()
	for _, peer := range srv.cfg.Peers {
		srv.logger.Debug("Loading CA cert", slog.String("ca", peer.CACert))
		caCert, err := os.ReadFile(peer.CACert)
		if err != nil {
			srv.logger.Error("Failed to read CA certifcate", slog.String("err", err.Error()))
			return
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	listener, err := tls.Listen("tcp", srv.cfg.Address, tlsConfig)
	if err != nil {
		srv.logger.Error("Failed to start TLS server", slog.String("err", err.Error()))
		return
	}

	srv.listener = listener

	// loop stops after srv.listener is explicitly closed by srv.Close()
	for {
		conn, err := srv.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			srv.logger.With("err", err).Debug("listen.Accept")
			continue
		}

		srv.logger.Debug("Client connected", slog.String("from", conn.RemoteAddr().String()))

		// routine to wait for client to disconnect and then close the connection
		srv.wg.Add(1)
		go func() {
			defer srv.wg.Done()
			srv.handleConn(srv.ctx, conn)
		}()
	}
}
