package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/rpc"
	"os"
	"strings"
	"sync"

	"tee-dao/logger"
)

type Server struct {
	cfg *Config
	ctx context.Context

	listener   net.Listener
	handleConn func(context.Context, net.Conn)

	rpcListener net.Listener

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

	if srv.rpcListener != nil {
		srv.rpcListener.Close()
	}

	srv.wg.Wait()
}

func (srv *Server) ListenTLS() {
	srv.logger.Info("Starting TLS server")

	srv.logger.With("func", "ListenTLS").Debug("Loading server key pair",
		slog.String("cert", srv.cfg.Cert), slog.String("key", srv.cfg.Key))
	serverCert, err := tls.LoadX509KeyPair(srv.cfg.Cert, srv.cfg.Key)
	if err != nil {
		srv.logger.With("func", "ListenTLS").Error("Failed to load server certificate", slog.String("err", err.Error()))
		return
	}

	caCertPool := x509.NewCertPool()
	for _, peer := range srv.cfg.Peers {
		srv.logger.With("func", "ListenTLS").Debug("Loading CA cert", slog.String("ca", peer.CACert))
		caCert, err := os.ReadFile(peer.CACert)
		if err != nil {
			srv.logger.With("func", "ListenTLS").Error("Failed to read CA certificate", slog.String("err", err.Error()))
			return
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	// Setup the server listen to ipd 0.0.0.0 with port in the config
	serverAddress := "0.0.0.0:" + strings.Split(srv.cfg.Address, ":")[1]
	listener, err := tls.Listen("tcp", serverAddress, tlsConfig)
	if err != nil {
		srv.logger.With("func", "ListenTLS").Error("Failed to start TLS server", slog.String("err", err.Error()))
		return
	}

	srv.logger.With("func", "ListenTLS").Debug("TLS server started", slog.String("address", listener.Addr().String()))
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

		srv.logger.With("func", "ListenTLS").Debug("Client connected", slog.String("from", conn.RemoteAddr().String()))

		// routine to wait for client to disconnect and then close the connection
		srv.wg.Add(1)
		go func() {
			defer srv.wg.Done()
			srv.handleConn(srv.ctx, conn)
		}()
	}
}

func (srv *Server) ListenRPC() {
	srv.logger.Info("Starting RPC server")

	srv.logger.With("func", "ListenRPC").With("func", "ListenRPC").Debug("Loading server key pair",
		slog.String("cert", srv.cfg.Cert), slog.String("key", srv.cfg.Key))
	serverCert, err := tls.LoadX509KeyPair(srv.cfg.Cert, srv.cfg.Key)
	if err != nil {
		srv.logger.Error("Failed to load server certificate", slog.String("err", err.Error()))
		return
	}

	caCertPool := x509.NewCertPool()
	for _, CACert := range srv.cfg.ClientsCACert {
		srv.logger.With("func", "ListenRPC").Debug("Loading CA cert", slog.String("ca", CACert))
		caCert, err := os.ReadFile(CACert)
		if err != nil {
			srv.logger.With("func", "ListenRPC").Error("Failed to read CA certificate", slog.String("err", err.Error()))
			return
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	// Setup the server listen to ipd 0.0.0.0 with port in the config
	serverAddress := "0.0.0.0:" + strings.Split(srv.cfg.RPCAddress, ":")[1]
	rpcListener, err := tls.Listen("tcp", serverAddress, tlsConfig)
	if err != nil {
		srv.logger.With("func", "ListenRPC").Error("Failed to start RPC server", slog.String("err", err.Error()))
		return
	}

	srv.logger.With("func", "ListenRPC").Debug("RPC server started", slog.String("address", rpcListener.Addr().String()))
	srv.rpcListener = rpcListener

	// loop stops after srv.rpcListener is explicitly closed by srv.Close()
	for {
		conn, err := srv.rpcListener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			srv.logger.With("err", err).Debug("rpcListener.Accept")
			continue
		}

		srv.logger.With("func", "ListenRPC").Debug("RPC Client connected", slog.String("from", conn.RemoteAddr().String()))

		// routine to wait for client to disconnect and then close the connection
		srv.wg.Add(1)
		go func() {
			defer srv.wg.Done()
			rpc.ServeConn(conn)
		}()
	}
}

// RegisterRPC registers an RPC service.
func (srv *Server) RegisterRPC(service interface{}) error {
	return rpc.Register(service)
}
