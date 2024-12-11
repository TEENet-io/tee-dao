package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"tee-dao/logger"
	pb "tee-dao/rpc"
)

type Server struct {
	cfg *Config
	ctx context.Context

	listener   net.Listener
	handleConn func(context.Context, net.Conn)

	rpcListener net.Listener

	logger *slog.Logger
	wg     sync.WaitGroup
	grpcServer *grpc.Server
}

func NewServer(
	ctx context.Context,
	cfg *Config,
) (*Server, error) {
	// init logger
	serverLogger := logger.New(logLvl).With("server", cfg.Name)

	serverLogger.Info("init gRPC server")
	serverLogger.With("func", "NewServer").Debug("Loading server key pair",
		slog.String("cert", cfg.Cert), slog.String("key", cfg.Key))


	// Load server certificate and private key
	serverCert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
	if err != nil {
		serverLogger.With("func", "NewServer").Error("Failed to load server certificate", slog.String("err", err.Error()))
		return nil, err
	}

	// Create a pool of CA certificates
	caCertPool := x509.NewCertPool()
	for _, CaCert := range cfg.ClientsCaCert {
		serverLogger.With("func", "NewServer").Debug("Loading clients CA cert", slog.String("ca", CaCert))
		caCert, err := os.ReadFile(CaCert)
		if err != nil {
			serverLogger.With("func", "NewServer").Error("Failed to read CA certificate", slog.String("err", err.Error()))
			return nil, err
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}

	for _, peer := range cfg.Peers {
		serverLogger.With("func", "NewServer").Debug("Loading peers CA cert", slog.String("ca", peer.CaCert))
		caCert, err := os.ReadFile(peer.CaCert)
		if err != nil {
			serverLogger.With("func", "NewServer").Error("Failed to read CA certificate", slog.String("err", err.Error()))
			return nil, err
		}
		caCertPool.AppendCertsFromPEM(caCert)
	}

	// Configure TLS for gRPC
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	// Create gRPC server options with TLS credentials
	grpcCreds := credentials.NewTLS(tlsConfig)
	grpcServer := grpc.NewServer(grpc.Creds(grpcCreds))


	return &Server{
		ctx:        ctx,
		cfg:        cfg,
		logger:     serverLogger,
		grpcServer:	grpcServer,
	}, nil
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

func (srv *Server) ListenRPC() error {
	srv.logger.Info("Starting RPC server")

	// Start the listener
  serverAddress := "0.0.0.0:" + strings.Split(srv.cfg.RpcAddress, ":")[1]
	rpcListener, err := net.Listen("tcp", serverAddress)

	if err != nil {
		srv.logger.With("func", "ListenRPC").Error("Failed to start gRPC server", slog.String("err", err.Error()))
		return err
	}

	srv.logger.Info("gRPC server is listening", slog.String("address", srv.cfg.RpcAddress))

	// Serve gRPC requests
	if err := srv.grpcServer.Serve(rpcListener); err != nil {
		if errors.Is(err, net.ErrClosed) {
			srv.logger.Info("gRPC server shut down")
			return err
		}
		srv.logger.With("func", "ListenRPC").Error("gRPC server encountered an error", slog.String("err", err.Error()))
	}

	return nil
}

// RegisterRPC registers an RPC service.
func (srv *Server) RegisterRPC(service interface{}) error {
	// Register the service with the gRPC server
	switch s := service.(type) {
	case pb.SignatureServer:
		pb.RegisterSignatureServer(srv.grpcServer, s)
	case pb.CoordinatorServer:
		pb.RegisterCoordinatorServer(srv.grpcServer, s)
	case pb.NodeCommServer:
		pb.RegisterNodeCommServer(srv.grpcServer, s)
	default:
		srv.logger.With("service", service).Error("unknown service type")
		return errors.New("unknown service type")
	}

	return nil
}
