package coordinator

import (
	"context"
	"log/slog"
	"math/rand/v2"
	"net"
	"sync"
	"tee-dao/comm"
	"tee-dao/logger"
	"tee-dao/rpc"
)

type CoordinatorConfig struct {
	// The address of the coordinator
	Address string
	// Cert is the path to the certificate file
	Cert string
	// Key is the path to the communication private key file
	Key string
	// CaCert is the path to the CA certificate file
	CaCert string
	// Threshold is the threshold for the DKG and multisig
	Threshold int
	// NodesNum is the number of nodes
	NodesNum int
	// NodesCACert is a list of the paths to the Nodes CA certificate files
	NodesCACert []string
}

type Coordinator struct {
	config             *CoordinatorConfig
	server             *comm.Server                           // Communication layer
	Leader             string                                 // Leader name
	participantID      int                                    // Participant ID to be assigned
	participantConfigs map[int32]*rpc.NodeConfig // Participant configurations
	configCond         *sync.Cond
	wg                 sync.WaitGroup // New WaitGroup for message loop
	ctx                context.Context
	cancel             context.CancelFunc
	logger             *slog.Logger
}

// NewCoordinator creates a new coordinator instance
func NewCoordinator(config *CoordinatorConfig) (*Coordinator, error) {
	// Initialize context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	coordinator := &Coordinator{
		config:             config,
		participantID:      0,
		participantConfigs: make(map[int32]*rpc.NodeConfig),
		configCond:         sync.NewCond(&sync.Mutex{}),
		wg:                 sync.WaitGroup{},
		ctx:                ctx,
		cancel:             cancel,
		logger:             logger.New(slog.LevelInfo).With("role", "coordinator"),
	}

	commConfig := &comm.Config{
		Name:          "coordinator",
		RpcAddress:    config.Address,
		Cert:          config.Cert,
		Key:           config.Key,
		CaCert:        config.CaCert,
		ClientsCaCert: config.NodesCACert,
	}

	coordinator.server, _ = comm.NewServer(ctx, commConfig, func(ctx context.Context, c net.Conn) {
		// Not implemented
		panic("not implemented")
	})
	// Register the RPC services for node requests
	rpcService := &ConfigService{coordinator: coordinator}
	err := coordinator.server.RegisterRPC(rpcService)
	if err != nil {
		return nil, err
	}

	return coordinator, nil
}

// Start starts the coordinator
func (c *Coordinator) Start() error {
	c.logger.Info("Starting coordinator")

	// Start the server
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.server.ListenRPC()
	}()

	return nil
}

// Close closes the coordinator
func (c *Coordinator) Close() error {
	defer c.logger.Info("Closing coordinator")

	// Cancel the context
	c.cancel()

	// Close the server
	if c.server != nil {
		c.server.Close()
	}

	// Wait for the server to finish
	c.wg.Wait()

	return nil
}

func (c *Coordinator) getNodesConfig(participantConfig *rpc.NodeConfig) bool {
	// Assume the attestation has been completed at the connection time

	// Validate the participant configuration
	exist := false
	for _, config := range c.participantConfigs {
		if config.Name == participantConfig.Name {
			exist = true
			break
		}
	}
	if exist {
		c.logger.With("func", "getNodesConfig").Debug("Already exist config for name", "name", participantConfig.Name)
		return false
	}

	// Store the participant configuration
	c.participantConfigs[int32(c.participantID)] = participantConfig
	c.participantID++

	// Check if all participants' configurations have been received
	if len(c.participantConfigs) == c.config.NodesNum {
		// randomly select a leader
		randLeaderID := rand.IntN(c.config.NodesNum)
		for id, config := range c.participantConfigs {
			if id == int32(randLeaderID) {
				c.Leader = config.Name
				break
			}
		}
		// Broadcast that all configurations have been received
		c.configCond.Broadcast()
	}

	return true
}
