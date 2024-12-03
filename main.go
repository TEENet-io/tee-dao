package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/rpc"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"tee-dao/comm"
	"tee-dao/coordinator"
	"tee-dao/frost_dkg_multisig"
	"tee-dao/utils"
)

// Request the general configuration from the coordinator
func requestConfig(nodeConfig *frost_dkg_multisig.NodeConfig) (*coordinator.ConfigReply, error) {
	// Load node certificate and key
	cert, err := tls.LoadX509KeyPair(nodeConfig.Cert, nodeConfig.Key)
	if err != nil {
		fmt.Printf("failed to load client certificate and key: %v", err)
		return nil, err
	}

	// Load CA certificate
	caCertPool := x509.NewCertPool()
	fmt.Printf("Loading CA cert: %s", nodeConfig.CoordinatorCACert)
	caCert, err := os.ReadFile(nodeConfig.CoordinatorCACert)
	if err != nil {
		fmt.Printf("Failed to read CA certificate. err: %v", err)
		return nil, err
	}
	caCertPool.AppendCertsFromPEM(caCert)

	// Create a TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	// Connect to the RPC server with TLS
	client, err := tls.Dial("tcp", nodeConfig.CoordinatorAddress, tlsConfig)
	if err != nil {
		fmt.Printf("Error connecting to RPC server: %v", err)
		return nil, err
	}
	defer client.Close()

	// Create an RPC client
	rpcClient := rpc.NewClient(client)

	// Call the GetConfig RPC method
	args := &coordinator.GetConfigArgs{ParticipantConfig: *nodeConfig}
	var reply coordinator.ConfigReply
	if err := rpcClient.Call("ConfigService.GetConfig", args, &reply); err != nil {
		fmt.Printf("Failed to call GetConfig RPC method: %v", err)
		return nil, err
	}

	// Print the received configuration
	fmt.Printf("Received configuration: %v", reply)
	return &reply, nil
}

func main() {
	name := flag.String("n", "node0", "Name of the participant")
	flag.Parse()
	// Step 1: Load Configurations
	nodeConfig, err := utils.LoadNodeConfig(fmt.Sprintf("config/config_%s.json", *name))
	if err != nil {
		log.Fatalf("Error loading node config: %v", err)
	}

	// Step 2: Request the general configuration from the coordinator
	configReply, err := requestConfig(nodeConfig)
	if err != nil {
		log.Fatalf("Error requesting configuration: %v", err)
	}
	allParticipantConfigs := configReply.ParticipantConfigs
	var ID int
	var peers []comm.PeerConfig
	for id, participantConfig := range allParticipantConfigs {
		if participantConfig.Name != nodeConfig.Name {
			peers = append(peers, comm.PeerConfig{ID: id, Name: participantConfig.Name, Address: participantConfig.Address, RPCAddress: participantConfig.RPCAddress, CACert: participantConfig.CACert})
		} else {
			ID = id
		}
	}
	config := comm.Config{
		ID:            ID,
		Name:          nodeConfig.Name,
		Address:       nodeConfig.Address,
		RPCAddress:    nodeConfig.RPCAddress,
		Cert:          nodeConfig.Cert,
		Key:           nodeConfig.Key,
		CACert:        nodeConfig.CACert,
		Peers:         peers,
		ClientsCACert: nodeConfig.ClientsCACert,
	}

	// Role Assignment (Leader or Participant)
	isLeader := *name == configReply.Leader
	log.Printf("Node %s initialized as %s\n", nodeConfig.Name, func() string {
		if isLeader {
			return "Leader"
		}
		return "Participant"
	}())

	// Step 3: Initialize participant state and start DKG
	// Initialize context and tag
	context := []byte("example_context") // For DKG
	tag := []byte("message_tag")         // For Signature
	participant, err := frost_dkg_multisig.NewParticipant(configReply.Leader, &config, isLeader, ID, len(allParticipantConfigs), configReply.Threshold, context, tag)
	if err != nil {
		log.Fatalf("Error creating participant: %v", err)
	}

	// Start the participant
	if err := participant.Start(); err != nil {
		log.Fatalf("Failed to start participant: %v", err)
	}
	defer participant.Close()

	// Set up WaitGroup and signal handling to wait until we receive a termination signal
	var wg sync.WaitGroup
	wg.Add(1)

	// Listen for OS interrupt signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Received shutdown signal")
		participant.Close()
		wg.Done()
	}()

	// Wait for the signal handling goroutine to finish
	wg.Wait()
	log.Println("Participant shut down gracefully")
}
