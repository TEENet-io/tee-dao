package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"tee-dao/comm"

	// "tee-dao/coordinator"
	"tee-dao/frost_dkg_multisig"
	pb "tee-dao/rpc"
	"tee-dao/utils"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Request the general configuration from the coordinator
func requestConfig(nodeConfig *pb.NodeConfig) (*pb.GetConfigReply, error) {
	// Load node certificate and key
	cert, err := tls.LoadX509KeyPair(nodeConfig.Cert, nodeConfig.Key)
	if err != nil {
		fmt.Printf("failed to load client certificate and key: %v", err)
		return nil, err
	}

	// Load CA certificate
	caCertPool := x509.NewCertPool()
	fmt.Printf("Loading CA cert: %s", nodeConfig.CoordinatorCaCert)
	caCert, err := os.ReadFile(nodeConfig.CoordinatorCaCert)
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

	// Connect to the gRPC server with TLS
	conn, err := grpc.Dial(nodeConfig.CoordinatorAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		log.Fatalf("Error connecting to gRPC server: %v", err)
	}
	defer conn.Close()

	// Create a new DKG client
	client := pb.NewCoordinatorClient(conn)

	// Prepare and make the GetPubKey RPC call
	log.Printf("Requesting configuration from coordinator %s\n", nodeConfig.CoordinatorAddress)
	getConfigRequest := &pb.GetConfigRequest{ParticipantConfig: nodeConfig}
	getConfigReply, err := client.GetConfig(context.Background(), getConfigRequest)
	if err != nil {
		log.Fatalf("Error calling GetConfig: %v", err)
	}

	log.Printf("Configuration Reply: %v", getConfigReply)

	return getConfigReply, nil
}

func main() {
	name := flag.String("n", "node0", "Name of the participant")
	flag.Parse()
	// Step 1: Load Configurations
	nodeConfig, err := utils.LoadNodeConfig(fmt.Sprintf("config/config_%s.json", *name))
	if err != nil {
		log.Fatalf("Error loading node config: %v", err)
	}

	log.Printf("Node config loaded: %v\n", nodeConfig)

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
			peers = append(peers, comm.PeerConfig{ID: int(id), Name: participantConfig.Name, RpcAddress: participantConfig.RpcAddress, CaCert: participantConfig.CaCert})
		} else {
			ID = int(id)
		}
	}
	config := comm.Config{
		ID:            ID,
		Name:          nodeConfig.Name,
		RpcAddress:    nodeConfig.RpcAddress,
		Cert:          nodeConfig.Cert,
		Key:           nodeConfig.Key,
		CaCert:        nodeConfig.CaCert,
		Peers:         peers,
		ClientsCaCert: nodeConfig.ClientsCaCert,
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
	participant, err := frost_dkg_multisig.NewParticipant(configReply.Leader, &config, isLeader, ID, len(allParticipantConfigs), int(configReply.Threshold), context, tag)
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
