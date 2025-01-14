package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"tee-dao/attestation"
	"tee-dao/comm"

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
	conn, err := grpc.NewClient(nodeConfig.CoordinatorAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
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

	// Step 2: Remote Attestation with the coordinator
	remoteAttestationWithCoordinator()

	// Step 3: Request the general configuration from the coordinator
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

	// Step 4: Initialize participant state and start DKG
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

/* configuration const */
const (
	address       = "20.205.129.240:8072"
	nonceClient   = "$Q9%*@JW#C%Y"                   // don't need to change
	clientCredDir = "./script/cred/client-cred"      //folder path to read client credentials(certs)
	serverCredDir = "./script/cred/server-cred-recv" //folder path to store server credentials(certs)
	mma_path      = "./script/cred/mma_config.json"  //tdx mma config file
	psh_script    = "./script/cred"
	name          = "client"
)

func remoteAttestationWithCoordinator() {
	//1.client establish socket with server（ip:localhost, port:8071）
	conn, err := net.Dial("tcp", address)
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		return
	}
	defer conn.Close()

	//2.client send: nonce(12-byte length in string format), client-ca.crt, client.crt
	//2.1 Access these file. The directory path of all these files located：./script/cred/client-cred
	//2.2 Sent to the server;
	attestation.SendMessage(conn, nonceClient)
	attestation.SendMessage(conn, name)
	myCACert := clientCredDir + "/" + name + "-ca.crt"
	myCert := clientCredDir + "/" + name + ".crt"
	attestation.SendFile(conn, myCACert)
	attestation.SendFile(conn, myCert)

	//3. receive server nonce,server-ca.crt, server.crt; And store them in "./script/cred/server-cred-recv" folder
	serverNonce := attestation.ReceiveMessage(conn)
	fmt.Println("Server Nonce:", serverNonce)
	attestation.ReceiveFile(conn, serverCredDir+"/server-ca.crt")
	attestation.ReceiveFile(conn, serverCredDir+"/server.crt")

	//4. call the system tool and obtain the return result, stored in JWTResult
	extractPubkey := attestation.CallOpensslGetPubkey(myCert)
	extractPubkey = attestation.ExtractPubkeyFromPem(extractPubkey)
	fmt.Println("Extracted Public Key:", extractPubkey)

	machineName, err := os.Hostname()
	fmt.Println("Machine Name:", machineName)
	jwtResult := ""
	if err != nil {
		fmt.Println("Error getting machine name:", err)
		return
	}
	if strings.Contains(strings.ToUpper(machineName), "SNP") {
		fmt.Println("callSNPAttestationClient")
		jwtResult = attestation.CallSNPAttestationClient(serverNonce + extractPubkey)

	} else if strings.Contains(strings.ToUpper(machineName), "TDX") {
		fmt.Println("callTDXAttestationClient")
		jwtResult = attestation.CallTDXAttestationClient(serverNonce+extractPubkey, mma_path)
	} else {
		fmt.Println("Unsupported machine type")
		return
	}

	//5. client send JWTResult to server
	fmt.Println("Send self JWT Result:", jwtResult)
	attestation.SendMessage(conn, jwtResult)

	// //6. receive server JWTResult and print it
	// serverJwtResult := attestation.ReceiveMessage(conn)
	// fmt.Println("Recv Server JWT Result:", serverJwtResult)

	// //7. validate server JWTResult
	// isValid, err := attestation.ValidateJWTwithPSH(serverJwtResult)
	// if err != nil {
	// 	fmt.Println("Error validating JWT:", err)
	// } else {
	// 	fmt.Println("JWT Validation Result:", isValid)
	// }

	// //8. Check the JWT token claims
	// expectPubkey := attestation.CallOpensslGetPubkey(serverCredDir + "/server.crt")
	// expectPubkey = attestation.ExtractPubkeyFromPem(expectPubkey)
	// expectUserData := attestation.CalExptUserData(serverCredDir + "/server.crt")
	// checkTee, checkPubkey, checkNonce, checkUserData, err := attestation.ExtractAndCheckJWTCliams(serverJwtResult, expectPubkey, nonceClient, expectUserData)
	// verificationResult := "Failed"
	// if err != nil {
	// 	fmt.Println("Error checking JWT claims:", err)
	// } else {
	// 	if checkNonce && checkPubkey && checkTee && checkUserData {
	// 		fmt.Println("Vlidation of JWT Claims passed")
	// 		verificationResult = "Success"
	// 	} else {
	// 		fmt.Println("Vlidation of JWT Claims failed")
	// 	}
	// }
	// attestation.SendMessage(conn, verificationResult)
	result := attestation.ReceiveMessage(conn)
	if result == "Success" {
		fmt.Println("Server validation passed")
	} else {
		fmt.Println("Server validation failed")
	}
}
