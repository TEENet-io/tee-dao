package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	pb "tee-dao/rpc"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type MyConfig struct {
	// user id in multisig
	UserID int

	// name given to the user
	Name string

	// path to the TLS certificate and key used to run a TLS client
	Cert string
	Key  string

	// path to the CA certificate used to authenticate the user during TLS handshake
	CaCert string

	// IP address of the remote RPC server, in the form of host:port
	ServerAddress string

	// path to the CA certificate used to authenticate the remote RPC server during TLS handshake
	ServerCACert string
}

func loadConfig(configPath string) (*MyConfig, error) {
	file, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &MyConfig{}
	decoder := json.NewDecoder(file)
	err = decoder.Decode(config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

func createTLSConfig(certFile, keyFile, serverCaCertFile string) (*tls.Config, error) {
	// Load client certificate and key
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fmt.Printf("failed to load client certificate and key: %v", err)
		return nil, err
	}

	// Load CA certificate
	caCertPool := x509.NewCertPool()
	log.Printf("Loading CA cert: %s", serverCaCertFile)
	caCert, err := os.ReadFile(serverCaCertFile)
	if err != nil {
		fmt.Printf("Failed to read CA certificate. err: %v", err)
		return nil, err
	}
	caCertPool.AppendCertsFromPEM(caCert)

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}, nil
}

func main() {
	uid := flag.Int("uid", 0, "ID of the client")
	flag.Parse()

	// Load the client configuration
	clientConfig, err := loadConfig(fmt.Sprintf("config/config_client%d.json", *uid))
	if err != nil {
		fmt.Printf("Error loading client config: %v", err)
		return
	}

	// Create a TLS configuration for the client
	tlsConfig, err := createTLSConfig(clientConfig.Cert, clientConfig.Key, clientConfig.ServerCACert)
	if err != nil {
		fmt.Printf("Error creating TLS config: %v", err)
		return
	}

	// Connect to the RPC server with TLS
	conn, err := grpc.NewClient(clientConfig.ServerAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		fmt.Printf("Error connecting to RPC server: %v", err)
		return
	}
	defer conn.Close()

	// Create an RPC client
	client := pb.NewSignatureClient(conn)

	// Prepare and make the GetPubKey RPC call
	getPubKeyRequest := &pb.GetPubKeyRequest{UserID: int32(clientConfig.UserID), UserName: clientConfig.Name}
	getPubKeyReply, err := client.GetPubKey(context.Background(), getPubKeyRequest)
	if err != nil {
		log.Fatalf("Error calling GetPubKey: %v", err)
	}

	// Output the group public key
	fmt.Printf("Success: %v\n", getPubKeyReply.GetSuccess())
	fmt.Printf("Group Public Key: %x\n", getPubKeyReply.GetGroupPublicKey())

	getSignatureRequest := &pb.GetSignatureRequest{Msg: []byte("hello1")}
	getSignatureReply, err := client.GetSignature(context.Background(), getSignatureRequest)
	if err != nil {
		log.Fatalf("Error calling GetSignature: %v", err)
	}

	// Output the signature
	fmt.Printf("Success: %v\n", getSignatureReply.GetSuccess())
	fmt.Printf("MsgHash: %x\n", getSignatureReply.GetMsgHash())
	fmt.Printf("Signature: %x\n", getSignatureReply.GetSignature())
}
