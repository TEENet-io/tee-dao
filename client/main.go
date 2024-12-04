package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"context"
	"log"
	"flag"
	"fmt"
	"io/ioutil"
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

	// IP address, in the form of host:port
	Address string

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

func LoadClientConfig(filePath string) (*MyConfig, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open client config file: %v", err)
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read client config file: %v", err)
	}

	var clientConfig MyConfig
	err = json.Unmarshal(data, &clientConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse client config JSON: %v", err)
	}

	return &clientConfig, nil
}

func main() {
	uid := flag.Int("uid", 0, "ID of the client")
	flag.Parse()

	// Load the client configuration
	clientConfig, err := LoadClientConfig(fmt.Sprintf("config/config_client%d.json", *uid))
	if err != nil {
		fmt.Printf("Error loading client config: %v", err)
		return
	}

	// Load client certificate and key
	cert, err := tls.LoadX509KeyPair(clientConfig.Cert, clientConfig.Key)
	if err != nil {
		fmt.Printf("failed to load client certificate and key: %v", err)
		return
	}

	// Load CA certificate
	caCertPool := x509.NewCertPool()
	log.Printf("Loading CA cert: %s", clientConfig.ServerCACert)
	caCert, err := os.ReadFile(clientConfig.ServerCACert)
	if err != nil {
		fmt.Printf("Failed to read CA certificate. err: %v", err)
		return
	}
	caCertPool.AppendCertsFromPEM(caCert)

	// Create a TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	// Connect to the RPC server with TLS
	conn, err := grpc.Dial(clientConfig.ServerAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		fmt.Printf("Error connecting to RPC server: %v", err)
		return
	}
	defer conn.Close()

	// Create an RPC client
	client := pb.NewSignatureClient(conn)

	// Prepare and make the GetPubKey RPC call
	getPubKeyRequest := &pb.GetPubKeyRequest{UserID: int32(clientConfig.UserID)}
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
	fmt.Printf("Signature: %x\n", getSignatureReply.GetSignature())
}
