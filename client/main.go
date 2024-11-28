package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"log/slog"
	"net/rpc"
	"os"
	"tee-dao/comm"
	"tee-dao/frost_dkg_multisig"
	"tee-dao/utils"
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
	CACert string
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
	// Load general configuration
	leader, _, _, participants, _, err := utils.LoadGeneralConfig("config/config.json")
	if err != nil {
		log.Fatalf("Error loading general config: %v", err)
		return
	}

	// Load the client configuration
	clientConfig, err := LoadClientConfig(fmt.Sprintf("config/client_config%d.json", *uid))
	if err != nil {
		log.Fatalf("Error loading client config: %v", err)
		return
	}

	// Load client certificate and key
	cert, err := tls.LoadX509KeyPair(clientConfig.Cert, clientConfig.Key)
	if err != nil {
		log.Fatalf("failed to load client certificate and key: %v", err)
	}

	// Find the leader's configuration
	var leaderConfig comm.PeerConfig
	for _, participant := range participants {
		if participant.Name == leader {
			leaderConfig = participant
		}
	}
	// Load CA certificate
	caCertPool := x509.NewCertPool()
	log.Printf("Loading CA cert", slog.String("ca", leaderConfig.CACert))
	caCert, err := os.ReadFile(leaderConfig.CACert)
	if err != nil {
		log.Fatalf("Failed to read CA certifcate", slog.String("err", err.Error()))
		return
	}
	caCertPool.AppendCertsFromPEM(caCert)

	// Create a TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caCertPool,
	}

	// Connect to the RPC server with TLS
	client, err := tls.Dial("tcp", leaderConfig.RPCAddress, tlsConfig)
	if err != nil {
		log.Fatalf("Error connecting to RPC server: %v", err)
	}
	defer client.Close()

	// Create an RPC client
	rpcClient := rpc.NewClient(client)

	args := frost_dkg_multisig.GetPubKeyArgs{UserID: clientConfig.UserID}
	var pubKeyReply frost_dkg_multisig.PubKeyReply

	// Call the GetPubKey method on the server
	err = rpcClient.Call("SignatureService.GetPubKey", args, &pubKeyReply)
	if err != nil {
		log.Fatalf("Error calling RPC method: %v", err)
	}

	fmt.Printf("Group public key: %v\n", pubKeyReply)

	// Call the Sign method on the server
	signArgs := frost_dkg_multisig.SignArgs{Msg: []byte("hello")}
	var signatureReply frost_dkg_multisig.SignatureReply
	err = rpcClient.Call("SignatureService.Sign", signArgs, &signatureReply)
	if err != nil {
		log.Fatalf("Error calling RPC method: %v", err)
	}

	fmt.Printf("Signature: %v\n", signatureReply)
}
