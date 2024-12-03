package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/rpc"
	"os"
	"tee-dao/frost_dkg_multisig"
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
	fmt.Printf("Loading CA cert: %s", clientConfig.ServerCACert)
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
	client, err := tls.Dial("tcp", clientConfig.ServerAddress, tlsConfig)
	if err != nil {
		fmt.Printf("Error connecting to RPC server: %v", err)
		return
	}
	defer client.Close()

	// Create an RPC client
	rpcClient := rpc.NewClient(client)

	args := frost_dkg_multisig.GetPubKeyArgs{UserID: clientConfig.UserID}
	var pubKeyReply frost_dkg_multisig.PubKeyReply

	// Call the GetPubKey method on the server
	err = rpcClient.Call("SignatureService.GetPubKey", args, &pubKeyReply)
	if err != nil {
		fmt.Printf("Error calling RPC method: %v", err)
		return
	}

	fmt.Printf("Group public key: %v\n", pubKeyReply)

	// Call the Sign method on the server
	signArgs := frost_dkg_multisig.SignArgs{Msg: []byte("hello")}
	var signatureReply frost_dkg_multisig.SignatureReply
	err = rpcClient.Call("SignatureService.Sign", signArgs, &signatureReply)
	if err != nil {
		fmt.Printf("Error calling RPC method: %v", err)
		return
	}

	fmt.Printf("Signature: %v\n", signatureReply)
}
