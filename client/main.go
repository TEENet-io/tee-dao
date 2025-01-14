package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"tee-dao/attestation"
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

	// Remote Attestation with the server
	remoteAttestationWithServer()

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
	fmt.Printf("Signature: %x\n", getSignatureReply.GetSignature())
}

/* configuration const */
const (
	address       = "20.189.73.225:8072"
	nonceClient   = "$Q9%*@JW#C%Y"                   // don't need to change
	clientCredDir = "./script/cred/client-cred"      //folder path to read client credentials(certs)
	serverCredDir = "./script/cred/server-cred-recv" //folder path to store server credentials(certs)
	mma_path      = "./script/cred/mma_config.json"  //tdx mma config file
	psh_script    = "./script/cred"
	name          = "client0"
)

func remoteAttestationWithServer() {
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

	//6. receive server JWTResult and print it
	serverJwtResult := attestation.ReceiveMessage(conn)
	fmt.Println("Recv Server JWT Result:", serverJwtResult)

	//7. validate server JWTResult
	isValid, err := attestation.ValidateJWTwithPSH(serverJwtResult)
	if err != nil {
		fmt.Println("Error validating JWT:", err)
	} else {
		fmt.Println("JWT Validation Result:", isValid)
	}

	//8. Check the JWT token claims
	expectPubkey := attestation.CallOpensslGetPubkey(serverCredDir + "/server.crt")
	expectPubkey = attestation.ExtractPubkeyFromPem(expectPubkey)
	expectUserData := attestation.CalExptUserData(serverCredDir + "/server.crt")
	checkTee, checkPubkey, checkNonce, checkUserData, err := attestation.ExtractAndCheckJWTCliams(serverJwtResult, expectPubkey, nonceClient, expectUserData)
	verificationResult := "Failed"
	if err != nil {
		fmt.Println("Error checking JWT claims:", err)
	} else {
		if checkNonce && checkPubkey && checkTee && checkUserData {
			fmt.Println("Vlidation of JWT Claims passed")
			verificationResult = "Success"
		} else {
			fmt.Println("Vlidation of JWT Claims failed")
		}
	}
	attestation.SendMessage(conn, verificationResult)
	result := attestation.ReceiveMessage(conn)
	if result == "Success" {
		fmt.Println("Server validation passed")
	} else {
		fmt.Println("Server validation failed")
	}
}
