package attestation

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"tee-dao/logger"
)

/* configuration const */
const (
	address          = "0.0.0.0:8072" //"localhost:8072"
	nonceServer      = "1P6*&%4u#w$M"
	serverCreDir     = "./script/cred/server-cred"      //folder path to read server credentials(certs)
	clientCredDir    = "./script/cred/client-cred-recv" //folder path to store client credentials(certs)
	mma_path         = "./script/mma_config.json"       //tdx mma config file
	psh_script       = "./script"
	program_hashfile = "./script/server_hashOf_test-program"
)

// 定义签名算法映射
var algToSignatureAlgorithm = map[string]x509.SignatureAlgorithm{
	"RS256": x509.SHA256WithRSA,
	"RS384": x509.SHA384WithRSA,
	"RS512": x509.SHA512WithRSA,
	"PS256": x509.SHA256WithRSAPSS,
	"PS384": x509.SHA384WithRSAPSS,
	"PS512": x509.SHA512WithRSAPSS,
}

type JWTToken struct {
	Header    map[string]interface{} `json:"header"`
	Payload   map[string]interface{} `json:"payload"`
	Signature string                 `json:"signature"`
}

type AttestationServer struct {
	ctx context.Context

	name        string
	tcpListener net.Listener

	AttestedServers sync.Map
	AttestedCond    *sync.Cond

	logger *slog.Logger
}

// NewAttestationServer creates a new attestation server instance
func NewAttestationServer(ctx context.Context, name string) *AttestationServer {
	// init logger
	serverLogger := logger.New(slog.LevelInfo).With("attestationServer", name)
	return &AttestationServer{
		ctx:          ctx,
		name:         name,
		AttestedCond: sync.NewCond(&sync.Mutex{}),
		logger:       serverLogger,
	}
}

func (s *AttestationServer) Close() {
	defer s.logger.Info("Closed attestation server")
	if s.tcpListener != nil {
		s.tcpListener.Close()
	}
}

// ListenAttestation listens for attestation requests
func (s *AttestationServer) ListenAttestation() {
	s.logger.Info("Listening for attestation requests")
	//1.server establish socket with client (ip:localhost, port:8072)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		fmt.Println("Error starting server:", err)
		return
	}
	fmt.Println("Server listening on", address)
	s.tcpListener = listener
	for {
		select {
		case <-s.ctx.Done():
			s.logger.Info("Stopped listening for attestation requests")
			return
		default:
			// Accept attestation requests
			conn, err := listener.Accept()
			if err != nil {
				fmt.Println("Error accepting connection:", err)
				continue
			}

			go s.handleClient(conn)
		}
	}
}

func (s *AttestationServer) handleClient(conn net.Conn) bool {
	defer conn.Close()

	//2.server send 3 files: nonce(12-byte length in string format), server-ca.crt, server.crt
	//2.1 Access these file. The directory path of all these files located：./script/cred/server-cred
	//2.2 Sent to the client;
	SendMessage(conn, nonceServer)
	myCACert := serverCreDir + "/" + s.name + "-ca.crt"
	myCert := serverCreDir + "/" + s.name + ".crt"
	SendFile(conn, myCACert)
	SendFile(conn, myCert)

	//3. receive client nonce, client name, client-ca.crt, client.crt; And store them in "./script/cred/client-cred-recv" folder
	clientNonce := ReceiveMessage(conn)
	fmt.Println("Client Nonce:", clientNonce)
	clientName := ReceiveMessage(conn)
	fmt.Println("Client Name:", clientName)
	clientCaCert := clientCredDir + "/" + clientName + "-ca.crt"
	clientCert := clientCredDir + "/" + clientName + ".crt"
	ReceiveFile(conn, clientCaCert)
	ReceiveFile(conn, clientCert)

	// TTP does not need to be attested
	if s.name != "coordinator" {
		//4. call the system tool and obtain the return result, stored in JWTResult;
		//4.1 Command to call the "AttestationClient": sudo AttestationClient -n "nonce" -o token
		extractPubkey := CallOpensslGetPubkey(myCert)
		fmt.Print("Extracted pubkey test1:", extractPubkey)
		extractPubkey = ExtractPubkeyFromPem(extractPubkey)

		machineName, err := os.Hostname()
		fmt.Println("Machine Name:", machineName)
		jwtResult := ""
		if err != nil {
			fmt.Println("Error getting machine name:", err)
			return false
		}
		if strings.Contains(strings.ToUpper(machineName), "SNP") {
			fmt.Println("callSNPAttestationClient")
			jwtResult = CallSNPAttestationClient(clientNonce + extractPubkey)

		} else if strings.Contains(strings.ToUpper(machineName), "TDX") {
			fmt.Println("callTDXAttestationClient")
			jwtResult = CallTDXAttestationClient(clientNonce+extractPubkey, mma_path)
		} else {
			fmt.Println("Unsupported machine type")
			return false
		}

		//5. server send JWTResult to client
		fmt.Println("Send self JWT Result:", jwtResult)
		SendMessage(conn, jwtResult)
	}

	//6. receive client JWTResult and print it
	clientJwtResult := ReceiveMessage(conn)
	fmt.Println("Recv Client JWT Result:", clientJwtResult)

	//7. validate client JWTResult
	isValid, err := ValidateJWTwithPSH(clientJwtResult)
	if err != nil {
		fmt.Println("Error validating JWT:", err)
	} else {
		fmt.Println("JWT Validation Result:", isValid)
	}

	//8. Check the JWT token claims
	expectPubkey := CallOpensslGetPubkey(clientCert)
	expectPubkey = ExtractPubkeyFromPem(expectPubkey)
	expectUserData := CalExptUserData(clientCert, program_hashfile)
	checkTee, checkPubkey, checkNonce, checkUserData, err := ExtractAndCheckJWTCliams(clientJwtResult, expectPubkey, nonceServer, expectUserData) //client check Server's JWT claims,should be the clientNonce
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
	SendMessage(conn, verificationResult)
	s.AttestedServers.Store(clientName, verificationResult)
	s.AttestedCond.Broadcast()
	return true
}
