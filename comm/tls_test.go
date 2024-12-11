package comm

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTLS(t *testing.T) {
	dir, err := os.Getwd()
	assert.NoError(t, err)
	dir = filepath.Join(dir, "../config/data")

	cfgs := prepareTest(dir, []string{"10004", "10005"})

	go startTLSServer(t, cfgs[0].Cert, cfgs[0].Key, cfgs[1].CaCert)

	time.Sleep(1 * time.Second)

	startTLSClient(t, cfgs[1].Cert, cfgs[1].Key, cfgs[0].CaCert)
}

func startTLSClient(t *testing.T, clientCertFile, clientKeyFile, caCertFile string) {
	// Load client certificate and private key
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		t.Fatalf("Failed to load client certificate: %v", err)
	}

	// Load CA certificate to verify the server's certificate
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		t.Fatalf("Failed to read CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Configure TLS settings for the client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert}, // Client's certificate
		RootCAs:      caCertPool,                    // Trusted CA to verify the server
	}

	// Connect to the server on localhost:8443
	conn, err := tls.Dial("tcp", "localhost:8443", tlsConfig)
	if err != nil {
		t.Fatalf("Failed to connect to server: %v", err)
	}
	defer conn.Close()

	t.Log("TLS client: connected to server")

	// Send message to server
	_, err = conn.Write([]byte("Hello from TLS client!"))
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Read response from server
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Print response from server
	t.Logf("TLS client: received '%s'", string(buf[:n]))
}

func startTLSServer(t *testing.T, serverCertFile, serverKeyFile, caCertFile string) {
	// Load server certificate and private key
	cert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		t.Fatalf("Failed to load server certificate: %v", err)
	}

	// Load CA certificate to verify client certificates
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		t.Fatalf("Failed to read CA certificate: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Configure TLS settings
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},        // Server's certificate
		ClientCAs:    caCertPool,                     // CA to verify client certificates
		ClientAuth:   tls.RequireAndVerifyClientCert, // Require client certificate
	}

	// Listen for incoming connections on localhost:8443
	listener, err := tls.Listen("tcp", "localhost:8443", tlsConfig)
	if err != nil {
		t.Fatalf("Failed to start TLS server: %v", err)
	}
	defer listener.Close()

	t.Logf("TLS server started on localhost:8443")

	// Accept one connection for testing
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Failed to accept connection: %v", err)
	}
	defer conn.Close()

	t.Log("TLS server: client connected")

	// Read data from client
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Logf("Failed to read from client: %v", err)
		return
	}

	// Print message received from client
	t.Logf("TLS server: received '%s'", string(buf[:n]))

	// Send response to client
	_, err = conn.Write([]byte("Hello from TLS server!"))
	if err != nil {
		t.Fatalf("Failed to write to client: %v", err)
	}

	t.Log("TLS server: response sent to client")
}
