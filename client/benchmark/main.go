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
	"sort"
	"sync"
	pb "tee-dao/rpc"
	"time"

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

func benchmarkServer(client pb.SignatureClient, numRequests int, latencies []time.Duration, startIndex int, wg *sync.WaitGroup) {
	defer wg.Done()

	for i := 0; i < numRequests; i++ {
		start := time.Now()
		_, err := client.GetSignature(context.Background(), &pb.GetSignatureRequest{Msg: []byte("test message")})
		latency := time.Since(start)

		latencies[startIndex+i] = latency

		if err != nil {
			log.Printf("Error getting signature: %v", err)
		}
	}
}

func main() {
	uid := flag.Int("uid", 0, "ID of the client")
	numClients := flag.Int("clients", 10, "Number of concurrent clients")
	numRequests := flag.Int("requests", 100, "Number of requests per client")
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

	var wg sync.WaitGroup
	latencies := make([]time.Duration, *numClients**numRequests)

	startTime := time.Now()

	for i := 0; i < *numClients; i++ {
		wg.Add(1)
		go benchmarkServer(client, *numRequests, latencies, i**numRequests, &wg)
	}

	wg.Wait()

	endTime := time.Now()
	totalTime := endTime.Sub(startTime)

	var totalLatency time.Duration
	for _, latency := range latencies {
		totalLatency += latency
	}

	// calculate the average latency and throughput
	averageLatency := totalLatency / time.Duration(len(latencies))
	throughput := float64(len(latencies)) / totalTime.Seconds()

	// calculate the average latency without the 10% outliers
	// Sort latencies to remove outliers
	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})

	// Remove the top 5% and bottom 5% of latencies
	startIndex := len(latencies) / 20
	endIndex := len(latencies) - startIndex
	latenciesWithoutOutliers := latencies[startIndex:endIndex]

	var totalLatencyWithoutOutliers time.Duration
	for _, latency := range latenciesWithoutOutliers {
		totalLatencyWithoutOutliers += latency
	}

	averageLatencyWithoutOutliers := totalLatencyWithoutOutliers / time.Duration(len(latenciesWithoutOutliers))

	fmt.Printf("Total requests: %d\n", len(latencies))
	fmt.Printf("Average latency: %v\n", averageLatency)
	fmt.Printf("Average latency(-10): %v\n", averageLatencyWithoutOutliers)
	fmt.Printf("Throughput: %.2f requests/second\n", throughput)
}
