package comm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestServerWhenClientCloseConn(t *testing.T) {
	dir, err := os.Getwd()
	assert.NoError(t, err)
	dir = filepath.Join(dir, "../config/data")

	cfgs := prepareTest(dir, []string{"8444", "8445", "8446"})

	srv := cfgs[0]
	dialers := cfgs[1:]

	server := NewServer(context.Background(), srv, handleConn1)
	go server.ListenTLS()

	time.Sleep(1 * time.Second)

	wg := sync.WaitGroup{}
	for _, dialer := range dialers {
		dial(
			context.Background(),
			dialer.Cert, dialer.Key, srv.CACert, srv.Address,
			handleConn2, &wg,
		)
	}

	wg.Wait()
	server.Close()
}

func TestServerWhenServerCloseConn(t *testing.T) {
	dir, err := os.Getwd()
	assert.NoError(t, err)
	dir = filepath.Join(dir, "../config/data")

	cfgs := prepareTest(dir, []string{"8444", "8445", "8446"})

	srv := cfgs[0]
	dialers := cfgs[1:]

	server := NewServer(context.Background(), srv, handleConn2)
	go server.ListenTLS()

	time.Sleep(1 * time.Second)

	wg := sync.WaitGroup{}
	for _, dialer := range dialers {
		dial(
			context.Background(),
			dialer.Cert, dialer.Key, srv.CACert, srv.Address,
			handleConn1, &wg,
		)
	}

	wg.Wait()
	server.Close()
}

func handleConn1(ctx context.Context, conn net.Conn) {
	str := fmt.Sprintf("local=%s, remote=%s", conn.LocalAddr().String(), conn.RemoteAddr().String())

	defer fmt.Printf("Left handleConn: %s\n", str)
	defer conn.Close()

	fmt.Printf("Entered handleConn: %s\n", str)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// conn.SetDeadline(time.Now().Add(1 * time.Second))
			_, err := conn.Write([]byte("ping"))
			if err != nil {
				fmt.Printf("connection closed: %s, err=%v\n", str, err)
				return
			}
		}
	}
}

func handleConn2(ctx context.Context, conn net.Conn) {
	str := fmt.Sprintf("local=%s, remote=%s", conn.LocalAddr().String(), conn.RemoteAddr().String())

	defer fmt.Printf("Left handleConn: %s\n", str)
	defer conn.Close()

	fmt.Printf("Entered handleConn: %s\n", str)

	ticker1 := time.NewTicker(1 * time.Second)
	ticker2 := time.NewTicker(5 * time.Second)
	defer ticker1.Stop()
	defer ticker2.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker2.C:
			return
		case <-ticker1.C:
			// conn.SetDeadline(time.Now().Add(1 * time.Second))
			_, err := conn.Write([]byte("ping"))
			if err != nil {
				fmt.Printf("connection closed: %s, err=%v\n", str, err)
				return
			}
		}
	}
}

func dial(
	ctx context.Context,
	certFile, keyFile, caCertFile, srvAddr string,
	handConn func(context.Context, net.Conn),
	wg *sync.WaitGroup,
) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		fmt.Printf("DIAL: Failed to load client certificate: err=%v\n", err)
		return
	}

	CACert, err := os.ReadFile(caCertFile)
	if err != nil {
		fmt.Printf("DIAL: Failed to read CA certificate: err=%v\n", err)
		return
	}

	CACertPool := x509.NewCertPool()
	CACertPool.AppendCertsFromPEM(CACert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      CACertPool,
	}

	// dialer := &net.Dialer{
	// 	Timeout: 5 * time.Second,
	// }

	// conn, err := tls.DialWithDialer(dialer, "tcp", srvAddr, tlsConfig)
	// if err != nil {
	// 	if conn != nil {
	// 		conn.Close()
	// 	}
	// 	fmt.Printf("DIAL: Failed to connect to server: err=%v\n", err)
	// 	return
	// }

	conn, err := tls.Dial("tcp", srvAddr, tlsConfig)
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		fmt.Printf("DIAL: Failed to connect to server: err=%v\n", err)
		return
	}

	fmt.Printf("DIAL: Connected to server: local=%s\n", conn.LocalAddr().String())

	wg.Add(1)
	go func() {
		defer wg.Done()
		handConn(ctx, conn)
	}()
}
