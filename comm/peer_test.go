package comm

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	MsgTypeCustom MessageType = 0x03
)

func TestPeer(t *testing.T) {
	dir, err := os.Getwd()
	assert.NoError(t, err)
	dir = filepath.Join(dir, "../config/data")

	cfgs := prepareTest(dir, []string{"8444", "8445"})
	srvCfg := cfgs[0]
	clientCfg := cfgs[1]

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	msgCh := make(chan []byte, MsgChanSize)

	RegisterMessageType(MsgTypeCustom, "Custom")
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()

		for {
			select {
			case <-ctx.Done():
				return
			case data := <-msgCh:
				myMsg := &Message{}

				err := myMsg.Deserialize(data)
				if err != nil {
					fmt.Printf("PRINT msg: %s, err: %s\n", string(data), err.Error())
				} else {
					fmt.Printf("PRINT msg: %s\n", myMsg.String())
				}
			}
		}
	}()

	srvHandleConn := func(ctx context.Context, conn net.Conn) {
		nonce := rand.Uint32()
		peer := NewPeer(ctx, clientCfg.Name, nonce, conn, msgCh)
		defer peer.Close()

		wg1 := sync.WaitGroup{}
		wg1.Add(1)
		go func() {
			defer wg1.Done()
			peer.Listen()
		}()

		time.Sleep(1 * time.Second)

		if err := peer.Ping(); err != nil {
			fmt.Printf("srvHandleConn: ping err: %v\n", err)
		}

		msg := &Message{
			MsgType:  MsgTypeCustom,
			From:     conn.LocalAddr().String(),
			To:       conn.RemoteAddr().String(),
			Data:     []byte("1000"),
			CreateAt: time.Now(),
		}
		data, _ := msg.Serialize()

		if err := peer.Write(data); err != nil {
			fmt.Printf("srvHandleConn: send msg err: %v\n", err)
		}

		wg1.Wait()
	}

	srv := NewServer(ctx, srvCfg, srvHandleConn)
	go srv.ListenTLS()

	time.Sleep(1 * time.Second)

	clientHandleConn := func(ctx context.Context, conn net.Conn) {
		nonce := rand.Uint32()
		peer := NewPeer(ctx, srvCfg.Name, nonce, conn, msgCh)
		defer peer.Close()

		wg2 := sync.WaitGroup{}

		wg2.Add(1)
		go func() {
			defer wg2.Done()
			peer.Listen()
		}()

		time.Sleep(1 * time.Second)

		if err := peer.Ping(); err != nil {
			fmt.Printf("clientHandleConn: ping err: %v\n", err)
		}

		msg := &Message{
			MsgType:  MsgTypeCustom,
			From:     conn.LocalAddr().String(),
			To:       conn.RemoteAddr().String(),
			Data:     []byte("1"),
			CreateAt: time.Now(),
		}
		data, _ := msg.Serialize()
		if err := peer.Write(data); err != nil {
			fmt.Printf("clientHandleConn: send msg err: %v\n", err)
		}

		wg2.Wait()
	}

	dial(
		ctx,
		clientCfg.Cert, clientCfg.Key, srvCfg.CaCert, srvCfg.Address,
		clientHandleConn, &wg,
	)

	time.Sleep(5 * time.Second)

	cancel()

	wg.Wait()
	srv.Close()
}
