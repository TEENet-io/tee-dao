package comm

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	TestMsg MessageType = 0x03
)

func setup(t *testing.T, ports []string, handleMessageFuncs []func(Message)) []*Communicator {
	dir, err := os.Getwd()
	assert.NoError(t, err)
	dir = filepath.Join(dir, "../config/data")

	cfgs := prepareTest(dir, ports)

	cs := []*Communicator{}
	for i, cfg := range cfgs {
		c, err := NewCommunicator(cfg)
		c.RegisterHandler("Test", TestMsg, handleMessageFuncs[i])
		assert.NoError(t, err)
		cs = append(cs, c)
	}

	return cs
}

func TestConnectionEstablishment(t *testing.T) {
	ports := []string{"8444", "8445", "8446"}
	funcs := []func(Message){}
	for i := 0; i < len(ports); i++ {
		funcs = append(funcs, func(msg Message) {
			fmt.Printf("PRINT node=node%d msg: %s\n", i+1, string(msg.Data))
		})
	}

	cs := setup(t, ports, funcs)

	for _, c := range cs {
		c.Start()
	}

	N := len(cs) - 1
	for _, c := range cs {
		count := 0
		for _, name := range c.PeerNames() {
			if c.GetPeer(name) != nil {
				count++
			}
		}
		assert.Equal(t, count, N)
	}

	for _, c := range cs {
		c.Close()
	}
}

func TestP2PCommunication(t *testing.T) {
	ports := []string{"8444", "8445", "8446"}
	funcs := []func(Message){}
	for i := 0; i < len(ports); i++ {
		funcs = append(funcs, func(msg Message) {
			fmt.Printf("PRINT node=node%d msg: %s\n", i+1, string(msg.Data))
		})
	}

	cs := setup(t, ports, funcs)

	for _, c := range cs {
		c.Start()
	}

	time.Sleep(1 * time.Second)

	for _, c := range cs {
		data := fmt.Sprintf("P2P message from %s", c.SelfName())
		for _, name := range c.PeerNames() {
			peer := c.GetPeer(name)
			msg := Message{
				MsgType: TestMsg,
				Data:    []byte(data),
				From:    c.cfg.Name,
				To:      name,
			}
			serializedMsg, err := msg.Serialize()
			assert.NoError(t, err)
			if peer != nil {
				err := peer.Write(serializedMsg)
				assert.NoError(t, err)
			}
		}
	}

	time.Sleep(1 * time.Second)

	for _, c := range cs {
		c.Close()
	}
}

func TestBroadcast(t *testing.T) {
	ports := []string{"8444", "8445", "8446"}
	funcs := []func(Message){}
	for i := 0; i < len(ports); i++ {
		funcs = append(funcs, func(msg Message) {
			fmt.Printf("PRINT node=node%d msg: %s\n", i+1, string(msg.Data))
		})
	}

	cs := setup(t, ports, funcs)

	for _, c := range cs {
		c.Start()
	}

	time.Sleep(1 * time.Second)

	for _, c := range cs {
		data := fmt.Sprintf("Broadcast message from %s", c.SelfName())
		msg := Message{
			MsgType: TestMsg,
			Data:    []byte(data),
			From:    c.cfg.Name,
			To:      "all",
		}
		serializedMsg, err := msg.Serialize()
		assert.NoError(t, err)
		err = c.Broadcast(serializedMsg)
		assert.NoError(t, err)
	}

	time.Sleep(1 * time.Second)

	for _, c := range cs {
		c.Close()
	}
}
