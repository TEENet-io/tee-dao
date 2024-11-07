package comm

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func setup(t *testing.T, ports []string, handleMessageFuncs []func([]byte)) []*Communicator {
	dir, err := os.Getwd()
	assert.NoError(t, err)
	dir = filepath.Join(dir, "../config/data")

	cfgs := prepareTest(dir, ports)

	cs := []*Communicator{}
	for i, cfg := range cfgs {
		c, err := NewCommunicator(cfg, handleMessageFuncs[i])
		assert.NoError(t, err)
		cs = append(cs, c)
	}

	return cs
}

func TestConnectionEstablishment(t *testing.T) {
	ports := []string{"8444", "8445", "8446"}
	funcs := []func([]byte){}
	for i := 0; i < len(ports); i++ {
		funcs = append(funcs, func(d []byte) {
			fmt.Printf("PRINT node=node%d msg: %s\n", i+1, string(d))
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
	funcs := []func([]byte){}
	for i := 0; i < len(ports); i++ {
		funcs = append(funcs, func(d []byte) {
			fmt.Printf("PRINT node=node%d msg: %s\n", i+1, string(d))
		})
	}

	cs := setup(t, ports, funcs)

	for _, c := range cs {
		c.Start()
	}

	time.Sleep(1 * time.Second)

	for _, c := range cs {
		msg := fmt.Sprintf("P2P message from %s", c.SelfName())
		for _, name := range c.PeerNames() {
			peer := c.GetPeer(name)
			if peer != nil {
				err := peer.Write([]byte(msg))
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
	funcs := []func([]byte){}
	for i := 0; i < len(ports); i++ {
		funcs = append(funcs, func(d []byte) {
			fmt.Printf("PRINT node=node%d msg: %s\n", i+1, string(d))
		})
	}

	cs := setup(t, ports, funcs)

	for _, c := range cs {
		c.Start()
	}

	time.Sleep(1 * time.Second)

	for _, c := range cs {
		msg := fmt.Sprintf("Broadcast message from %s", c.SelfName())
		err := c.Broadcast([]byte(msg))
		assert.NoError(t, err)
	}

	time.Sleep(1 * time.Second)

	for _, c := range cs {
		c.Close()
	}
}
