package comm

import (
	"sync"
	// pb "tee-dao/rpc"
)

const (
	MsgTypeSetUp uint32 = 0x01
	MsgTypePing  uint32 = 0x02
)

var (
	messageTypeNames = map[uint32]string{
		MsgTypeSetUp: "SetUp",
		MsgTypePing:  "Ping",
	}
	messageTypeNamesMu sync.RWMutex
)

func RegisterMessageType(msgType uint32, name string) {
	messageTypeNamesMu.Lock()
	defer messageTypeNamesMu.Unlock()
	messageTypeNames[msgType] = name
}

func msgName(msgType uint32) string {
	messageTypeNamesMu.RLock()
	defer messageTypeNamesMu.RUnlock()
	if name, exists := messageTypeNames[msgType]; exists {
		return name
	}
	return "Unknown"
}