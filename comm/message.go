package comm

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"time"
)

type MessageType byte

const (
	MsgTypeSetUp MessageType = 0x01
)

type Message struct {
	MsgType  MessageType
	Data     []byte
	From     string
	To       string
	CreateAt time.Time
}

func (m *Message) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	encoder := gob.NewEncoder(&buf)
	err := encoder.Encode(m)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (m *Message) String() string {
	return fmt.Sprintf("type=%s, from=%s, to=%s, createdAt=%v, data=0x%x", msgType(m.MsgType), m.From, m.To, m.CreateAt.Unix(), m.Data)
}

func (m *Message) Deserialize(data []byte) error {

	buf := bytes.NewBuffer(data)
	decoder := gob.NewDecoder(buf)
	if err := decoder.Decode(m); err != nil {
		return err
	}

	return nil
}

func (m *Message) Type() MessageType {
	return MessageType(m.MsgType)
}
