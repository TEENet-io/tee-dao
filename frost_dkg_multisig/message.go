package frost_dkg_multisig

import (
	"bytes"
	"distributed-multisig/comm"
	"encoding/gob"
	"fmt"
)

const (
	DKGSecretShare          comm.MessageType = 0x05
	ReadyForPreprocessing   comm.MessageType = 0x06
	NonceCommitmentExchange comm.MessageType = 0x07
	PreprocessingRequest    comm.MessageType = 0x08
	ReadyForSign            comm.MessageType = 0x09
	SignRequest             comm.MessageType = 0x0a
	SignatureShareResponse  comm.MessageType = 0x0b
)

func msgType(t comm.MessageType) string {
	switch t {
	case DKGSecretShare:
		return "DKGSecretShare"
	case ReadyForPreprocessing:
		return "ReadyForPreprocessing"
	case PreprocessingRequest:
		return "PreprocessingRequest"
	case NonceCommitmentExchange:
		return "NonceCommitmentExchange"
	case ReadyForSign:
		return "ReadyForSign"
	case SignRequest:
		return "SignRequest"
	case SignatureShareResponse:
		return "SignatureShareResponse"
	default:
		return "Unknown"
	}
}

// SecretShareWithCommitment Struct
type SecretShareWithCommitment struct {
	SecretShare Secp256k1FrostKeygenSecretShare
	Commitment  *Secp256k1FrostVssCommitments
}

func (s *SecretShareWithCommitment) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *SecretShareWithCommitment) Deserialize(data []byte) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(s)
}

func (s *SecretShareWithCommitment) String() string {
	return fmt.Sprintf("SecretShareWithCommitment{SecretShare: %v, Commitment: %v}", s.SecretShare, s.Commitment)
}

// DKGComplete Struct
type DKGComplete struct {
	Complete  bool
	PublicKey Secp256k1FrostPubkey
}

func (d *DKGComplete) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (d *DKGComplete) Deserialize(data []byte) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(d)
}

func (d *DKGComplete) String() string {
	return fmt.Sprintf("DKGComplete{Complete: %v}", d.Complete)
}

// PreprocessingSequence Struct
type PreprocessingSequence struct {
	Sequence int
}

func (p *PreprocessingSequence) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (p *PreprocessingSequence) Deserialize(data []byte) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(p)
}

// NonceCommitment Struct
type NonceCommitment struct {
	Sequence        int
	NonceCommitment Secp256k1FrostNonceCommitment
}

func (n *NonceCommitment) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(n); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (n *NonceCommitment) Deserialize(data []byte) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(n)
}

func (n *NonceCommitment) String() string {
	return fmt.Sprintf("NonceCommitment{Sequence: %d, NonceCommitment: %v}", n.Sequence, n.NonceCommitment)
}

// PreprocessingComplete struct
type PreprocessingComplete struct {
	Sequence int
	Complete bool
}

func (d *PreprocessingComplete) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (d *PreprocessingComplete) Deserialize(data []byte) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(d)
}

// SignMessage Struct
type SignMessage struct {
	Sequence int
	Msg_hash [32]byte
}

func (s *SignMessage) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *SignMessage) Deserialize(data []byte) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(s)
}

func (s *SignMessage) String() string {
	return fmt.Sprintf("SignMessage{Sequence: %d, Msg_hash: %x}", s.Sequence, s.Msg_hash)
}

// SignatureShare Struct
type SignatureShare struct {
	Sequence       int
	Msg_hash       [32]byte
	SignatureShare Secp256k1FrostSignatureShare
}

func (s *SignatureShare) Serialize() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (s *SignatureShare) Deserialize(data []byte) error {
	buf := bytes.NewBuffer(data)
	dec := gob.NewDecoder(buf)
	return dec.Decode(s)
}

func (s *SignatureShare) String() string {
	return fmt.Sprintf("SignatureShare{Sequence: %d, SignatureShare: %v}", s.Sequence, s.SignatureShare)
}
