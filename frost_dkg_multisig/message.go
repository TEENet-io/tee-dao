package frost_dkg_multisig

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

const (
	DKGSecretShare          uint32 = 0x05
	ReadyForPreprocessing   uint32 = 0x06
	NonceCommitmentExchange uint32 = 0x07
	PreprocessingRequest    uint32 = 0x08
	ReadyForSign            uint32 = 0x09
	SignRequest             uint32 = 0x0a
	SignatureShareResponse  uint32 = 0x0b
)

// SecretShareWithCommitment Struct
type SecretShareWithCommitment struct {
	SecretShare Secp256k1FrostKeygenSecretShare
	Commitments *Secp256k1FrostVssCommitments
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
	return fmt.Sprintf("SecretShareWithCommitment{SecretShare: %v, Commitments: %v, Coefficient: %+v}", s.SecretShare, s.Commitments, s.Commitments.CoefficientCommitments)
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
	InitiatorSequence InitiatorSequence
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
	InitiatorSequence InitiatorSequence
	NonceCommitment   Secp256k1FrostNonceCommitment
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
	return fmt.Sprintf("NonceCommitment{InitiatorSequence: %v, NonceCommitment: %v}", n.InitiatorSequence, n.NonceCommitment)
}

// PreprocessingComplete struct
type PreprocessingComplete struct {
	InitiatorSequence InitiatorSequence
	Complete          bool
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
	InitiatorSequence InitiatorSequence
	Signers           []int
	Msg_hash          [32]byte
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
	return fmt.Sprintf("SignMessage{InitiatorSequence: %v, Msg_hash: %x}", s.InitiatorSequence, s.Msg_hash)
}

// SignatureShare Struct
type SignatureShare struct {
	InitiatorSequence InitiatorSequence
	Msg_hash          [32]byte
	SignatureShare    Secp256k1FrostSignatureShare
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
	return fmt.Sprintf("SignatureShare{Sequence: %v, SignatureShare: %v}", s.InitiatorSequence, s.SignatureShare)
}
