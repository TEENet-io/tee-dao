package frost_dkg_multisig

import (
	"bytes"
	"tee-dao/comm"
	"testing"
	"time"
)

func TestMessage_Serialization(t *testing.T) {
	msg := comm.Message{
		MsgType:  DKGSecretShare,
		Data:     []byte("test data"),
		From:     "Node1",
		To:       "Node2",
		CreateAt: time.Now(),
	}

	// Test serialization
	serialized, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize MultiSigMessage: %v", err)
	}

	// Test deserialization
	var deserializedMsg comm.Message
	err = deserializedMsg.Deserialize(serialized)
	if err != nil {
		t.Fatalf("Failed to deserialize MultiSigMessage: %v", err)
	}

	// Compare original and deserialized
	if msg.MsgType != deserializedMsg.MsgType ||
		!bytes.Equal(msg.Data, deserializedMsg.Data) ||
		msg.From != deserializedMsg.From ||
		msg.To != deserializedMsg.To ||
		!msg.CreateAt.Equal(deserializedMsg.CreateAt) {
		t.Fatalf("Deserialized message does not match the original")
	}
}

func TestSecretShareWithCommitment_Serialization(t *testing.T) {
	share := SecretShareWithCommitment{
		SecretShare: Secp256k1FrostKeygenSecretShare{
			GeneratorIndex: 1,
			ReceiverIndex:  2,
			Value:          [32]byte{1, 2, 3},
		},
		Commitments: &Secp256k1FrostVssCommitments{
			Index:                  3,
			NumCoefficients:        2,
			CoefficientCommitments: []Secp256k1FrostVssCommitment{{Data: [64]byte{4, 5, 6}}, {Data: [64]byte{7, 8, 9}}},
			ZkpR:                   [64]byte{10, 11, 12},
			ZkpZ:                   [32]byte{13, 14, 15},
		},
	}

	serialized, err := share.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize SecretShareWithCommitment: %v", err)
	}

	var deserializedShare SecretShareWithCommitment
	err = deserializedShare.Deserialize(serialized)
	if err != nil {
		t.Fatalf("Failed to deserialize SecretShareWithCommitment: %v", err)
	}

	if share.SecretShare != deserializedShare.SecretShare ||
		share.Commitments.Index != deserializedShare.Commitments.Index ||
		share.Commitments.NumCoefficients != deserializedShare.Commitments.NumCoefficients ||
		share.Commitments.CoefficientCommitments[0] != deserializedShare.Commitments.CoefficientCommitments[0] ||
		share.Commitments.CoefficientCommitments[1] != deserializedShare.Commitments.CoefficientCommitments[1] ||
		share.Commitments.ZkpR != deserializedShare.Commitments.ZkpR ||
		share.Commitments.ZkpZ != deserializedShare.Commitments.ZkpZ {
		t.Fatalf("Deserialized share does not match original")
	}
}

func TestDKGComplete_Serialization(t *testing.T) {
	dkgComplete := DKGComplete{
		Complete:  true,
		PublicKey: Secp256k1FrostPubkey{Index: 1, PublicKey: [64]byte{10, 11, 12}},
	}

	serialized, err := dkgComplete.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize DKGComplete: %v", err)
	}

	var deserializedDKGComplete DKGComplete
	err = deserializedDKGComplete.Deserialize(serialized)
	if err != nil {
		t.Fatalf("Failed to deserialize DKGComplete: %v", err)
	}

	if dkgComplete.Complete != deserializedDKGComplete.Complete ||
		dkgComplete.PublicKey != deserializedDKGComplete.PublicKey {
		t.Fatalf("Deserialized DKGComplete does not match original")
	}
}

func TestNonceCommitment_Serialization(t *testing.T) {
	nonceCommitment := NonceCommitment{
		Sequence: 1,
		NonceCommitment: Secp256k1FrostNonceCommitment{
			Index:   1,
			Hiding:  [64]byte{1, 2, 3},
			Binding: [64]byte{4, 5, 6},
		},
	}

	serialized, err := nonceCommitment.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize NonceCommitment: %v", err)
	}

	var deserializedNonceCommitment NonceCommitment
	err = deserializedNonceCommitment.Deserialize(serialized)
	if err != nil {
		t.Fatalf("Failed to deserialize NonceCommitment: %v", err)
	}

	if nonceCommitment.Sequence != deserializedNonceCommitment.Sequence ||
		nonceCommitment.NonceCommitment != deserializedNonceCommitment.NonceCommitment {
		t.Fatalf("Deserialized NonceCommitment does not match original")
	}
}

func TestSignMessage_Serialization(t *testing.T) {
	msg := SignMessage{
		Sequence: 123,
		Msg_hash: [32]byte{10, 20, 30, 40},
	}

	serialized, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize SignMessage: %v", err)
	}

	var deserializedMsg SignMessage
	err = deserializedMsg.Deserialize(serialized)
	if err != nil {
		t.Fatalf("Failed to deserialize SignMessage: %v", err)
	}

	if msg.Sequence != deserializedMsg.Sequence || msg.Msg_hash != deserializedMsg.Msg_hash {
		t.Fatalf("Deserialized SignMessage does not match original")
	}
}

func TestSignatureShare_Serialization(t *testing.T) {
	signatureShare := SignatureShare{
		Sequence:       2,
		Msg_hash:       [32]byte{1, 1, 1},
		SignatureShare: Secp256k1FrostSignatureShare{Index: 1, Response: [32]byte{2, 2, 2}},
	}

	serialized, err := signatureShare.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize SignatureShare: %v", err)
	}

	var deserializedSignatureShare SignatureShare
	err = deserializedSignatureShare.Deserialize(serialized)
	if err != nil {
		t.Fatalf("Failed to deserialize SignatureShare: %v", err)
	}

	if signatureShare.Sequence != deserializedSignatureShare.Sequence ||
		signatureShare.Msg_hash != deserializedSignatureShare.Msg_hash ||
		signatureShare.SignatureShare != deserializedSignatureShare.SignatureShare {
		t.Fatalf("Deserialized SignatureShare does not match original")
	}
}

func TestStringMethods(t *testing.T) {
	msg := comm.Message{
		MsgType:  DKGSecretShare,
		Data:     []byte("test data"),
		From:     "Node1",
		To:       "Node2",
		CreateAt: time.Now(),
	}
	expected := "type=DKGSectretShare, from=Node1, to=Node2, createdAt="
	if msg.String()[:len(expected)] != expected {
		t.Fatalf("String() output did not contain expected substring: %v", msg.String())
	}
}
