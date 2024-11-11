package frost_dkg_multisig

/*
#cgo LDFLAGS: -Wl,-rpath=${SRCDIR}/../secp256k1-frost/build/src -L${SRCDIR}/../secp256k1-frost/build/src -lsecp256k1
#cgo LDFLAGS: -Wl,-rpath=${SRCDIR}/../secp256k1-frost/build/examples -L${SRCDIR}/../secp256k1-frost/build/examples -lfrost_dkg_link
#include "frost_dkg_link.h"
*/
import "C"
import (
	"unsafe"
)

// Wrappers for the C functions
func KeygenDKGBegin(dkgCommitment **Secp256k1FrostVssCommitments, shares []Secp256k1FrostKeygenSecretShare, numParticipants uint32, threshold uint32, generatorIndex uint32, context []byte) int {
	cContext := (*C.uchar)(unsafe.Pointer(&context[0]))
	result := C.keygen_dkg_begin((**C.secp256k1_frost_vss_commitments)(unsafe.Pointer(dkgCommitment)),
		(*C.secp256k1_frost_keygen_secret_share)(unsafe.Pointer(&shares[0])),
		C.uint32_t(numParticipants), C.uint32_t(threshold), C.uint32_t(generatorIndex), cContext, C.uint32_t(len(context)))
	return int(result)
}

func KeygenDKGCommitmentValidate(peerCommitment **Secp256k1FrostVssCommitments, context []byte) int {
	cContext := (*C.uchar)(unsafe.Pointer(&context[0]))
	result := C.keygen_dkg_commitment_validate((**C.secp256k1_frost_vss_commitments)(unsafe.Pointer(peerCommitment)), cContext, C.uint32_t(len(context)))
	return int(result)
}

func KeygenDKGFinalize(keypair *Secp256k1FrostKeypair, index uint32, numParticipants uint32, shares []Secp256k1FrostKeygenSecretShare, commitments []*Secp256k1FrostVssCommitments) int {
	result := C.keygen_dkg_finalize((*C.secp256k1_frost_keypair)(unsafe.Pointer(keypair)),
		C.uint32_t(index), C.uint32_t(numParticipants),
		(*C.secp256k1_frost_keygen_secret_share)(unsafe.Pointer(&shares[0])),
		(**C.secp256k1_frost_vss_commitments)(unsafe.Pointer(&commitments[0])))
	return int(result)
}

func PubkeyFromKeypair(pubkey *Secp256k1FrostPubkey, keypair *Secp256k1FrostKeypair) int {
	result := C.pubkey_from_keypair((*C.secp256k1_frost_pubkey)(unsafe.Pointer(pubkey)), (*C.secp256k1_frost_keypair)(unsafe.Pointer(keypair)))
	return int(result)
}

func CreateNonce(nonce **Secp256k1FrostNonce, keypair *Secp256k1FrostKeypair) int {
	result := C.create_nonce((**C.secp256k1_frost_nonce)(unsafe.Pointer(nonce)), (*C.secp256k1_frost_keypair)(unsafe.Pointer(keypair)))
	return int(result)
}

func TaggedSha256(msg_hash *[32]byte, tag []byte, msg []byte) int {
	cMsgHash := (*C.uchar)(unsafe.Pointer(&msg_hash[0]))
	cTag := (*C.uchar)(unsafe.Pointer(&tag[0]))
	cMsg := (*C.uchar)(unsafe.Pointer(&msg[0]))
	result := C.tagged_sha256(cMsgHash, cTag, C.uint32_t(len(tag)), cMsg, C.uint32_t(len(msg)))
	return int(result)
}

func Sign(signatureShare *Secp256k1FrostSignatureShare, msg_hash []byte, numSigners uint32, keypair *Secp256k1FrostKeypair, nonce *Secp256k1FrostNonce, signingCommitments []Secp256k1FrostNonceCommitment) int {
	cMsg := (*C.uchar)(unsafe.Pointer(&msg_hash[0]))
	result := C.sign((*C.secp256k1_frost_signature_share)(unsafe.Pointer(signatureShare)), cMsg, C.uint32_t(numSigners), (*C.secp256k1_frost_keypair)(unsafe.Pointer(keypair)),
		(*C.secp256k1_frost_nonce)(unsafe.Pointer(nonce)), (*C.secp256k1_frost_nonce_commitment)(unsafe.Pointer(&signingCommitments[0])))
	return int(result)
}

func Aggregate(sig64 []byte, msg32 []byte, keypair *Secp256k1FrostKeypair, publicKeys []Secp256k1FrostPubkey, commitments []Secp256k1FrostNonceCommitment, signatureShares []Secp256k1FrostSignatureShare, numSigners uint32) int {
	cSig64 := (*C.uchar)(unsafe.Pointer(&sig64[0]))
	cMsg32 := (*C.uchar)(unsafe.Pointer(&msg32[0]))
	result := C.aggregate(cSig64, cMsg32, (*C.secp256k1_frost_keypair)(unsafe.Pointer(keypair)), (*C.secp256k1_frost_pubkey)(unsafe.Pointer(&publicKeys[0])),
		(*C.secp256k1_frost_nonce_commitment)(unsafe.Pointer(&commitments[0])), (*C.secp256k1_frost_signature_share)(unsafe.Pointer(&signatureShares[0])), C.uint32_t(numSigners))
	return int(result)
}

func Verify(sig64 []byte, msg32 []byte, publicKeys *Secp256k1FrostPubkey) int {
	cSig64 := (*C.uchar)(unsafe.Pointer(&sig64[0]))
	cMsg32 := (*C.uchar)(unsafe.Pointer(&msg32[0]))
	result := C.verify(cSig64, cMsg32, (*C.secp256k1_frost_pubkey)(unsafe.Pointer(publicKeys)))
	return int(result)
}

// PerformDKGMultisig calls the C function perform_dkg_multisig
func PerformDKGMultisig() {
	C.perform_dkg_multisig()
}

func PerformDKGMultisigWithInterface() {
	C.perform_dkg_multisig_with_interface()
}
