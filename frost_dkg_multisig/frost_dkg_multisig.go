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

// function implementations
func KeygenDKGBegin(dkgCommitment **Secp256k1FrostVssCommitments, shares []Secp256k1FrostKeygenSecretShare, numParticipants uint32, threshold uint32, generatorIndex uint32, context []byte) int {
	cShares := (*C.secp256k1_frost_keygen_secret_share)(C.malloc(C.size_t(len(shares)) * C.size_t(unsafe.Sizeof(C.secp256k1_frost_keygen_secret_share{}))))
	defer C.free(unsafe.Pointer(cShares))

	cDkgCommitment := (**C.secp256k1_frost_vss_commitments)(C.malloc(C.size_t(unsafe.Sizeof(uintptr(0)))))
	defer C.free(unsafe.Pointer(cDkgCommitment))

	cContext := (*C.uchar)(C.CBytes(context))
	defer C.free(unsafe.Pointer(cContext))

	result := C.keygen_dkg_begin(cDkgCommitment,
		cShares, C.uint32_t(numParticipants), C.uint32_t(threshold), C.uint32_t(generatorIndex), cContext, C.uint32_t(len(context)))
	cShareSlice := (*[1 << 30]C.secp256k1_frost_keygen_secret_share)(unsafe.Pointer(cShares))[:len(shares):len(shares)]
	for i := range shares {
		shares[i].GeneratorIndex = uint32(cShareSlice[i].generator_index)
		shares[i].ReceiverIndex = uint32(cShareSlice[i].receiver_index)
		cValue := (*[32]byte)(unsafe.Pointer(&cShareSlice[i].value))[:]
		copy(shares[i].Value[:], cValue)
	}

	cCommitment := *cDkgCommitment
	goCommitment := *dkgCommitment
	goCommitment.Index = uint32(cCommitment.index)
	goCommitment.NumCoefficients = uint32(cCommitment.num_coefficients)
	// Copy the 'zkp_r' and 'zkp_z' arrays from C to Go
	copy(goCommitment.ZkpR[:], (*[64]byte)(unsafe.Pointer(&cCommitment.zkp_r))[:])
	copy(goCommitment.ZkpZ[:], (*[32]byte)(unsafe.Pointer(&cCommitment.zkp_z))[:])

	// Allocate an array of coefficients in Go, if necessary
	if cCommitment.num_coefficients > 0 {
		// Allocate an array of coefficients in Go
		goCommitment.CoefficientCommitments = make([]Secp256k1FrostVssCommitment, cCommitment.num_coefficients)

		// Create a Go slice from the C pointer
		cCoeffSlice := (*[1 << 30]C.secp256k1_frost_vss_commitment)(unsafe.Pointer(cCommitment.coefficient_commitments))[:cCommitment.num_coefficients:cCommitment.num_coefficients]

		// Copy the coefficient_commitments data from C to Go
		for i := 0; i < int(cCommitment.num_coefficients); i++ {
			copy(goCommitment.CoefficientCommitments[i].Data[:], (*[64]byte)(unsafe.Pointer(&cCoeffSlice[i].data))[:])
		}

	}

	return int(result)
}

func KeygenDKGCommitmentValidate(peerCommitment **Secp256k1FrostVssCommitments, context []byte) int {
	cContext := (*C.uchar)(C.CBytes(context))
	defer C.free(unsafe.Pointer(cContext))

	// Allocate memory for a C commitment
	cCommitment := (*C.secp256k1_frost_vss_commitments)(C.malloc(C.size_t(unsafe.Sizeof(C.secp256k1_frost_vss_commitments{}))))
	defer C.free(unsafe.Pointer(cCommitment))

	commitment := *peerCommitment
	// Explicitly copy fields from the Go commitment struct to the C struct
	cCommitment.index = C.uint32_t(commitment.Index)
	cCommitment.num_coefficients = C.uint32_t(commitment.NumCoefficients)
	goCommitmentsZkpRValue := (*[64]C.uchar)(unsafe.Pointer(&commitment.ZkpR))[:]
	copy(cCommitment.zkp_r[:], goCommitmentsZkpRValue)
	goCommitmentsZkpZValue := (*[32]C.uchar)(unsafe.Pointer(&commitment.ZkpZ))[:]
	copy(cCommitment.zkp_z[:], goCommitmentsZkpZValue)

	// Allocate memory for the coefficient_commitments array in C
	cCommitment.coefficient_commitments = (*C.secp256k1_frost_vss_commitment)(C.malloc(C.size_t(commitment.NumCoefficients) * C.size_t(unsafe.Sizeof(C.secp256k1_frost_vss_commitment{}))))
	defer C.free(unsafe.Pointer(cCommitment.coefficient_commitments))

	// Create a Go slice for the C array
	cCoeffSlice := (*[1 << 30]C.secp256k1_frost_vss_commitment)(unsafe.Pointer(cCommitment.coefficient_commitments))[:commitment.NumCoefficients:commitment.NumCoefficients]

	// Copy each coefficient commitment from Go to C
	for i := 0; i < int(commitment.NumCoefficients); i++ {
		goCoefficientCommitmentsValue := (*[64]C.uchar)(unsafe.Pointer(&commitment.CoefficientCommitments[i].Data))[:]
		copy(cCoeffSlice[i].data[:], goCoefficientCommitmentsValue)
	}

	result := C.keygen_dkg_commitment_validate(&cCommitment, cContext, C.uint32_t(len(context)))
	return int(result)
}

func KeygenDKGFinalize(keypair *Secp256k1FrostKeypair, index uint32, numParticipants uint32, shares []Secp256k1FrostKeygenSecretShare, commitments []*Secp256k1FrostVssCommitments) int {
	// Allocate memory for C keypair
	cKeypair := (*C.secp256k1_frost_keypair)(C.malloc(C.size_t(unsafe.Sizeof(C.secp256k1_frost_keypair{}))))
	defer C.free(unsafe.Pointer(cKeypair))

	// Allocate memory for C shares
	cShares := (*C.secp256k1_frost_keygen_secret_share)(C.malloc(C.size_t(len(shares)) * C.size_t(unsafe.Sizeof(C.secp256k1_frost_keygen_secret_share{}))))
	defer C.free(unsafe.Pointer(cShares))

	// Map Go shares to C memory
	cShareSlice := (*[1 << 30]C.secp256k1_frost_keygen_secret_share)(unsafe.Pointer(cShares))[:len(shares):len(shares)]
	for i, share := range shares {
		cShareSlice[i].generator_index = C.uint32_t(share.GeneratorIndex)
		cShareSlice[i].receiver_index = C.uint32_t(share.ReceiverIndex)
		// copy((*[32]C.uchar)(unsafe.Pointer(&cShareSlice[i].value))[:], share.Value[:])
		goValue := (*[32]C.uchar)(unsafe.Pointer(&share.Value))[:]
		copy(cShareSlice[i].value[:], goValue)
	}

	cCommitments := (**C.secp256k1_frost_vss_commitments)(C.malloc(C.size_t(len(commitments)) * C.size_t(unsafe.Sizeof(uintptr(0)))))
	defer C.free(unsafe.Pointer(cCommitments))
	cCommitmentsSlice := (*[1 << 30]*C.secp256k1_frost_vss_commitments)(unsafe.Pointer(cCommitments))[:len(commitments):len(commitments)]
	for i, commitment := range commitments {
		// Allocate memory for a C commitment
		cCommitment := (*C.secp256k1_frost_vss_commitments)(C.malloc(C.size_t(unsafe.Sizeof(C.secp256k1_frost_vss_commitments{}))))
		defer C.free(unsafe.Pointer(cCommitment))

		// Explicitly copy fields from the Go commitment struct to the C struct
		cCommitment.index = C.uint32_t(commitment.Index)
		cCommitment.num_coefficients = C.uint32_t(commitment.NumCoefficients)
		goCommitmentsZkpRValue := (*[64]C.uchar)(unsafe.Pointer(&commitment.ZkpR))[:]
		copy(cCommitment.zkp_r[:], goCommitmentsZkpRValue)
		goCommitmentsZkpZValue := (*[32]C.uchar)(unsafe.Pointer(&commitment.ZkpZ))[:]
		copy(cCommitment.zkp_z[:], goCommitmentsZkpZValue)

		// Allocate memory for the coefficient_commitments array in C
		cCommitment.coefficient_commitments = (*C.secp256k1_frost_vss_commitment)(C.malloc(C.size_t(commitment.NumCoefficients) * C.size_t(unsafe.Sizeof(C.secp256k1_frost_vss_commitment{}))))
		defer C.free(unsafe.Pointer(cCommitment.coefficient_commitments))

		// Create a Go slice for the C array
		cCoeffSlice := (*[1 << 30]C.secp256k1_frost_vss_commitment)(unsafe.Pointer(cCommitment.coefficient_commitments))[:commitment.NumCoefficients:commitment.NumCoefficients]

		// Copy each coefficient commitment from Go to C
		for j := 0; j < int(commitment.NumCoefficients); j++ {
			goCoefficientCommitmentsValue := (*[64]C.uchar)(unsafe.Pointer(&commitment.CoefficientCommitments[j].Data))[:]
			copy(cCoeffSlice[j].data[:], goCoefficientCommitmentsValue)
		}
		// Now assign the allocated C commitment to the slice
		cCommitmentsSlice[i] = cCommitment
	}

	result := C.keygen_dkg_finalize(cKeypair,
		C.uint32_t(index), C.uint32_t(numParticipants), cShares, cCommitments)

	// Explicitly copy fields from the C keypair struct to the Go struct
	goSecretValue := (*[32]byte)(unsafe.Pointer(&cKeypair.secret))[:]
	copy(keypair.Secret[:], goSecretValue)
	keypair.PublicKeys.Index = uint32(cKeypair.public_keys.index)
	keypair.PublicKeys.MaxParticipants = uint32(cKeypair.public_keys.max_participants)
	goPublicKeyValue := (*[64]byte)(unsafe.Pointer(&cKeypair.public_keys.public_key))[:]
	copy(keypair.PublicKeys.PublicKey[:], goPublicKeyValue)
	goGroupPublicKeyValue := (*[64]byte)(unsafe.Pointer(&cKeypair.public_keys.group_public_key))[:]
	copy(keypair.PublicKeys.GroupPublicKey[:], goGroupPublicKeyValue)

	return int(result)
}

func PubkeyFromKeypair(pubkey *Secp256k1FrostPubkey, keypair *Secp256k1FrostKeypair) int {
	// Allocate memory for C pubkey
	cPubkey := (*C.secp256k1_frost_pubkey)(C.malloc(C.size_t(unsafe.Sizeof(C.secp256k1_frost_pubkey{}))))
	defer C.free(unsafe.Pointer(cPubkey))

	// Allocate memory for C keypair
	cKeypair := (*C.secp256k1_frost_keypair)(C.malloc(C.size_t(unsafe.Sizeof(C.secp256k1_frost_keypair{}))))
	defer C.free(unsafe.Pointer(cKeypair))

	// Explicitly copy fields from the Go pubkey struct to the C struct
	goSecretValue := (*[32]C.uchar)(unsafe.Pointer(&keypair.Secret))[:]
	copy(cKeypair.secret[:], goSecretValue)

	// Explicitly copy fields from the Go pubkey struct to the C struct
	cKeypair.public_keys.index = C.uint32_t(keypair.PublicKeys.Index)
	cKeypair.public_keys.max_participants = C.uint32_t(keypair.PublicKeys.MaxParticipants)
	goPublicKeyValue := (*[64]C.uchar)(unsafe.Pointer(&keypair.PublicKeys.PublicKey))[:]
	copy(cKeypair.public_keys.public_key[:], goPublicKeyValue)
	goGroupPublicKeyValue := (*[64]C.uchar)(unsafe.Pointer(&keypair.PublicKeys.GroupPublicKey))[:]
	copy(cKeypair.public_keys.group_public_key[:], goGroupPublicKeyValue)

	result := C.pubkey_from_keypair(cPubkey, cKeypair)

	// Explicitly copy fields from the C pubkey struct to the Go struct
	pubkey.Index = uint32(cPubkey.index)
	pubkey.MaxParticipants = uint32(cPubkey.max_participants)
	cPublicKeyValue := (*[64]byte)(unsafe.Pointer(&cPubkey.public_key))[:]
	copy(pubkey.PublicKey[:], cPublicKeyValue)
	cGroupPublicKeyValue := (*[64]byte)(unsafe.Pointer(&cPubkey.group_public_key))[:]
	copy(pubkey.GroupPublicKey[:], cGroupPublicKeyValue)

	return int(result)
}

func CreateNonce(nonce **Secp256k1FrostNonce, keypair *Secp256k1FrostKeypair) int {
	// Allocate memory for C nonce
	cNonce := (**C.secp256k1_frost_nonce)(C.malloc(C.size_t(unsafe.Sizeof(C.secp256k1_frost_nonce{}))))
	defer C.free(unsafe.Pointer(cNonce))

	// Allocate memory for C keypair
	cKeypair := (*C.secp256k1_frost_keypair)(C.malloc(C.size_t(unsafe.Sizeof(C.secp256k1_frost_keypair{}))))
	defer C.free(unsafe.Pointer(cKeypair))

	// Explicitly copy fields from the Go keypair struct to the C struct
	goSecretValue := (*[32]C.uchar)(unsafe.Pointer(&keypair.Secret))[:]
	copy(cKeypair.secret[:], goSecretValue)

	// Explicitly copy fields from the Go pubkey struct to the C struct
	cKeypair.public_keys.index = C.uint32_t(keypair.PublicKeys.Index)
	cKeypair.public_keys.max_participants = C.uint32_t(keypair.PublicKeys.MaxParticipants)
	goPublicKeyValue := (*[64]C.uchar)(unsafe.Pointer(&keypair.PublicKeys.PublicKey))[:]
	copy(cKeypair.public_keys.public_key[:], goPublicKeyValue)
	goGroupPublicKeyValue := (*[64]C.uchar)(unsafe.Pointer(&keypair.PublicKeys.GroupPublicKey))[:]
	copy(cKeypair.public_keys.group_public_key[:], goGroupPublicKeyValue)

	result := C.create_nonce(cNonce, cKeypair)

	// Explicitly copy fields from the C nonce struct to the Go struct
	cNonceValue := *cNonce
	goNonce := *nonce
	goNonce.Used = int32(cNonceValue.used)
	cHidingValue := (*[32]byte)(unsafe.Pointer(&cNonceValue.hiding))[:]
	copy(goNonce.Hiding[:], cHidingValue)
	cBindingValue := (*[32]byte)(unsafe.Pointer(&cNonceValue.binding))[:]
	copy(goNonce.Binding[:], cBindingValue)

	// Explicitly copy fields from the C nonce.commitments struct to the Go struct
	goNonce.Commitments.Index = uint32(cNonceValue.commitments.index)
	cCommitmentHidingValue := (*[64]byte)(unsafe.Pointer(&cNonceValue.commitments.hiding))[:]
	copy(goNonce.Commitments.Hiding[:], cCommitmentHidingValue)
	cCommitmentBindingValue := (*[64]byte)(unsafe.Pointer(&cNonceValue.commitments.binding))[:]
	copy(goNonce.Commitments.Binding[:], cCommitmentBindingValue)

	return int(result)
}

func TaggedSha256(msgHash *[32]byte, tag []byte, msg []byte) int {
	cTag := (*C.uchar)(C.CBytes(tag))
	defer C.free(unsafe.Pointer(cTag))

	cMsg := (*C.uchar)(C.CBytes(msg))
	defer C.free(unsafe.Pointer(cMsg))

	cMsgHash := (*C.uchar)(C.malloc(C.size_t(32)))
	defer C.free(unsafe.Pointer(cMsgHash))

	result := C.tagged_sha256(cMsgHash, cTag, C.uint32_t(len(tag)), cMsg, C.uint32_t(len(msg)))

	// Explicitly copy fields from the C msgHash to the Go struct
	cMsgHashValue := (*[32]byte)(unsafe.Pointer(cMsgHash))[:]
	copy(msgHash[:], cMsgHashValue)

	return int(result)
}

func Sign(signatureShare *Secp256k1FrostSignatureShare, msgHash []byte, numSigners uint32, keypair *Secp256k1FrostKeypair, nonce *Secp256k1FrostNonce, signingCommitments []Secp256k1FrostNonceCommitment) int {
	cMsgHash := (*C.uchar)(C.CBytes(msgHash))
	defer C.free(unsafe.Pointer(cMsgHash))

	// Allocate memory for C signingCommitments
	cSignCommitments := (*C.secp256k1_frost_nonce_commitment)(C.malloc(C.size_t(len(signingCommitments)) * C.size_t(unsafe.Sizeof(C.secp256k1_frost_nonce_commitment{}))))
	defer C.free(unsafe.Pointer(cSignCommitments))

	// Allocate memory for C keypair
	cKeyPair := (*C.secp256k1_frost_keypair)(C.malloc(C.size_t(unsafe.Sizeof(C.secp256k1_frost_keypair{}))))
	defer C.free(unsafe.Pointer(cKeyPair))

	// Allocate memory for C nonce
	cNonce := (*C.secp256k1_frost_nonce)(C.malloc(C.size_t(unsafe.Sizeof(C.secp256k1_frost_nonce{}))))
	defer C.free(unsafe.Pointer(cNonce))

	// Allocate memory for C signatureShare
	cSignatureShare := (*C.secp256k1_frost_signature_share)(C.malloc(C.size_t(unsafe.Sizeof(C.secp256k1_frost_signature_share{}))))
	defer C.free(unsafe.Pointer(cSignatureShare))

	// Create a Go slice for the C array
	cSignCommitmentsSlice := (*[1 << 30]C.secp256k1_frost_nonce_commitment)(unsafe.Pointer(cSignCommitments))[:len(signingCommitments):len(signingCommitments)]

	// Explicitly copy fields from the Go NonceCommitment struct to the C struct
	for i, commitment := range signingCommitments {
		cSignCommitmentsSlice[i].index = C.uint32_t(commitment.Index)
		goHidingValue := (*[64]C.uchar)(unsafe.Pointer(&commitment.Hiding))[:]
		copy(cSignCommitmentsSlice[i].hiding[:], goHidingValue)
		goBindingValue := (*[64]C.uchar)(unsafe.Pointer(&commitment.Binding))[:]
		copy(cSignCommitmentsSlice[i].binding[:], goBindingValue)
	}

	// Explicitly copy fields from the Go keypair struct to the C struct
	goSecretValue := (*[32]C.uchar)(unsafe.Pointer(&keypair.Secret))[:]
	copy(cKeyPair.secret[:], goSecretValue)
	cKeyPair.public_keys.index = C.uint32_t(keypair.PublicKeys.Index)
	cKeyPair.public_keys.max_participants = C.uint32_t(keypair.PublicKeys.MaxParticipants)
	goPublicKeyValue := (*[64]C.uchar)(unsafe.Pointer(&keypair.PublicKeys.PublicKey))[:]
	copy(cKeyPair.public_keys.public_key[:], goPublicKeyValue)
	goGroupPublicKeyValue := (*[64]C.uchar)(unsafe.Pointer(&keypair.PublicKeys.GroupPublicKey))[:]
	copy(cKeyPair.public_keys.group_public_key[:], goGroupPublicKeyValue)

	// Explicitly copy fields from the Go nonce struct to the C struct
	cNonce.used = C.int(nonce.Used)
	goHidingValue := (*[32]C.uchar)(unsafe.Pointer(&nonce.Hiding))[:]
	copy(cNonce.hiding[:], goHidingValue)
	goBindingValue := (*[32]C.uchar)(unsafe.Pointer(&nonce.Binding))[:]
	copy(cNonce.binding[:], goBindingValue)
	cNonce.commitments.index = C.uint32_t(nonce.Commitments.Index)
	goCommitmentHidingValue := (*[64]C.uchar)(unsafe.Pointer(&nonce.Commitments.Hiding))[:]
	copy(cNonce.commitments.hiding[:], goCommitmentHidingValue)
	goCommitmentBindingValue := (*[64]C.uchar)(unsafe.Pointer(&nonce.Commitments.Binding))[:]
	copy(cNonce.commitments.binding[:], goCommitmentBindingValue)

	result := C.sign(cSignatureShare, cMsgHash, C.uint32_t(numSigners),
		cKeyPair, cNonce, cSignCommitments)

	// Explicitly copy fields from the C signatureShare struct to the Go struct
	signatureShare.Index = uint32(cSignatureShare.index)
	goResponseValue := (*[32]byte)(unsafe.Pointer(&cSignatureShare.response))[:]
	copy(signatureShare.Response[:], goResponseValue)

	return int(result)
}

func Aggregate(sig64 []byte, msg32 []byte, keypair *Secp256k1FrostKeypair, publicKeys []Secp256k1FrostPubkey, commitments []Secp256k1FrostNonceCommitment, signatureShares []Secp256k1FrostSignatureShare, numSigners uint32) int {
	cSig64 := (*C.uchar)(C.CBytes(sig64))
	defer C.free(unsafe.Pointer(cSig64))

	cMsg32 := (*C.uchar)(C.CBytes(msg32))
	defer C.free(unsafe.Pointer(cMsg32))

	// Allocate memory for C keypair
	cKeypair := (*C.secp256k1_frost_keypair)(C.malloc(C.size_t(unsafe.Sizeof(C.secp256k1_frost_keypair{}))))
	defer C.free(unsafe.Pointer(cKeypair))

	// Allocate memory for C publicKeys
	cPublicKeys := (*C.secp256k1_frost_pubkey)(C.malloc(C.size_t(len(publicKeys)) * C.size_t(unsafe.Sizeof(C.secp256k1_frost_pubkey{}))))
	defer C.free(unsafe.Pointer(cPublicKeys))

	// Allocate memory for C commitments
	cCommitments := (*C.secp256k1_frost_nonce_commitment)(C.malloc(C.size_t(len(commitments)) * C.size_t(unsafe.Sizeof(C.secp256k1_frost_nonce_commitment{}))))
	defer C.free(unsafe.Pointer(cCommitments))

	// Allocate memory for C signatureShares
	cSignatureShares := (*C.secp256k1_frost_signature_share)(C.malloc(C.size_t(len(signatureShares)) * C.size_t(unsafe.Sizeof(C.secp256k1_frost_signature_share{}))))
	defer C.free(unsafe.Pointer(cSignatureShares))

	// Explicitly copy fields from the Go keypair struct to the C struct
	goSecretValue := (*[32]C.uchar)(unsafe.Pointer(&keypair.Secret))[:]
	copy(cKeypair.secret[:], goSecretValue)
	cKeypair.public_keys.index = C.uint32_t(keypair.PublicKeys.Index)
	cKeypair.public_keys.max_participants = C.uint32_t(keypair.PublicKeys.MaxParticipants)
	goPublicKeyValue := (*[64]C.uchar)(unsafe.Pointer(&keypair.PublicKeys.PublicKey))[:]
	copy(cKeypair.public_keys.public_key[:], goPublicKeyValue)
	goGroupPublicKeyValue := (*[64]C.uchar)(unsafe.Pointer(&keypair.PublicKeys.GroupPublicKey))[:]
	copy(cKeypair.public_keys.group_public_key[:], goGroupPublicKeyValue)

	// Create a Go slice for the C array
	cPublicKeysSlice := (*[1 << 30]C.secp256k1_frost_pubkey)(unsafe.Pointer(cPublicKeys))[:len(publicKeys):len(publicKeys)]
	cCommitmentsSlice := (*[1 << 30]C.secp256k1_frost_nonce_commitment)(unsafe.Pointer(cCommitments))[:len(commitments):len(commitments)]
	cSignatureSharesSlice := (*[1 << 30]C.secp256k1_frost_signature_share)(unsafe.Pointer(cSignatureShares))[:len(signatureShares):len(signatureShares)]

	// Explicitly copy fields from the Go publicKeys struct to the C struct
	for i, publicKey := range publicKeys {
		cPublicKeysSlice[i].index = C.uint32_t(publicKey.Index)
		cPublicKeysSlice[i].max_participants = C.uint32_t(publicKey.MaxParticipants)
		goPublicKeyValue := (*[64]C.uchar)(unsafe.Pointer(&publicKey.PublicKey))[:]
		copy(cPublicKeysSlice[i].public_key[:], goPublicKeyValue)
		goGroupPublicKeyValue := (*[64]C.uchar)(unsafe.Pointer(&publicKey.GroupPublicKey))[:]
		copy(cPublicKeysSlice[i].group_public_key[:], goGroupPublicKeyValue)
	}

	// Explicitly copy fields from the Go commitments struct to the C struct
	for i, commitment := range commitments {
		cCommitmentsSlice[i].index = C.uint32_t(commitment.Index)
		goHidingValue := (*[64]C.uchar)(unsafe.Pointer(&commitment.Hiding))[:]
		copy(cCommitmentsSlice[i].hiding[:], goHidingValue)
		goBindingValue := (*[64]C.uchar)(unsafe.Pointer(&commitment.Binding))[:]
		copy(cCommitmentsSlice[i].binding[:], goBindingValue)
	}

	// Explicitly copy fields from the Go signatureShares struct to the C struct
	for i, signatureShare := range signatureShares {
		cSignatureSharesSlice[i].index = C.uint32_t(signatureShare.Index)
		goResponseValue := (*[32]C.uchar)(unsafe.Pointer(&signatureShare.Response))[:]
		copy(cSignatureSharesSlice[i].response[:], goResponseValue)
	}

	result := C.aggregate(cSig64, cMsg32, cKeypair,
		cPublicKeys, cCommitments,
		cSignatureShares, C.uint32_t(numSigners))

	// Explicitly copy fields from the C signature struct to the Go struct
	cSig64Value := (*[64]byte)(unsafe.Pointer(cSig64))[:]
	copy(sig64, cSig64Value)

	return int(result)
}

func Verify(sig64 []byte, msg32 []byte, publicKeys *Secp256k1FrostPubkey) int {
	cSig64 := (*C.uchar)(C.CBytes(sig64))
	defer C.free(unsafe.Pointer(cSig64))

	cMsg32 := (*C.uchar)(C.CBytes(msg32))
	defer C.free(unsafe.Pointer(cMsg32))

	// Allocate memory for C publicKeys
	cPublicKeys := (*C.secp256k1_frost_pubkey)(C.malloc(C.size_t(unsafe.Sizeof(C.secp256k1_frost_pubkey{}))))
	defer C.free(unsafe.Pointer(cPublicKeys))

	// Explicitly copy fields from the Go publicKeys struct to the C struct
	cPublicKeys.index = C.uint32_t(publicKeys.Index)
	cPublicKeys.max_participants = C.uint32_t(publicKeys.MaxParticipants)
	goPublicKeyValue := (*[64]C.uchar)(unsafe.Pointer(&publicKeys.PublicKey))[:]
	copy(cPublicKeys.public_key[:], goPublicKeyValue)
	goGroupPublicKeyValue := (*[64]C.uchar)(unsafe.Pointer(&publicKeys.GroupPublicKey))[:]
	copy(cPublicKeys.group_public_key[:], goGroupPublicKeyValue)

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
