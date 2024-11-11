package frost_dkg_multisig

/*
#include <stdint.h>
#include <stdlib.h> // Include stdlib for malloc and free

typedef struct {
    uint32_t generator_index;
    uint32_t receiver_index;
    unsigned char value[32];
} secp256k1_frost_keygen_secret_share;

typedef struct {
    unsigned char data[64];
} secp256k1_frost_vss_commitment;

typedef struct {
    uint32_t index;
    uint32_t num_coefficients;
    secp256k1_frost_vss_commitment *coefficient_commitments;
    unsigned char zkp_r[64];
    unsigned char zkp_z[32];
} secp256k1_frost_vss_commitments;

typedef struct {
    uint32_t index;
    unsigned char hiding[64];
    unsigned char binding[64];
} secp256k1_frost_nonce_commitment;

typedef struct {
    int used; // 0 if not used, 1 if used
    unsigned char hiding[32];
    unsigned char binding[32];
    secp256k1_frost_nonce_commitment commitments;
} secp256k1_frost_nonce;

typedef struct {
    uint32_t index;
    uint32_t max_participants;
    unsigned char public_key[64];
    unsigned char group_public_key[64];
} secp256k1_frost_pubkey;

typedef struct {
    unsigned char secret[32];
    secp256k1_frost_pubkey public_keys;
} secp256k1_frost_keypair;

typedef struct {
    uint32_t index;
    unsigned char response[32];
} secp256k1_frost_signature_share;
*/
import "C"

// Go representation using basic Go types where possible

type Secp256k1FrostKeygenSecretShare struct {
	GeneratorIndex uint32
	ReceiverIndex  uint32
	Value          [32]byte
}

type Secp256k1FrostVssCommitment struct {
	Data [64]byte
}

type Secp256k1FrostVssCommitments struct {
	Index                  uint32
	NumCoefficients        uint32
	CoefficientCommitments *Secp256k1FrostVssCommitment // pointer to secp256k1_frost_vss_commitment in C
	ZkpR                   [64]byte
	ZkpZ                   [32]byte
}

type Secp256k1FrostNonceCommitment struct {
	Index   uint32
	Hiding  [64]byte
	Binding [64]byte
}

type Secp256k1FrostNonce struct {
	Used        int32                         // maps to int in C (boolean logic), Matches the 4-byte int in C
	Hiding      [32]byte                      // maps to unsigned char[32] in C
	Binding     [32]byte                      // maps to unsigned char[32] in C
	Commitments Secp256k1FrostNonceCommitment // maps to secp256k1_frost_nonce_commitment struct in C
}

type Secp256k1FrostPubkey struct {
	Index           uint32   // maps to uint32_t in C
	MaxParticipants uint32   // maps to uint32_t in C
	PublicKey       [64]byte // maps to unsigned char[64] in C
	GroupPublicKey  [64]byte // maps to unsigned char[64] in C
}

type Secp256k1FrostKeypair struct {
	Secret     [32]byte             // maps to unsigned char[32] in C
	PublicKeys Secp256k1FrostPubkey // maps to secp256k1_frost_pubkey struct in C
}

type Secp256k1FrostSignatureShare struct {
	Index    uint32
	Response [32]byte
}
