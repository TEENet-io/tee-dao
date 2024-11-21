/* frost_dkg_link.h */ 
#ifndef FROST_DKG_LINK_H
#define FROST_DKG_LINK_H

#include <stdint.h>
#include <stdlib.h>
#include <../secp256k1-frost/include/secp256k1.h>
#include <../secp256k1-frost/include/secp256k1_frost.h>

#ifdef __cplusplus
extern "C" {
#endif
int keygen_dkg_begin(secp256k1_frost_vss_commitments **dkg_commitment,
                     secp256k1_frost_keygen_secret_share *shares,
                     uint32_t num_participants,
                     uint32_t threshold,
                     uint32_t generator_index,
                     const unsigned char *context,
                     uint32_t context_length); /* This function performs the first step of the DKG process. Then the commitment should be exchanged and validated. */

int keygen_dkg_commitment_validate(const secp256k1_frost_vss_commitments **peer_commitment,
                                   const unsigned char *context,
                                   uint32_t context_length); /* This function gathers commitments from peers and validates the zero knowledge proof of knowledge for the peer's secret term. */

int keygen_dkg_finalize(secp256k1_frost_keypair *keypair, uint32_t index, 
                        uint32_t num_participants, const secp256k1_frost_keygen_secret_share *shares,
                        secp256k1_frost_vss_commitments **commitments); /* This function performs the finalization of the DKG process. */

int pubkey_from_keypair(secp256k1_frost_pubkey *pubkey, const secp256k1_frost_keypair *keypair); /* This function initializes a secp256k1_frost_pubkey using information in a secp256k1_frost_keypair. */

int create_nonce(secp256k1_frost_nonce** nonce, const secp256k1_frost_keypair *keypair); /* This function create a secp256k1 frost nonce. Then the commitment in the nonce should be exchanged. */

int tagged_sha256(unsigned char *msg_hash, const unsigned char *tag, uint32_t tag_length, const unsigned char *msg, uint32_t msg_length); /* This function compute a tagged hash as defined in BIP-340. */
                  
int sign(secp256k1_frost_signature_share *signature_share,
         const unsigned char *msg_hash,
         uint32_t num_signers,
         const secp256k1_frost_keypair *keypair,
         secp256k1_frost_nonce *nonce,
         secp256k1_frost_nonce_commitment *signing_commitments); /* This function performs the sign process in each participant. */

int aggregate(unsigned char *sig64,
              const unsigned char *msg32,
              const secp256k1_frost_keypair *keypair,
              const secp256k1_frost_pubkey *public_keys,
              secp256k1_frost_nonce_commitment *commitments,
              const secp256k1_frost_signature_share *signature_shares,
              uint32_t num_signers); /* This function combines signature shares to obtain an aggregated signature. */

int verify(const unsigned char *sig64,
           const unsigned char *msg32,
           const secp256k1_frost_pubkey *public_keys); /* This function verifies a signature. */   

int perform_dkg_multisig_with_interface(); /* This function performs the DKG and multisig process with interface. */
int perform_dkg_multisig(); /* This function performs the DKG and multisig process. */

#ifdef __cplusplus
}
#endif

#endif // FROST_DKG_LINK_H
