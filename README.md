# TEE-DAO
TEE-DAO is a Decentralized Autonomous Organization (DAO) constructed by heterogeneous Trusted Execution Environments (TEE) to protect critical assets. This repository is the implementation of a multi-sig application of TEE-DAO.

## Quick Start Guide
This project is based on the modified [secp256k1-frost](https://github.com/Payson1019/secp256k1-frost), which extends the [secp256k1](https://github.com/bitcoin-core/secp256k1) library to implement a threshold signature scheme based on the FROST protocol. [FROST](https://eprint.iacr.org/2020/852) is a Schnorr threshold signature scheme originally designed by C. Komlo and I. Goldberg at the the 2020 International Conference on Selected Areas in Cryptography.

Package `frost_dkg_multisig`  implements the Go wrapper and the whole procedure of Distributed Key Generation (DKG) and threshold signature in a fully connected network.

## How to use
``` 
# Install from the repo
git clone https://github.com/TEENet-io/tee-dao
cd tee-dao
git submodule update --init --recursive

# Generate the key with cert with script/gen-self-signed-cert.sh
mkdir config/data
cd config/data
../../script/gen-self-signed-cert.sh node0
../../script/gen-self-signed-cert.sh node1
../../script/gen-self-signed-cert.sh node2

# start 3 demo nodes with script/run_nodes.sh
```

