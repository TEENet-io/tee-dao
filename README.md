# TEE-DAO
TEE-DAO is a Decentralized Autonomous Organization (DAO) constructed by heterogeneous Trusted Execution Environments (TEE) to protect critical assets. This repository implements a multi-sig application of TEE-DAO.

## Quick Start Guide
This project is based on the modified [secp256k1-frost](https://github.com/Payson1019/secp256k1-frost), which extends the [secp256k1](https://github.com/bitcoin-core/secp256k1) library to implement a threshold signature scheme based on the FROST protocol. [FROST](https://eprint.iacr.org/2020/852) is a Schnorr threshold signature scheme designed initially by C. Komlo and I. Goldberg at the 2020 International Conference on Selected Areas in Cryptography.

Package `frost_dkg_multisig`  implements the Go wrapper and the whole procedure of Distributed Key Generation (DKG) and threshold signature in a fully connected network.

## How to use
```bash
# Install from the repo
git clone https://github.com/TEENet-io/tee-dao
cd tee-dao
git submodule update --init --recursive

# Build the crypto library
cd secp256k1-frost
mkdir build && cd build
cmake -DSECP256K1_ENABLE_MODULE_FROST=ON -DSECP256K1_EXPERIMENTAL=ON -DSECP256K1_BUILD_EXAMPLES=ON .. 
make

# Generate the key with cert
mkdir config/data
cd config/data
../../script/gen-self-signed-cert.sh -n coordinator
../../script/gen-self-signed-cert.sh -n node0
../../script/gen-self-signed-cert.sh -n node1
../../script/gen-self-signed-cert.sh -n node2
../../script/gen-self-signed-cert.sh -n client0

# Start a coordinator
go run coordinator/cmd/main.go 

# Start 3 demo nodes
./script/run_nodes.sh

# Start a client for signature request
go run client/main.go -uid 0
```

