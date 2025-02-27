#!/bin/bash

set -e

while getopts ":n:" opt; do
    case $opt in
        n)
            NAME=$OPTARG
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            ;;
    esac
done

if [ -z "$NAME" ]; then
    echo "Name is required. Use -n to specify"
    exit 1
fi

CA_KEY="${NAME}-ca.key"
CA_CERT="${NAME}-ca.crt"

SERVER_KEY="${NAME}.key"
SERVER_CSR="${NAME}.csr"
SERVER_CERT="${NAME}.crt"

DAYS=3650
SUB="/C=SO/ST=Earth/L=Mountain/O=TEENet/OU=DEV/CN=localhost"

# generate a self-signed root CA
openssl req -newkey rsa:2048 \
  -new -nodes -x509 \
  -days $DAYS \
  -out $CA_CERT \
  -keyout $CA_KEY \
  -subj $SUB

# generate a key for server
openssl genrsa -out $SERVER_KEY 2048

# generate a signing request for server
openssl req -new -key $SERVER_KEY -out $SERVER_CSR -subj $SUB

# generate a certificate for server
openssl x509 -req -in $SERVER_CSR \
    -extfile <(printf "subjectAltName=DNS:localhost") \
    -CA $CA_CERT -CAkey $CA_KEY \
    -days $DAYS -CAcreateserial \
    -out $SERVER_CERT 