#!/bin/bash
# genkeys.sh
# Generate test keys for ocrypto unit tests

set -e

# Ensure we're in the correct directory
cd "$(dirname "$0")"

echo "Generating test keys..."

# Generate EC keys
echo "Generating EC secp256r1 keys..."
openssl ecparam -name prime256v1 -genkey -noout -out sample-ec-secp256r1-01-private.pem
openssl ec -in sample-ec-secp256r1-01-private.pem -pubout -out sample-ec-secp256r1-01-public.pem

echo "Generating EC secp384r1 keys..."
openssl ecparam -name secp384r1 -genkey -noout -out sample-ec-secp384r1-01-private.pem
openssl ec -in sample-ec-secp384r1-01-private.pem -pubout -out sample-ec-secp384r1-01-public.pem

echo "Generating EC secp521r1 keys..."
openssl ecparam -name secp521r1 -genkey -noout -out sample-ec-secp521r1-01-private.pem
openssl ec -in sample-ec-secp521r1-01-private.pem -pubout -out sample-ec-secp521r1-01-public.pem

echo "Generating EC secp256k1 keys..."
openssl ecparam -name secp256k1 -genkey -noout -out sample-ec-secp256k1-01-private.pem
openssl ec -in sample-ec-secp256k1-01-private.pem -pubout -out sample-ec-secp256k1-01-public.pem

openssl ecparam -name brainpoolP160r1 -genkey -noout -out sample-ec-brainpoolP160r1-01-private.pem
openssl ec -in sample-ec-brainpoolP160r1-01-private.pem -pubout -out sample-ec-brainpoolP160r1-01-public.pem

# Generate RSA keys
echo "Generating RSA 2048 keys..."
openssl genpkey -algorithm RSA -out sample-rsa-2048-01-private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in sample-rsa-2048-01-private.pem -pubout -out sample-rsa-2048-01-public.pem

echo "Generating RSA 4096 keys..."
openssl genpkey -algorithm RSA -out sample-rsa-4096-01-private.pem -pkeyopt rsa_keygen_bits:4096
openssl rsa -in sample-rsa-4096-01-private.pem -pubout -out sample-rsa-4096-01-public.pem

echo "Generating too short RSA 1024 keys..."
openssl genpkey -algorithm RSA -out sample-rsa-1024-01-private.pem -pkeyopt rsa_keygen_bits:1024
openssl rsa -in sample-rsa-1024-01-private.pem -pubout -out sample-rsa-1024-01-public.pem

echo "Test key generation complete!"
echo "Generated keys:"
ls -la sample-*.pem
