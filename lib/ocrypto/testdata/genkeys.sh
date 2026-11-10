#!/bin/bash
# genkeys.sh
# Generate test keys for ocrypto unit tests

set -e

# Ensure we're in the correct directory
cd "$(dirname "$0")"

echo "Generating test keys..."

# Which EC curves we are using to generate keys
ec_curves=(
    "secp256r1"
    "secp384r1"
    "secp521r1"
    "secp256k1"
    "brainpoolP160r1"
)

# Generate EC keys
for curve_name in "${ec_curves[@]}"; do
    echo "Generating EC $curve_name keys..."
    openssl ecparam -name "$curve_name" -genkey -noout -out "sample-ec-$curve_name-01-private.pem"
    openssl ec -in "sample-ec-$curve_name-01-private.pem" -pubout -out "sample-ec-$curve_name-01-public.pem"
done

# What RSA bit lengths we want to test
rsa_bits=(2048 4096 1024)

# Generate RSA keys
for bits in "${rsa_bits[@]}"; do
    echo "Generating RSA $bits keys..."
    openssl genpkey -algorithm RSA -out "sample-rsa-$bits-01-private.pem" -pkeyopt "rsa_keygen_bits:$bits"
    openssl rsa -in "sample-rsa-$bits-01-private.pem" -pubout -out "sample-rsa-$bits-01-public.pem"
done

echo "Test key generation complete!"
echo "Generated keys:"
ls -la sample-*.pem
