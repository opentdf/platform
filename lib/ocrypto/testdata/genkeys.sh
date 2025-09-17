#!/bin/bash
# genkeys.sh
# Generate test keys for ocrypto unit tests

set -e

# Ensure we're in the correct directory
cd "$(dirname "$0")"

echo "Generating test keys..."

# Define EC curves: openssl_name:output_name
ec_curves=(
    "prime256v1:secp256r1"
    "secp384r1:secp384r1"
    "secp521r1:secp521r1"
    "secp256k1:secp256k1"
    "brainpoolP160r1:brainpoolP160r1"
)

# Generate EC keys
for curve_pair in "${ec_curves[@]}"; do
    IFS=':' read -r openssl_name output_name <<<"$curve_pair"
    echo "Generating EC $output_name keys..."
    openssl ecparam -name "$openssl_name" -genkey -noout -out "sample-ec-$output_name-01-private.pem"
    openssl ec -in "sample-ec-$output_name-01-private.pem" -pubout -out "sample-ec-$output_name-01-public.pem"
done

# Define RSA bit lengths
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
