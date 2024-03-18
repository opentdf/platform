#!/bin/bash

# Get the directory of the script
SCRIPT_DIR=$(dirname "$0")

# Define the output path for the keys and certificates relative to the script location
KEY_OUTPUT="$(realpath "$SCRIPT_DIR/../keys")"

# Ensure the output directory exists
mkdir -p "$KEY_OUTPUT"

# Generate RSA keys and certificates
openssl req -x509 -nodes -newkey RSA:2048 -subj "/CN=kas" -keyout "$KEY_OUTPUT/kas-rsa-private.pem" -out "$KEY_OUTPUT/kas-rsa-cert.pem" -days 365

# Generate EC parameters
openssl ecparam -name prime256v1 -out "$SCRIPT_DIR/ecparams.tmp"

# Generate EC keys and certificates
openssl req -x509 -nodes -newkey ec:"$SCRIPT_DIR/ecparams.tmp" -subj "/CN=kas" -keyout "$KEY_OUTPUT/kas-ec-private.pem" -out "$KEY_OUTPUT/kas-ec-cert.pem" -days 365

# Clean up temporary EC parameters file
rm -f "$SCRIPT_DIR/ecparams.tmp"