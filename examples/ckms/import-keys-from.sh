#!/bin/bash
# Imports existing keys from opentdf.yaml into Vault.
#
# Usage:
#   ./import_keys_from.sh opentdf.yaml
#
# Required environment variables:
#   KAS_ADMIN_TOKEN: A token capable of updating kas_keypair in Vault.
#

# Determine the directory containing this script
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)

# Set environment variables
export VAULT_ADDR="${VAULT_ADDR:-https://127.0.0.1:8200}"
export VAULT_CACERT="${VAULT_CACERT:-${SCRIPT_DIR}/vault-ca.pem}"

# Check if KAS_ADMIN_TOKEN is set
if [ -z "$KAS_ADMIN_TOKEN" ]; then
  echo "KAS_ADMIN_TOKEN is not set. Please set it before running this script." >&2
  exit 1
fi

# Log in with the admin token
if ! echo "$KAS_ADMIN_TOKEN" | vault login -; then
  echo "Failed to log in with admin token. Exiting." >&2
  exit 1
fi

# Make sure the first parameter is provided and is a valid yaml file
if [ -z "$1" ]; then
  echo "Usage: $0 <path_to_opentdf.yaml>" >&2
  exit 1
fi
if [ ! -f "$1" ]; then
  echo "File not found: $1" >&2
  exit 1
fi
if ! yq eval -o=json "$1" >/dev/null 2>&1; then
  echo "Invalid YAML file: $1" >&2
  exit 1
fi

# Iterate through keys in opentdf-dev.yaml and store them in Vault
if ! yq eval -o=json ".server.cryptoProvider.standard.keys" <"$1"; then
  echo "Failed to retrieve keys from $1. Exiting." >&2
  exit 1
fi
OPENTDF_KAS_KEYS_JSON=$(yq eval -o=json ".server.cryptoProvider.standard.keys" <"$1")
if [ -z "$OPENTDF_KAS_KEYS_JSON" ]; then
  echo "No keys found in $1. Exiting." >&2
  exit 1
fi

# Store keys in Vault from opentdf.yaml
echo "$OPENTDF_KAS_KEYS_JSON" | jq -r 'keys[]' | while read -r KEY; do
  PRIVATE_KEY_PATH=${PROJECT_DIR}/$(echo "$OPENTDF_KAS_KEYS_JSON" | jq -r ".[${KEY}].private")
  PUBLIC_KEY_PATH=${PROJECT_DIR}/$(echo "$OPENTDF_KAS_KEYS_JSON" | jq -r ".[${KEY}].cert")
  KEY_ALGORITHM=$(echo "$OPENTDF_KAS_KEYS_JSON" | jq -r ".[${KEY}].alg")
  KEY_ID=$(echo "$OPENTDF_KAS_KEYS_JSON" | jq -r ".[${KEY}].kid")

  if ! vault kv put "secret/kas_keypair/${KEY_ID}" \
    private="$(<"$PRIVATE_KEY_PATH")" \
    public="$(<"$PUBLIC_KEY_PATH")" \
    algorithm="$KEY_ALGORITHM"; then
    echo "Failed to store key '${KEY}' in Vault." >&2
  else
    echo "Successfully stored key '${KEY_ID}' in Vault."
  fi
done
