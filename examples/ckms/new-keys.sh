#!/bin/bash
# Creates and uploads new EC and RSA keys to Vault.
#
# Usage:
#   . ./setup_vault_env.sh
#   ./new_keys.sh

# Determine the directory containing this script
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)

# Check if Vault is already running
if ! pgrep -f "vault server"; then
  echo "Vault is not running. Please start it first" >&2
  exit 1
fi

export VAULT_ADDR="${VAULT_ADDR:-https://127.0.0.1:8200}"
export VAULT_CACERT="${VAULT_CACERT:-${SCRIPT_DIR}/vault-ca.pem}"

if [ -z "$KAS_ADMIN_TOKEN" ]; then
  echo "KAS_ADMIN_TOKEN is not set. Creating a new admin role" >&2

  echo root | vault login -
  if ! echo root | vault login -; then
    echo "Failed to log in to Vault. Exiting." >&2
    exit 1
  fi

  ADMIN_TOKEN=$(vault token create -policy="kas-admin" -policy="kas-viewer" -format=json | jq -r '.auth.client_token')
  if [ -z "$ADMIN_TOKEN" ]; then
    echo "Failed to create admin token. Exiting." >&2
    exit 1
  fi

  export KAS_ADMIN_TOKEN="$ADMIN_TOKEN"
fi

# Log in with the admin token
if ! echo "$KAS_ADMIN_TOKEN" | vault login -; then
  echo "Failed to log in with admin token. Exiting." >&2
  exit 1
fi

mkdir -p "${PROJECT_DIR}/keys"

tstamp=$(date +%Y%m%d-%H%M%S)
opt_output="${PROJECT_DIR}/keys/${tstamp}"
mkdir -p "$opt_output"
if [ -z "$opt_output" ]; then
  echo "Failed to create output directory. Exiting." >&2
  exit 1
fi

openssl req -x509 -nodes -newkey RSA:2048 -subj "/CN=kas" -keyout "$opt_output/rsa-private.pem" -out "$opt_output/rsa.crt" -days 365
if ! vault kv put "secret/kas_keypair/r${tstamp}" \
  private="$(<"$opt_output/rsa-private.pem")" \
  public="$(<"$opt_output/rsa.crt")" \
  algorithm="rsa:2048"; then
  echo "Failed to store key r${tstamp} in Vault. Exiting." >&2
  exit 1
fi

openssl ecparam -name prime256v1 >ecparams.tmp
openssl req -x509 -nodes -newkey ec:ecparams.tmp -subj "/CN=kas" -keyout "$opt_output/ec-private.pem" -out "$opt_output/ec.crt" -days 365
if ! vault kv put "secret/kas_keypair/e${tstamp}" \
  private="$(<"$opt_output/ec-private.pem")" \
  public="$(<"$opt_output/ec.crt")" \
  algorithm="ec:secp256r1"; then
  echo "Failed to store key e${tstamp} in Vault. Exiting." >&2
  exit 1
fi
