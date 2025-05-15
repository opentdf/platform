#!/bin/bash
# Sets up the Vault environment for KAS with CKMS example.
#
# Usage:
#   . ./setup_vault_env.sh
#   go run ./
# Outputs:
#   KAS_ADMIN_TOKEN: A token capable of updating kas_keypair in Vault.
#   KAS_APPROLE_ROLEID: The role ID for the AppRole.
#   KAS_APPROLE_SECRETID: The secret ID for the AppRole.
#
# This script sets up a local Vault server in development mode, configures it for KAS,
# and retrieves the AppRole credentials needed for KAS to authenticate with Vault.
# It also checks if Vault is already running and if the required port is available.
# Requires: jq, yq, and Vault CLI to be installed and available in PATH.

# Determine the directory containing this script
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

# Check if Vault is already running
if pgrep -f "vault server"; then
  echo "Vault is already running." >&2
else
  # Check if port 8200 is in use
  if lsof -i :8200; then
    echo "Port 8200 is already in use. Exiting." >&2
    return 1
  fi

  # Start Vault in dev mode
  vault server -dev -dev-root-token-id root -dev-tls -dev-tls-cert-dir="${SCRIPT_DIR}/" &>>vault_startup.log &
  VAULT_PID=$!

  echo "Vault started with PID $VAULT_PID. Waiting for it to be ready..." >&2
  echo "To install cert on macOS, run: sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./vault-ca.pem" >&2

  # Clean up Vault process on exit
  trap 'echo "Trapped signal: EXIT at $(date)"; kill $VAULT_PID' EXIT
fi

# Set environment variables
export VAULT_ADDR="https://127.0.0.1:8200"
export VAULT_CACERT="${SCRIPT_DIR}/vault-ca.pem"

# Wait for Vault to start, checking every 2 seconds for up to 30 seconds
for i in {1..15}; do
  if vault status -format=json; then
    echo "Vault is running." >&2
    break
  fi
  if [ "$i" -eq 15 ]; then
    echo "Vault did not start / respond with positive within 30 seconds. Exiting." >&2
    kill "$VAULT_PID"
    return 1
  fi
  sleep 2
done

setup_vault_adminrole() {
  # Log in to Vault
  echo root | vault login -
  if ! echo root | vault login -; then
    echo "Failed to log in to Vault. Exiting." >&2
    return 1
  fi

  # Check if the path is already in use before enabling KV secrets engine
  if vault secrets list -format=json | jq -e 'has("secret/")' >/dev/null; then
    echo "KV secrets engine is already enabled at the path 'secret/'. Skipping." >&2
  else
    # Enable KV secrets engine
    if ! vault secrets enable -path=secret kv-v2; then
      echo "Failed to enable KV secrets engine. Exiting." >&2
      return 1
    fi
  fi

  # Write policies
  if ! vault policy write kas-admin "${SCRIPT_DIR}/vaultkms/policy-admin.hcl"; then
    echo "Failed to write kas-admin policy. Exiting." >&2
    return 1
  fi

  if ! vault policy write kas-service "${SCRIPT_DIR}/vaultkms/policy-service.hcl"; then
    echo "Failed to write kas-service policy. Exiting." >&2
    return 1
  fi

  if ! vault policy write kas-viewer "${SCRIPT_DIR}/vaultkms/policy-viewer.hcl"; then
    echo "Failed to write kas-viewer policy. Exiting." >&2
    return 1
  fi

  # Create an admin token
  ADMIN_TOKEN=$(vault token create -policy="kas-admin" -policy="kas-viewer" -format=json | jq -r '.auth.client_token')
  if [ -z "$ADMIN_TOKEN" ]; then
    echo "Failed to create admin token. Exiting." >&2
    return 1
  fi

  # Export the admin token
  export KAS_ADMIN_TOKEN="$ADMIN_TOKEN"
  echo "Admin token created; exported as KAS_ADMIN_TOKEN" >&2
}

setup_vault_approle() {
  # Log in to Vault
  echo root | vault login -format=json -
  if ! echo root | vault login -format=json -; then
    echo "Failed to log in to Vault. Exiting." >&2
    return 1
  fi

  # Enable approle authentication
  if ! vault auth enable approle; then
    echo "Failed to enable approle authentication. Assuming it is already present and continuing." >&2
  fi

  # Create a role for KAS
  if ! vault write auth/approle/role/kas policies="kas-service,kas-viewer" \
    secret_id_ttl=10h \
    token_ttl=10h \
    token_max_ttl=20h \
    secret_id_num_uses=100; then
    echo "Failed to create role for KAS. Exiting." >&2
    return 1
  fi

  # Retrieve role_id and secret_id
  ROLE_ID=$(vault read -format=json auth/approle/role/kas/role-id | tee /dev/stderr | jq -r '.data.role_id')
  if ! ROLE_ID=$(vault read -format=json auth/approle/role/kas/role-id | jq -r '.data.role_id'); then
    echo "Failed to retrieve role_id. Exiting." >&2
    return 1
  fi

  SECRET_ID=$(vault write -f -format=json auth/approle/role/kas/secret-id | tee /dev/stderr | jq -r '.data.secret_id')
  if ! SECRET_ID=$(vault write -f -format=json auth/approle/role/kas/secret-id | jq -r '.data.secret_id'); then
    echo "Failed to retrieve secret_id. Exiting." >&2
    return 1
  fi

  # Export the retrieved values
  export KAS_APPROLE_ROLEID="$ROLE_ID"
  export KAS_APPROLE_SECRETID="$SECRET_ID"
}

setup_vault_adminrole
setup_vault_approle
export KAS_APPROLE_ROLEID="$ROLE_ID"
export KAS_APPROLE_SECRETID="$SECRET_ID"
