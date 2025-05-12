#!/bin/bash
# Use: `. ./setup_vault_env.sh` to set up the Vault environment for KAS
# This script sets up a local Vault server in development mode, configures it for KAS,
# and retrieves the AppRole credentials needed for KAS to authenticate with Vault.
# It also checks if Vault is already running and if the required port is available.
# Ensure the script is run from the correct directory
# and that the necessary tools (Vault, jq) are installed.

# Determine the directory containing this script
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PROJECT_DIR=$(cd "$SCRIPT_DIR/../.." && pwd)

# Check if Vault is already running
if pgrep -f "vault server"; then
  echo "Vault is already running. Exiting." >&2
  return 1
fi

# Check if port 8200 is in use
if lsof -i :8200; then
  echo "Port 8200 is already in use. Exiting." >&2
  return 1
fi

# Start Vault in dev mode
LOCAL_HOSTNAME=$(hostname)
vault server -dev -dev-root-token-id root -dev-tls -dev-tls-cert-dir="${SCRIPT_DIR}/" 2>&1 >>vault_startup.log &
VAULT_PID=$!

# Clean up Vault process on exit
trap 'echo "Trapped signal: EXIT at $(date)"; kill $VAULT_PID' EXIT

# Set environment variables
export VAULT_ADDR="https://127.0.0.1:8200"
export VAULT_CACERT="${SCRIPT_DIR}/vault-ca.pem"

# Wait for Vault to start, checking every 2 seconds for up to 30 seconds
for i in {1..15}; do
  vault status -format=json
  if [ $? -eq 0 ]; then
    echo "Vault is running." >&2
    break
  fi
  if [ $i -eq 15 ]; then
    echo "Vault did not start within 30 seconds. Exiting." >&2
    kill $VAULT_PID
    return 1
  fi
  sleep 2
done

setup_vault_adminrole() {
  # Log in to Vault
  echo root | vault login -
  if [ $? -ne 0 ]; then
    echo "Failed to log in to Vault. Exiting." >&2
    kill $VAULT_PID
    return 1
  fi

  # Check if the path is already in use before enabling KV secrets engine
  if vault secrets list -format=json | jq -e 'has("secrets/")' >/dev/null; then
    echo "KV secrets engine is already enabled at the path 'secrets/'. Skipping." >&2
  else
    # Enable KV secrets engine
    vault secrets enable -path=secrets kv-v2
    if [ $? -ne 0 ]; then
      echo "Failed to enable KV secrets engine. Exiting." >&2
      kill $VAULT_PID
      return 1
    fi
  fi

  # Write policies
  vault policy write kas-admin "${SCRIPT_DIR}/vault/policy-admin.hcl"
  if [ $? -ne 0 ]; then
    echo "Failed to write kas-admin policy. Exiting." >&2
    kill $VAULT_PID
    return 1
  fi

  vault policy write kas-service "${SCRIPT_DIR}/vault/policy-service.hcl"
  if [ $? -ne 0 ]; then
    echo "Failed to write kas-service policy. Exiting." >&2
    kill $VAULT_PID
    return 1
  fi

  vault policy write kas-viewer "${SCRIPT_DIR}/vault/policy-viewer.hcl"
  if [ $? -ne 0 ]; then
    echo "Failed to write kas-viewer policy. Exiting." >&2
    kill $VAULT_PID
    return 1
  fi

  # Create an admin token
  ADMIN_TOKEN=$(vault token create -policy="kas-admin" -policy="kas-viewer" -format=json | jq -r '.auth.client_token')
  if [ $? -ne 0 ]; then
    echo "Failed to create admin token. Exiting." >&2
    kill $VAULT_PID
    return 1
  fi

  # Export the admin token
  export KAS_ADMIN_TOKEN="$ADMIN_TOKEN"

  # Log in with the admin token
  echo "$KAS_ADMIN_TOKEN" | vault login -
  if [ $? -ne 0 ]; then
    echo "Failed to log in with admin token. Exiting." >&2
    kill $VAULT_PID
    return 1
  fi

  # Iterate through keys in opentdf-dev.yaml and store them in Vault
  OPENTDF_KAS_KEYS_JSON=$(yq eval -o=json ".server.cryptoProvider.standard.keys" <"${PROJECT_DIR}/opentdf.yaml>")
  if [ $? -ne 0 ] || [ -z "$OPENTDF_KAS_KEYS_JSON" ]; then
    echo "Failed to retrieve keys from opentdf-dev.yaml. Exiting." >&2
    kill $VAULT_PID
    return 1
  fi

  # Store keys in Vault from opentdf.yaml
  echo "$OPENTDF_KAS_KEYS_JSON" | jq -r 'keys[]' | while read -r KEY; do
    PRIVATE_KEY_PATH=${PROJECT_DIR}/$(echo "$OPENTDF_KAS_KEYS_JSON" | jq -r ".${KEY}.private")
    PUBLIC_KEY_PATH=${PROJECT_DIR}/$(echo "$OPENTDF_KAS_KEYS_JSON" | jq -r ".${KEY}.cert")
    KEY_ALGORITHM=$(echo "$OPENTDF_KAS_KEYS_JSON" | jq -r ".${KEY}.alg")
    KEY_ID=$(echo "$OPENTDF_KAS_KEYS_JSON" | jq -r ".${KEY}.kid")

    vault kv put "secrets/rsa_keys/${KEY_ID}" \
      private="$(<$PRIVATE_KEY_PATH)" \
      public="$(<$PUBLIC_KEY_PATH)" \
      algorithm="$KEY_ALGORITHM"
    if [ $? -ne 0 ]; then
      echo "Failed to store key '${KEY}' in Vault. Exiting." >&2
      kill $VAULT_PID
      return 1
    fi
  done
}

setup_vault_approle() {
  # Log in to Vault
  echo root | vault login -format=json -
  if [ $? -ne 0 ]; then
    echo "Failed to log in to Vault. Exiting." >&2
    kill $VAULT_PID
    return 1
  fi

  # Enable approle authentication
  vault auth enable approle
  if [ $? -ne 0 ]; then
    echo "Failed to enable approle authentication. Exiting." >&2
    kill $VAULT_PID
    return 1
  fi

  # Create a role for KAS
  vault write auth/approle/role/kas policies="kas-service,kas-viewer" \
    secret_id_ttl=1h \
    token_ttl=1h \
    token_max_ttl=2h \
    secret_id_num_uses=10
  if [ $? -ne 0 ]; then
    echo "Failed to create role for KAS. Exiting." >&2
    kill $VAULT_PID
    return 1
  fi

  # Retrieve role_id and secret_id
  ROLE_ID=$(vault read -format=json auth/approle/role/kas/role-id | tee /dev/stderr | jq -r '.data.role_id')
  if [ $? -ne 0 ]; then
    echo "Failed to retrieve role_id. Exiting." >&2
    kill $VAULT_PID
    return 1
  fi

  SECRET_ID=$(vault write -f -format=json auth/approle/role/kas/secret-id | tee /dev/stderr | jq -r '.data.secret_id')
  if [ $? -ne 0 ]; then
    echo "Failed to retrieve secret_id. Exiting." >&2
    kill $VAULT_PID
    return 1
  fi

  # Export the retrieved values
  export KAS_APPROLE_ROLEID="$ROLE_ID"
  export KAS_APPROLE_SECRETID="$SECRET_ID"
}

# Call the function
setup_vault_approle
export KAS_APPROLE_ROLEID="$ROLE_ID"
export KAS_APPROLE_SECRETID="$SECRET_ID"
