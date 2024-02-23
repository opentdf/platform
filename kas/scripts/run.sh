#!/usr/bin/env bash
# Use ./scripts/run.sh [host]
# Parameters:
#   Optional parameter: port or host to expose. Defaults to 8000
#
# Environment variables:
#   KAS_URL
#     - The URL prefix this KAS is served from, including origin and optional PATH
#   SERVER_GRPC_PORT
#     - The port to server gRPC content on. If not specified, stores at a free
#       high port, selected by the operating system
#   SERVER_HTTP_PORT
#     - The port to serve the HTTP REST endpoint on
#   OIDC_ISSUER_URL
#     - The URL prefix to check for ISSUER. Also used for oidc discovery,
#       unless overridden by OIDC_DISCOVERY_BASE_URL
#   PKCS11_PIN
#     - SECRET
#     - local PIN for pkcs11. will be generated if not present
#   PKCS11_SO_PIN
#     - SECRET
#     - SO PIN for pkcs11. will be generated if not present
#   KAS_PRIVATE_KEY
#     - SECRET
#     - Private key (SECRET) KAS uses to certify responses.
#   KAS_CERTIFICATE
#     - SECRET
#     - Public key KAS clients can use to validate responses.
#   ATTR_AUTHORITY_HOST
#     - OpenTDF Attribute service host, or other compliant authority
#   LOG_LEVEL
#     - `slog` level. Defaults to `info`. Other options include
#       `debug` (more verbose) and `warn` (less verbose)
#     - For compatiblity, LOGLEVEL is an acceptible alias
#   LOG_FORMAT
#     - Set to `json` to enable JSON loglines
#     - For compatiblity, you may also set JSON_LOGGER to `true`
#
#   Not Implemented or used Yet
#   OIDC_SERVER_URL
#     - FIXME/DEPRECATED
#     - Partial implementation for demos only. List of allowed prefixes for OIDC tokens
#   KAS_EC_SECP256R1_PRIVATE_KEY
#     - (SECRET) private key of curve secp256r1, KAS uses to certify responses.
#     - required for nanoTDF
#   KAS_EC_SECP256R1_CERTIFICATE
#     - The public key of curve secp256r1, KAS clients can use
#       to validate responses.
#     - required for nanoTDF
#   AUDIT_ENABLED
#   CA_CERT_PATH
#     -
#
#   Maybe will not implement?
#   USE_OIDC
#   CLIENT_CERT_PATH
#   CLIENT_KEY_PATH
#   V2_SAAS_ENABLED
#   LEGACY_NANOTDF_IV
#   ATTR_AUTHORITY_CERTIFICATE
#     - The public key used to validate responses from ATTR_AUTHORITY_HOST. Not used in OIDC mode

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
PROJECT_ROOT="$(cd "${SCRIPTS_DIR}/../" >/dev/null && pwd | sed 's:/*$::')"

e() {
  echo ERROR "${@}"
  exit 1
}

l() {
  echo INFO "${@}"
}

w() {
  echo WARNING "${@}"
}

: "${SERVER_HTTP_PORT:=8000}"

# Configure and validate HOST variable
# This should be of the form [port] or [https://host:port/], for example
if [ -z "$1" ]; then
  HOST=https://localhost:${SERVER_HTTP_PORT}/
elif [[ $1 == *" "* ]]; then
  e "Invalid hostname: [$1]"
elif [[ $1 == http?:* ]]; then
  HOST="${1}:${SERVER_HTTP_PORT}"
elif [[ ${1} == http?:*:* ]]; then
  p1="${1#*:}"
  p2="${p1#*:}"
  SERVER_HTTP_PORT="${p2%%/*}"
  HOST="${1}"
elif [[ $1 =~ ^[0-9]+$ ]]; then
  SERVER_HTTP_PORT="$1"
  HOST=https://localhost:$1/
else
  e "Invalid hostname or port: [$1]"
fi
export HOST
export SERVER_HTTP_PORT

l "Configuring ${HOST}..."

# Translate from old chart env vars to newer ones
if [ -z "$OIDC_ISSUER_URL" ]; then
  if [ -n "$OIDC_SERVER_URL" ]; then
    OIDC_ISSUER_URL="${OIDC_SERVER_URL}/realms/tdf}"
    export OIDC_ISSUER_URL
  fi
fi
if [ -z "${LOG_FORMAT}" ] && [[ true == "${JSON_LOGGER}" ]]; then
  LOG_FORMAT=json
  export LOG_FORMAT
fi

if [ -z "${LOG_LEVEL}" ] && [ -n "${LOGLEVEL}" ]; then
  LOG_LEVEL="${LOGLEVEL}"
  export LOG_LEVEL
fi

: "${PKCS11_SLOT_INDEX:=0}"
: "${PKCS11_TOKEN_LABEL:=development-token}"
# FIXME random or error out if not set
: "${PKCS11_PIN:=12345}"
: "${PKCS11_SO_PIN:=12345}"
: "${PKCS11_LABEL_PUBKEY_RSA:=development-rsa-kas}"
: "${PKCS11_LABEL_PUBKEY_EC:=development-ec-kas}"

if [[ $OSTYPE == "linux-gnu"* ]]; then
  : "${PKCS11_MODULE_PATH:=/lib/softhsm/libsofthsm2.so}"
elif [[ $OSTYPE == "darwin"* ]]; then
  : "${PKCS11_MODULE_PATH:=$(brew --prefix)/lib/softhsm/libsofthsm2.so}"
else
  monolog ERROR "Unknown OS [${OSTYPE}]"
  exit 1
fi

export PKCS11_LABEL_PUBKEY_EC
export PKCS11_LABEL_PUBKEY_RSA
export PKCS11_MODULE_PATH
export PKCS11_PIN
export PKCS11_SLOT_INDEX
export PKCS11_SO_PIN

MODULE_ARGS=("--allow-sw")

if [ -f "${PKCS11_MODULE_PATH}" ]; then
  l "Using PKCS11 module ${PKCS11_MODULE_PATH}"
  MODULE_ARGS=(--module "${PKCS11_MODULE_PATH}")
else
  l "Using PKCS11 with default --allow-sw"
fi

export OIDC_ISSUER_URL
l "{host: '${HOST}', issuer: '${OIDC_ISSUER_URL}', slot: ${PKCS11_SLOT_INDEX}, tokenLabel: '${PKCS11_TOKEN_LABEL}', modulePath: '${PKCS11_MODULE_PATH}'}"

mkdir -p "${PROJECT_ROOT}/secrets/tokens"

if pkcs11-tool "${MODULE_ARGS[@]}" --show-info --list-objects --slot-index "${PKCS11_SLOT_INDEX}}"; then
  e "pkcs11-tool indicates softhsm already inited; run 'softhsm2-util --delete-token --token ${PKCS11_TOKEN_LABEL}' or similar to delete"
fi
l "Unable to list objects with pkcs11-tool before init"

# Configure softhsm. This is used to store secrets in an HSM compatible way
# softhsm2-util --init-token --slot 0 --label "development-token" --pin $PKCS11_PIN --so-pin $HSM_SO_PIN
softhsm2-util --init-token --slot "${PKCS11_SLOT_INDEX}" --label "${PKCS11_TOKEN_LABEL}" --pin "${PKCS11_PIN}" --so-pin "${PKCS11_SO_PIN}" ||
  e "Unable to use softhsm to init [--slot ${PKCS11_SLOT_INDEX} --label ${PKCS11_TOKEN_LABEL}]"

# verify login
pkcs11-tool "${MODULE_ARGS[@]}" --show-info --list-objects ||
  e "Unable to list objects with pkcs11-tool; continuing"

ptool=(pkcs11-tool "${MODULE_ARGS[@]}" --login --pin "${PKCS11_PIN}")

if [ -z "${KAS_PRIVATE_KEY}" ]; then
  if [ -f kas-private.pem ]; then
    if [ ! -f kas-cert.pem ]; then
      e "Missing kas-cert.pem"
    fi
    l "Importing KAS private key from files kas-{cert,private}.pem"
    "${ptool[@]}" --write-object kas-private.pem --type privkey --label "${PKCS11_LABEL_PUBKEY_RSA}"
    "${ptool[@]}" --write-object kas-cert.pem --type cert --label "${PKCS11_LABEL_PUBKEY_RSA}"
  else
    w "Creating new KAS private key - missing parameter KAS_PRIVATE_KEY"
    openssl req -x509 -nodes -newkey RSA:2048 -subj "/CN=kas" -keyout kas-private.pem -out kas-cert.pem -days 365
    "${ptool[@]}" --write-object kas-private.pem --type privkey --label "${PKCS11_LABEL_PUBKEY_RSA}"
    "${ptool[@]}" --write-object kas-cert.pem --type cert --label "${PKCS11_LABEL_PUBKEY_RSA}"
  fi
elif [ -z "${KAS_CERTIFICATE}" ]; then
  e "Missing KAS_CERTIFICATE"
else
  l "Importing KAS private key (RSA)"
  "${ptool[@]}" --write-object <(echo "${KAS_PRIVATE_KEY}") --type privkey --label "${PKCS11_LABEL_PUBKEY_RSA}"
  "${ptool[@]}" --write-object <(echo "${KAS_CERTIFICATE}") --type cert --label "${PKCS11_LABEL_PUBKEY_RSA}"
fi

if [ -z "${KAS_EC_SECP256R1_PRIVATE_KEY}" ]; then
  if [ -f kas-ec-private.pem ]; then
    if [ ! -f kas-ec-cert.pem ]; then
      e "Missing kas-ec-cert.pem"
    fi
    l "Importing KAS private key from file"
    # import EC key to PKCS
    "${ptool[@]}" --write-object kas-ec-private.pem --type privkey --label "${PKCS11_LABEL_PUBKEY_EC}" --usage-derive
    # import EC cert to PKCS
    "${ptool[@]}" --write-object kas-ec-cert.pem --type cert --label "${PKCS11_LABEL_PUBKEY_EC}"
  else
    w "Creating new KAS private key - missing parameter KAS_EC_SECP256R1_PRIVATE_KEY"
    # create EC key and cert
    openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -subj "/CN=kas" -keyout kas-ec-private.pem -out kas-ec-cert.pem -days 365
    # import EC key to PKCS
    "${ptool[@]}" --write-object kas-ec-private.pem --type privkey --label "${PKCS11_LABEL_PUBKEY_EC}" --usage-derive
    # import EC cert to PKCS
    "${ptool[@]}" --write-object kas-ec-cert.pem --type cert --label "${PKCS11_LABEL_PUBKEY_EC}"
  fi
elif [ -z "${KAS_EC_SECP256R1_CERTIFICATE}" ]; then
  e "Missing KAS_EC_SECP256R1_CERTIFICATE"
else
  l "Importing KAS private key (EC)"
  "${ptool[@]}" --write-object <(echo "$KAS_EC_SECP256R1_PRIVATE_KEY") --type privkey --label "${PKCS11_LABEL_PUBKEY_EC}" --usage-derive
  "${ptool[@]}" --write-object <(echo "$KAS_EC_SECP256R1_CERTIFICATE") --type cert --label "${PKCS11_LABEL_PUBKEY_EC}"
fi

l "Starting..."
"${PROJECT_ROOT}/gokas"
