#!/usr/bin/env bash
set -x
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"

HOST=https://localhost:5000/
LOG_FORMAT=dev
OIDC_ISSUER_URL=http:///localhost:65432/auth/realms/tdf
PKCS11_SLOT_INDEX=1

export HOST
export LOG_FORMAT
export OIDC_ISSUER_URL
export PKCS11_SLOT_INDEX

openssl req -x509 -nodes -newkey RSA:2048 -subj "/CN=kas" -keyout kas-private.pem -out kas-cert.pem -days 365
openssl req -x509 -nodes -newkey ec:<(openssl ecparam -name prime256v1) -subj "/CN=kas" -keyout kas-ec-private.pem -out kas-ec-cert.pem -days 365

"${SCRIPTS_DIR}/run.sh"
