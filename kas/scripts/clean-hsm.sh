#! /bin/bash
# Use ./scripts/clean-hsm.sh

: "${PKCS11_TOKEN_LABEL:=development-token}"
softhsm2-util --delete-token --token "${PKCS11_TOKEN_LABEL}"
