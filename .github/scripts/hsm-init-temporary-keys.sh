#!/bin/sh
set -ex

PKCS11_MODULE_PATH=/lib/softhsm/libsofthsm2.so
if which brew; then
  PKCS11_MODULE_PATH=$(brew --prefix)/lib/softhsm/libsofthsm2.so
fi

if softhsm2-util --show-slots | grep dev-token; then
  echo "[INFO] dev-token slot is already configured"
  exit 0
fi

softhsm2-util --init-token --free --label "dev-token" --pin 12345 --so-pin 12345
pkcs11-tool --module $PKCS11_MODULE_PATH --login --show-info --list-objects --pin 12345
openssl req -x509 -nodes -newkey RSA:2048 -subj "/CN=kas" -keyout kas-private.pem -out kas-cert.pem -days 365
openssl ecparam -name prime256v1 >ecparams.tmp
openssl req -x509 -nodes -newkey ec:ecparams.tmp -subj "/CN=kas" -keyout kas-ec-private.pem -out kas-ec-cert.pem -days 365
pkcs11-tool --module $PKCS11_MODULE_PATH --login --pin 12345 --write-object kas-private.pem --type privkey --label development-rsa-kas
pkcs11-tool --module $PKCS11_MODULE_PATH --login --pin 12345 --write-object kas-cert.pem --type cert --label development-rsa-kas
pkcs11-tool --module $PKCS11_MODULE_PATH --login --pin 12345 --write-object kas-ec-private.pem --type privkey --label development-ec-kas
pkcs11-tool --module $PKCS11_MODULE_PATH --login --pin 12345 --write-object kas-ec-cert.pem --type cert --label development-ec-kas
