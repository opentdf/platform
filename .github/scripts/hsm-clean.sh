#!/bin/sh

# Deletes all you softhsm2 slots that have content. Use with caution

set -ex

PKCS11_MODULE_PATH=/lib/softhsm/libsofthsm2.so
if which brew; then
  PKCS11_MODULE_PATH=$(brew --prefix)/lib/softhsm/libsofthsm2.so
fi

softhsm2-util --show-slots | sed -n "s/^.*Serial number[^0-9a-f]*\([0-9a-f]*\)$/\1/p" | while read -r slot; do
  if [ ! -z $slot ]; then
    softhsm2-util --delete-token --serial $slot
  fi
done
