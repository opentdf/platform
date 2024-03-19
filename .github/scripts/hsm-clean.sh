#!/bin/sh

# Deletes all you softhsm2 slots that have content. Use with caution

set -ex

softhsm2-util --show-slots | sed -n "s/^.*Serial number[^0-9a-f]*\([0-9a-f]*\)$/\1/p" | while read -r slot; do
  if [ -n "${slot}" ]; then
    softhsm2-util --delete-token --serial "${slot}"
  fi
done
