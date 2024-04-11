#!/bin/sh
# init-temporary-keys.sh
# Initialize temporary keys for use with a KAS

USAGE="Usage:  ${CMD:=${0##*/}} [(-v|--verbose)] [-H|--hsm]"

# helper functions
exit2() {
  printf >&2 "%s:  %s: '%s'\n%s\n" "$CMD" "$1" "$2" "$USAGE"
  exit 2
}
check() { { [ "$1" != "$EOL" ] && [ "$1" != '--' ]; } || exit2 "missing argument" "$2"; }

# parse command-line options
set -- "$@" "${EOL:=$(printf '\1\3\3\7')}" # end-of-list marker
while [ "$1" != "$EOL" ]; do
  opt="$1"
  shift
  case "$opt" in
    -H | --hsm) opt_hsm='true' ;;
    -v | --verbose) opt_verbose='true' ;;
    -h | --help)
      printf "%s\n" "$USAGE"
      exit 0
      ;;

    # process special cases
    -[A-Za-z0-9] | -*[!A-Za-z0-9]*) exit2 "invalid option" "$opt" ;;
  esac
done
shift

if [ "$opt_verbose" = true ]; then
  set -x
fi

if [ "$opt_hsm" = true ]; then
  : "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_PIN:=12345}"
  : "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_KEYS_EC_LABEL:=development-ec-kas}"
  : "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_KEYS_RSA_LABEL:=development-rsa-kas}"

  if [ -z "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_MODULEPATH}" ]; then
    if which brew; then
      OPENTDF_SERVER_CRYPTOPROVIDER_HSM_MODULEPATH=$(brew --prefix)/lib/softhsm/libsofthsm2.so
    else
      OPENTDF_SERVER_CRYPTOPROVIDER_HSM_MODULEPATH=/lib/softhsm/libsofthsm2.so
    fi
  fi

  if softhsm2-util --show-slots | grep dev-token; then
    echo "[INFO] dev-token slot is already configured"
    exit 0
  fi

  softhsm2-util --init-token --free --label "dev-token" --pin "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_PIN}" --so-pin "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_PIN}"
  pkcs11-tool --module "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_MODULEPATH}" --login --show-info --list-objects --pin "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_PIN}"
fi

openssl req -x509 -nodes -newkey RSA:2048 -subj "/CN=kas" -keyout kas-private.pem -out kas-cert.pem -days 365
openssl ecparam -name prime256v1 >ecparams.tmp
openssl req -x509 -nodes -newkey ec:ecparams.tmp -subj "/CN=kas" -keyout kas-ec-private.pem -out kas-ec-cert.pem -days 365

if [ "$opt_hsm" = true ]; then
  pkcs11-tool --module "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_MODULEPATH}" --login --pin "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_PIN}" --write-object kas-private.pem --type privkey --label "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_KEYS_RSA_LABEL}"
  pkcs11-tool --module "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_MODULEPATH}" --login --pin "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_PIN}" --write-object kas-cert.pem --type cert --label "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_KEYS_RSA_LABEL}"
  # https://manpages.ubuntu.com/manpages/jammy/man1/pkcs11-tool.1.html --usage-derive
  pkcs11-tool --module "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_MODULEPATH}" --login --pin "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_PIN}" --write-object kas-ec-private.pem --type privkey --label "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_KEYS_EC_LABEL}" --usage-derive
  pkcs11-tool --module "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_MODULEPATH}" --login --pin "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_PIN}" --write-object kas-ec-cert.pem --type cert --label "${OPENTDF_SERVER_CRYPTOPROVIDER_HSM_KEYS_EC_LABEL}"
fi
