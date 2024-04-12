#!/bin/sh
# hsm-init-temporary-keys.sh
# Initialize a SoftHSM slot with a set of KAS appropriate key pairs.

APP_DIR="$(cd "$(dirname -- "${0}")" >/dev/null && pwd)"

"${APP_DIR}"/init-temp-keys.sh --hsm
