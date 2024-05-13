#!/usr/bin/env bash
# Generates a partial go.work for service X that only includes X and downstream
# items
#
#    Usage: work-init (component path)
#
# If component is unspecfied it will look for it in the GITHUB_HEAD_REF.
# This is intended to be used as part of a release please to validate the
# internal go.mod deps are up to date and accurate.
#
#  examples -> protocol/go, sdk
#  lib/crypto -> ∅
#  lib/fixtures -> ∅
#  protocol/go -> ∅
#  sdk -> lib/fixtures, lib/ocrypto, protocol/go
#  services -> lib/fixtures, lib/ocrypto, protocol/go, sdk

set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
ROOT_DIR="$(cd "${APP_DIR}/../.." >/dev/null && pwd)"

if [ -n "$1" ]; then
  component="$1"
else
  branch=${GITHUB_HEAD_REF:-${GITHUB_REF#refs/heads/}}
  component=${branch#release-please--branches--main--components--}
fi

if ! cd "$ROOT_DIR"; then
  echo "[ERROR] unable to find project directory; expected it to be in [${ROOT_DIR}]"
fi

echo "[INFO] Rebuilding partial go.work for [${component}]"
case $component in
  lib/ocrypto | lib/fixtures | protocol/go)
    echo "[INFO] skipping for leaf package"
    ;;
  sdk)
    rm go.work go.work.sum
    go work init
    go work add ./service
    go work add ./examples
    ;;
  service)
    rm go.work go.work.sum
    go work init
    go work add ./examples
    ;;
  examples)
    rm go.work go.work.sum
    ;;
  *)
    echo "[ERROR] unknown component [${component}]"
    ;;
esac
