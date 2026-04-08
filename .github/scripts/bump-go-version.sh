#!/usr/bin/env bash
# bump-go-version.sh - Updates the Go toolchain version across the monorepo.
#
# Usage: bump-go-version.sh [OPTIONS]
#
#   --dry-run           Print a unified diff of what would change; do not modify
#                       any files. Exits 0 if changes are needed, 2 if already
#                       at the target version.
#   --target VERSION    Use VERSION as the target (e.g. "1.25.9"); skips the
#                       go.dev API lookup.
#   --repo-root DIR     Path to the repository root (default: two directories
#                       above this script).
#   --api-url URL       Override the go.dev download API URL (default:
#                       https://go.dev/dl/?mode=json). Useful for testing.
#   --help              Print this message.
#
# Exit codes:
#   0  Changes applied successfully (normal mode) or diff produced (dry-run).
#   1  Error.
#   2  Already at the target version; no changes needed.
#
# Patch bumps update only go.work (toolchain directive).  CI workflows read
# the Go version from go.work via go-version-file, so no YAML edits are
# needed.  Individual go.mod files intentionally omit the toolchain directive
# — the workspace go.work governs builds.
#
# Minor-version bumps (triggered when the current minor falls out of Go's
# two-release support window) additionally update the go directive in go.work
# and in every module's go.mod.

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "${SCRIPT_DIR}/../.." && pwd)}"
API_URL="${API_URL:-https://go.dev/dl/?mode=json}"
DRY_RUN=false
TARGET_VERSION=""

# Modules whose go.mod carries a go directive that must be updated on a
# minor-version bump (relative to REPO_ROOT).
MODULE_DIRS=(
  examples
  sdk
  service
  lib/fixtures
  lib/flattening
  lib/identifier
  lib/ocrypto
  protocol/go
  tests-bdd
  test/integration
)

# ── Argument parsing ───────────────────────────────────────────────────────────

usage() {
  sed -n '/^# Usage:/,/^[^#]/{ /^#/{ s/^# \{0,1\}//; p } }' "$0"
}

needs_value() {
  if [[ $# -lt 2 || -z "$2" || "$2" == --* ]]; then
    echo "[ERROR] Option $1 requires a non-empty value" >&2
    usage
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)   DRY_RUN=true ;;
    --target)    needs_value "$@"; TARGET_VERSION="$2"; shift ;;
    --repo-root) needs_value "$@"; REPO_ROOT="$2"; shift ;;
    --api-url)   needs_value "$@"; API_URL="$2"; shift ;;
    --help)      usage; exit 0 ;;
    *) echo "[ERROR] Unknown option: $1" >&2; usage; exit 1 ;;
  esac
  shift
done

# ── Helpers ────────────────────────────────────────────────────────────────────

log()  { echo "[INFO] $*"; }
err()  { echo "[ERROR] $*" >&2; }

# Reads the toolchain version (e.g. "1.25.8") from a go.work file.
read_toolchain() {
  local gowork="$1"
  grep "^toolchain " "$gowork" | sed 's/toolchain go//'
}

# Returns the minor component (e.g. "1.25") from a full version string.
minor_of() {
  echo "$1" | cut -d. -f1,2
}

# ── Version resolution ─────────────────────────────────────────────────────────

GOWORK="${REPO_ROOT}/go.work"

if [[ ! -f "$GOWORK" ]]; then
  err "go.work not found at ${GOWORK}"
  exit 1
fi

CURRENT="$(read_toolchain "$GOWORK")"
if [[ -z "$CURRENT" ]]; then
  err "Could not read toolchain directive from ${GOWORK}"
  exit 1
fi
CURRENT_MINOR="$(minor_of "$CURRENT")"

if [[ -n "$TARGET_VERSION" ]]; then
  LATEST_PATCH="$TARGET_VERSION"
  TARGET_MINOR="$(minor_of "$TARGET_VERSION")"
  if [[ "$CURRENT_MINOR" != "$TARGET_MINOR" ]]; then
    NEEDS_MINOR_BUMP=true
  else
    NEEDS_MINOR_BUMP=false
  fi
else
  log "Fetching Go release list from ${API_URL}"
  VERSIONS_JSON="$(curl -sf --connect-timeout 5 --max-time 30 "$API_URL")"

  # Extract all distinct minor versions from *stable* releases, sorted ascending.
  # Filter .stable == true to exclude betas and release candidates.
  ALL_MINORS="$(
    echo "$VERSIONS_JSON" \
      | jq -r '[
          .[] | select(.stable == true) |
          .version
          | ltrimstr("go")
          | split(".")
          | .[0:2]
          | join(".")
        ] | unique | sort_by(split(".") | map(tonumber)) | .[]'
  )"

  LATEST_MINOR="$(echo "$ALL_MINORS" | tail -1)"
  PREV_MINOR="$(echo "$ALL_MINORS" | tail -2 | head -1)"

  NEEDS_MINOR_BUMP=false
  if [[ "$CURRENT_MINOR" != "$LATEST_MINOR" && "$CURRENT_MINOR" != "$PREV_MINOR" ]]; then
    log "Go ${CURRENT_MINOR} is no longer in the two most-recent supported minors" \
        "(${PREV_MINOR}, ${LATEST_MINOR}); upgrading minor version."
    TARGET_MINOR="$LATEST_MINOR"
    NEEDS_MINOR_BUMP=true
  else
    TARGET_MINOR="$CURRENT_MINOR"
  fi

  # Latest *stable* patch release for the target minor.
  # Sort numerically and take the last entry to guard against non-ordered API responses.
  LATEST_PATCH="$(
    echo "$VERSIONS_JSON" \
      | jq -r --arg prefix "go${TARGET_MINOR}." \
          '[.[] | select(.stable == true) | .version | select(startswith($prefix))]
           | sort_by(ltrimstr("go") | split(".") | map(tonumber))
           | last
           | ltrimstr("go")'
  )"

  if [[ -z "$LATEST_PATCH" || "$LATEST_PATCH" == "null" ]]; then
    err "Could not determine latest patch for Go ${TARGET_MINOR}"
    exit 1
  fi
fi

log "Current toolchain: ${CURRENT}  →  target: ${LATEST_PATCH}"

# ── Early exit if already current ─────────────────────────────────────────────

if [[ "$CURRENT" == "$LATEST_PATCH" ]]; then
  log "Already at Go ${LATEST_PATCH}; nothing to do."
  exit 2
fi

# ── Core update function ───────────────────────────────────────────────────────
# apply_changes_to TARGET_DIR
#
# Applies version updates to files rooted at TARGET_DIR.  TARGET_DIR may be
# the real REPO_ROOT (normal mode) or a temp copy (dry-run mode).
#
# Patch bumps:  only go.work toolchain directive.
# Minor bumps:  go.work toolchain + go directive, and go directive in every
#               module's go.mod.

apply_changes_to() {
  local root="$1"

  # go.work — toolchain always, go directive on minor bumps
  go work edit -toolchain="go${LATEST_PATCH}" "${root}/go.work"
  if [[ "$NEEDS_MINOR_BUMP" == "true" ]]; then
    go work edit -go="${TARGET_MINOR}.0" "${root}/go.work"
    # Each module's go.mod — go directive only (no toolchain in go.mod)
    for dir in "${MODULE_DIRS[@]}"; do
      local modfile="${root}/${dir}/go.mod"
      if [[ ! -f "$modfile" ]]; then
        log "Skipping ${dir}/go.mod (not found)"
        continue
      fi
      go mod edit -go="${TARGET_MINOR}.0" "$modfile"
    done
  fi
}

# ── List of all files the update may touch ────────────────────────────────────
target_files() {
  echo "go.work"
  if [[ "$NEEDS_MINOR_BUMP" == "true" ]]; then
    for dir in "${MODULE_DIRS[@]}"; do
      echo "${dir}/go.mod"
    done
  fi
}

# ── Dry-run: copy files, apply, diff ──────────────────────────────────────────

if [[ "$DRY_RUN" == "true" ]]; then
  TMPDIR="$(mktemp -d)"
  trap 'rm -rf "$TMPDIR"' EXIT

  # Copy only the files we will modify, preserving directory structure.
  while IFS= read -r rel; do
    local_file="${REPO_ROOT}/${rel}"
    if [[ -f "$local_file" ]]; then
      mkdir -p "${TMPDIR}/$(dirname "$rel")"
      cp "$local_file" "${TMPDIR}/${rel}"
    fi
  done < <(target_files)

  apply_changes_to "$TMPDIR"

  # Emit a unified diff for every changed file.
  HAS_DIFF=false
  while IFS= read -r rel; do
    orig="${REPO_ROOT}/${rel}"
    modified="${TMPDIR}/${rel}"
    if [[ ! -f "$orig" || ! -f "$modified" ]]; then
      continue
    fi
    if ! diff -q "$orig" "$modified" > /dev/null 2>&1; then
      # Use -L (short form) for portability: --label is GNU diff only.
      diff -u -L "a/${rel}" -L "b/${rel}" \
        "$orig" "$modified" \
        || true   # diff exits 1 when files differ — that is expected
      HAS_DIFF=true
    fi
  done < <(target_files)

  if [[ "$HAS_DIFF" == "false" ]]; then
    log "No differences — already at target version."
    exit 2
  fi
  exit 0
fi

# ── Normal mode: apply in place ───────────────────────────────────────────────

log "Applying Go ${LATEST_PATCH} updates to ${REPO_ROOT}"
apply_changes_to "$REPO_ROOT"
log "Done."
