#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GO_WORK="$ROOT/go.work"
OUT="$ROOT/.dora/index.scip"
TMP_DIR="$ROOT/.dora/.tmp-index"
COMBINED="$TMP_DIR/index.scip"
MERGE_DIR="$ROOT/tools/dora-merge-scip"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if ! command -v scip-go >/dev/null 2>&1; then
  echo "scip-go is not installed or not on PATH" >&2
  exit 1
fi

if [ ! -f "$GO_WORK" ]; then
  echo "go.work not found at $GO_WORK" >&2
  exit 1
fi

mkdir -p "$TMP_DIR"

MERGE_INPUTS=()

mapfile -t MODULES < <(
  awk '
    BEGIN { inuse = 0 }
    /^use[[:space:]]*\($/ { inuse = 1; next }
    inuse && /^\)$/ { inuse = 0; next }
    inuse {
      sub(/[[:space:]]+\/\/.*/, "", $0)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
      if (length($0) > 0) print $0
      next
    }
    /^use[[:space:]]+[^[:space:]]+/ {
      print $2
    }
  ' "$GO_WORK"
)

if [ "${#MODULES[@]}" -eq 0 ]; then
  echo "No modules found in $GO_WORK" >&2
  exit 1
fi

for module in "${MODULES[@]}"; do
  module_prefix="${module#./}"
  safe_name="${module_prefix//\//_}"
  module_dir="$ROOT/$module_prefix"
  module_out="$TMP_DIR/$safe_name.scip"

  mapfile -t PACKAGE_PATTERNS < <(
    (
      cd "$module_dir"
      go list -e -f '{{if or .GoFiles .CgoFiles}}{{.ImportPath}}{{end}}' ./... | sed '/^$/d'
    )
  )

  if [ "${#PACKAGE_PATTERNS[@]}" -eq 0 ]; then
    echo "Skipping $module (no non-test packages)"
    continue
  fi

  echo "Indexing $module"
  (
    cd "$ROOT"
    scip-go index "${PACKAGE_PATTERNS[@]}" --module-root "$module" --output "$module_out" --skip-tests
  )

  MERGE_INPUTS+=("$module_prefix=$module_out")

done

if [ "${#MERGE_INPUTS[@]}" -eq 0 ]; then
  echo "No module indexes were generated" >&2
  exit 1
fi

(
  cd "$MERGE_DIR"
  GOWORK=off go run . "$ROOT" "$COMBINED" "${MERGE_INPUTS[@]}"
)

mv "$COMBINED" "$OUT"
echo "Wrote merged SCIP index to $OUT"
