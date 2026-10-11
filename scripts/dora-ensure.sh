#!/usr/bin/env bash
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel)"
cd "$ROOT"

if ! command -v dora >/dev/null 2>&1; then
  echo "dora CLI is not installed; skipping Dora refresh" >&2
  exit 0
fi

if ! command -v scip-go >/dev/null 2>&1; then
  echo "scip-go is not installed; skipping Dora refresh" >&2
  exit 0
fi

mkdir -p .dora
LAST_INDEXED="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
cat > .dora/config.json <<EOF
{
  "root": "$ROOT",
  "scip": ".dora/index.scip",
  "db": ".dora/dora.db",
  "language": "go",
  "commands": {
    "index": "bash scripts/dora-index.sh"
  },
  "lastIndexed": "$LAST_INDEXED"
}
EOF

echo "Refreshing Dora index..."
dora index
