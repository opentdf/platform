#!/usr/bin/env bash
#
# Reproduce the DSPX-2754 static-vs-dynamic entitlement benchmark end to end.
#
# Prerequisites: a Go toolchain (matching service/go.mod) and python3. No network,
# no database, no extra packages. From a fresh clone:
#
#   bash docs/performance/DSPX-3498-dynamic-value-mappings/run.sh
#
# Optional: cap the largest scale point to fit a smaller host, e.g.
#   DVM_BENCH_MAX_N=1000000 bash docs/performance/DSPX-3498-dynamic-value-mappings/run.sh
#
set -euo pipefail

# Resolve this script's directory and the repo root (two parents up from docs/).
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../../.." && pwd)"

# Output paths default to this directory; override to avoid clobbering committed data.
RESULTS="${DVM_BENCH_OUT:-${HERE}/results.csv}"
CHARTS_DIR="${DVM_BENCH_CHARTS:-${HERE}/charts}"

echo "==> Running benchmark harness (this builds up to 5M in-memory subject mappings)"
cd "${REPO_ROOT}/service"
DVM_BENCH_OUT="${RESULTS}" \
  go test -tags dvmbench -run TestDVMScaleBenchmark -timeout 60m -v \
  ./internal/access/v2/

echo "==> Generating SVG charts"
python3 "${HERE}/plot.py" "${RESULTS}" "${CHARTS_DIR}"

echo "==> Done."
echo "    Data:   ${RESULTS}"
echo "    Charts: ${CHARTS_DIR}/in_memory.svg"
