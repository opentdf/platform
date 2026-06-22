#!/usr/bin/env bash
#
# Reproduce the DSPX-2541 entitlements fetch-path benchmark end to end.
#
# It needs Docker: a testcontainers Postgres is started by the integration
# package TestMain. It seeds N subject mappings across 5,000 attribute values on
# one definition, then measures two fetch paths per scale point:
#
#   - fullload: page all attributes + all subject mappings (the PDP cache build today)
#   - byfqns:   GetEntitleableAttributesByFqns for a 10-FQN decision (the new API)
#
# From a fresh clone:
#
#   bash docs/performance/DSPX-2541-entitleable-attributes/run-db.sh
#
# Optional: cap the largest scale point to fit a smaller host or bound runtime:
#   ENT_BENCH_MAX_N=100000 bash docs/performance/DSPX-2541-entitleable-attributes/run-db.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../../.." && pwd)"

RESULTS="${ENT_BENCH_OUT:-${HERE}/results.csv}"
CHARTS_DIR="${ENT_BENCH_CHARTS:-${HERE}/charts}"

echo "==> Running entitlements fetch benchmark (requires Docker; testcontainers Postgres)"
cd "${REPO_ROOT}/service"
ENT_BENCH_OUT="${RESULTS}" \
  go test -tags entbench -run TestEntitleableFetchBenchmark -timeout 60m -v \
  ./integration/

echo "==> Generating SVG chart"
python3 "${HERE}/plot.py" "${RESULTS}" "${CHARTS_DIR}"

echo "==> Done."
echo "    Data:   ${RESULTS}"
echo "    Charts: ${CHARTS_DIR}/fetch_ms.svg"
