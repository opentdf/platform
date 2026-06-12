#!/usr/bin/env bash
#
# Reproduce the DSPX-2754 database seed and load benchmark end to end.
#
# Unlike run.sh (pure in-memory), this benchmark needs Docker: it starts a
# testcontainers Postgres, seeds static subject mappings and one dynamic value
# mapping at scale, then pages both back through the PolicyDBClient. From a fresh
# clone:
#
#   bash docs/performance/DSPX-3498-dynamic-value-mappings/run-db.sh
#
# Optional: cap the largest scale point to fit a smaller host or bound runtime,
# e.g. (deep-OFFSET load at 1M is slow, which is itself a result):
#   DVM_DB_MAX_N=100000 bash docs/performance/DSPX-3498-dynamic-value-mappings/run-db.sh
#
set -euo pipefail

# Resolve this script's directory and the repo root (two parents up from docs/).
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../../.." && pwd)"

# Output paths default to this directory; override to avoid clobbering committed data.
RESULTS="${DVM_BENCH_OUT:-${HERE}/results.csv}"
DB_RESULTS="${DVM_DB_OUT:-${HERE}/db_results.csv}"
CHARTS_DIR="${DVM_BENCH_CHARTS:-${HERE}/charts}"

echo "==> Running DB benchmark harness (requires Docker; testcontainers Postgres)"
cd "${REPO_ROOT}/service"
DVM_DB_OUT="${DB_RESULTS}" \
  go test -tags dvmdbbench -run TestDVMDBBenchmark -timeout 60m -v \
  ./integration/

echo "==> Generating SVG charts (in-memory + DB)"
python3 "${HERE}/plot.py" "${RESULTS}" "${CHARTS_DIR}" "${DB_RESULTS}"

echo "==> Done."
echo "    Data:   ${DB_RESULTS}"
echo "    Charts: ${CHARTS_DIR}/db_load_seed.svg"
