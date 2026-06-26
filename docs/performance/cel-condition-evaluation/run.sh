#!/usr/bin/env bash
#
# Reproduce the CEL-vs-native benchmarks (no Docker). Both layers run in-memory
# below the RPC server (no wired client / server / ERS / Keycloak).
#
#   Layer 1 (operator engine): native operator switch vs precompiled CEL, plus
#            one-time CEL compile cost, swept over condition complexity.
#   Layer 2 (entitlements evaluation, v2): native Go switch vs CEL on the step
#            the v2 PDP performs, swept over subject-mapping count (no OPA).
#
# From a fresh clone:
#
#   bash docs/performance/cel-condition-evaluation/run.sh
#
# Optional: cap the largest Layer 2 scale point to bound runtime:
#   CEL_BENCH_MAX_N=1000 bash docs/performance/cel-condition-evaluation/run.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../../.." && pwd)"

OP_RESULTS="${HERE}/results.csv"
ENT_RESULTS="${HERE}/entitlements_results.csv"
CHARTS_DIR="${HERE}/charts"

cd "${REPO_ROOT}/service"

echo "==> Layer 1: operator engine (native vs CEL)"
CEL_BENCH_OP_OUT="${OP_RESULTS}" \
  go test -tags celbench -run TestCELOperatorBenchmark -timeout 30m -v \
  ./internal/subjectmappingbuiltin/

echo "==> Layer 2: entitlements evaluation, v2 (native vs CEL)"
CEL_BENCH_ENT_OUT="${ENT_RESULTS}" CEL_BENCH_MAX_N="${CEL_BENCH_MAX_N:-5000}" \
  go test -tags celbench -run TestCELEntitlementsBenchmark -timeout 30m -v \
  ./internal/subjectmappingbuiltin/

echo "==> Generating SVG charts"
python3 "${HERE}/plot.py" "${OP_RESULTS}" "${CHARTS_DIR}"
python3 "${HERE}/plot.py" "${ENT_RESULTS}" "${CHARTS_DIR}"

echo "==> Done."
echo "    Data:   ${OP_RESULTS}, ${ENT_RESULTS}"
echo "    Charts: ${CHARTS_DIR}/operator.svg, ${CHARTS_DIR}/entitlements.svg"
