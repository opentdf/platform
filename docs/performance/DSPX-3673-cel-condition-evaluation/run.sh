#!/usr/bin/env bash
#
# Reproduce the DSPX-3673 CEL-vs-native benchmarks (no Docker). Both layers run
# in-memory below the RPC server, matching the dspx-2754-perf-test / DSPX-2541
# approach (no wired client / server / ERS / Keycloak).
#
#   Layer 1 (operator engine): native operator switch vs precompiled CEL, plus
#            one-time CEL compile cost, swept over condition complexity.
#   Layer 2 (full entitlements path): OPA rego vs direct Go switch vs direct Go
#            + CEL, swept over subject-mapping count.
#
# From a fresh clone:
#
#   bash docs/performance/DSPX-3673-cel-condition-evaluation/run.sh
#
# Optional: cap the largest Layer 2 scale point to bound runtime:
#   CEL_BENCH_MAX_N=1000 bash docs/performance/DSPX-3673-cel-condition-evaluation/run.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../../.." && pwd)"

OP_RESULTS="${HERE}/results.csv"
FP_RESULTS="${HERE}/fullpath_results.csv"
CHARTS_DIR="${HERE}/charts"

cd "${REPO_ROOT}/service"

echo "==> Layer 1: operator engine (native vs CEL)"
CEL_BENCH_OP_OUT="${OP_RESULTS}" \
  go test -tags celbench -run TestCELOperatorBenchmark -timeout 30m -v \
  ./internal/subjectmappingbuiltin/

echo "==> Layer 2: full entitlements path (rego vs go_switch vs go_cel)"
CEL_BENCH_FP_OUT="${FP_RESULTS}" CEL_BENCH_MAX_N="${CEL_BENCH_MAX_N:-5000}" \
  go test -tags celbench -run TestCELFullPathBenchmark -timeout 30m -v \
  ./authorization/

echo "==> Generating SVG charts"
python3 "${HERE}/plot.py" "${OP_RESULTS}" "${CHARTS_DIR}"
python3 "${HERE}/plot.py" "${FP_RESULTS}" "${CHARTS_DIR}"

echo "==> Done."
echo "    Data:   ${OP_RESULTS}, ${FP_RESULTS}"
echo "    Charts: ${CHARTS_DIR}/operator_latency.svg, ${CHARTS_DIR}/fullpath_{latency,allocs}.svg"
