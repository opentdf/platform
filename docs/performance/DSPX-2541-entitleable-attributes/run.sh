#!/usr/bin/env bash
#
# Reproduce the DSPX-2541 in-memory PDP benchmark (no Docker).
#
# It drives the PDP in-memory (NewPolicyDecisionPoint + GetDecision /
# GetEntitlements) at subject-mapping scale points, measuring construction time,
# retained heap, and operation latency for two modes per operation:
#
#   - full:   PDP built over ALL policy (today's per-request load)
#   - scoped: PDP built over only the subset the operation needs
#             (projects the optimized fetch; ANY_OF corpus)
#
# From a fresh clone:
#
#   bash docs/performance/DSPX-2541-entitleable-attributes/run.sh
#
# Optional: cap the largest scale point to bound runtime:
#   ENT_PDP_MAX_N=100000 bash docs/performance/DSPX-2541-entitleable-attributes/run.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${HERE}/../../.." && pwd)"

RESULTS="${ENT_PDP_OUT:-${HERE}/pdp_results.csv}"
CHARTS_DIR="${ENT_PDP_CHARTS:-${HERE}/charts}"

echo "==> Running in-memory PDP benchmark (no Docker)"
cd "${REPO_ROOT}/service"
ENT_PDP_OUT="${RESULTS}" \
  go test -tags entpdpbench -run TestEntitleablePDPBenchmark -timeout 60m -v \
  ./internal/access/v2/

echo "==> Generating SVG charts"
python3 "${HERE}/plot.py" "${RESULTS}" "${CHARTS_DIR}"

echo "==> Done."
echo "    Data:   ${RESULTS}"
echo "    Charts: ${CHARTS_DIR}/pdp_decision_latency.svg, ${CHARTS_DIR}/pdp_entitlements_latency.svg, *_heap.svg"
