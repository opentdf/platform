#!/usr/bin/env bash
# e2e-hybrid-test.sh
# End-to-end test of TDF encrypt/decrypt with all supported key algorithms,
# including hybrid post-quantum (X-Wing, P256+ML-KEM-768, P384+ML-KEM-1024).
#
# Usage:
#   ./scripts/e2e-hybrid-test.sh setup              Start services (docker + platform)
#   ./scripts/e2e-hybrid-test.sh test [OPTIONS]      Run encrypt/decrypt tests
#   ./scripts/e2e-hybrid-test.sh teardown            Stop services and clean up
#   ./scripts/e2e-hybrid-test.sh all [OPTIONS]       Setup + test + teardown (legacy mode)
#
# Test options:
#   --alg ALGORITHM   Test only a specific algorithm (e.g. hpqt:xwing)
#
# Examples:
#   ./scripts/e2e-hybrid-test.sh setup               # Terminal 1: start everything
#   ./scripts/e2e-hybrid-test.sh test                 # Terminal 2: run all tests
#   ./scripts/e2e-hybrid-test.sh test --alg hpqt:xwing  # test one algorithm
#   ./scripts/e2e-hybrid-test.sh teardown             # Terminal 1: stop everything

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

PLATFORM_ENDPOINT="http://localhost:8080"
CREDS="opentdf-sdk:secret"
PLATFORM_PID_FILE="/tmp/opentdf-e2e-platform.pid"

ALL_ALGS=(
  "rsa:2048"
  "ec:secp256r1"
  "hpqt:xwing"
  "hpqt:secp256r1-mlkem768"
  "hpqt:secp384r1-mlkem1024"
)

usage() {
  sed -n '2,17p' "$0" | sed 's/^# \?//'
  exit 1
}

#
# ── SETUP ──────────────────────────────────────────────────────────────
#
do_setup() {
  echo "============================================"
  echo "  OpenTDF E2E Setup"
  echo "============================================"
  echo ""

  # Clean slate: stop any existing services
  echo "==> Tearing down any existing services..."
  if [ -f "$PLATFORM_PID_FILE" ]; then
    local old_pid
    old_pid=$(cat "$PLATFORM_PID_FILE")
    kill "$old_pid" 2>/dev/null || true
    wait "$old_pid" 2>/dev/null || true
    rm -f "$PLATFORM_PID_FILE"
  fi
  local port_pid
  port_pid=$(lsof -ti :8080 2>/dev/null || true)
  if [ -n "$port_pid" ]; then
    kill "$port_pid" 2>/dev/null || true
  fi
  docker compose down 2>/dev/null || true
  echo ""

  # Step 1: Generate keys
  echo "==> Generating KAS keys (RSA, EC, hybrid PQ)..."
  .github/scripts/init-temp-keys.sh
  echo ""

  # Step 2: Create runtime config
  echo "==> Creating runtime config..."
  cp opentdf-dev.yaml opentdf.yaml
  echo ""

  # Step 3: Start docker services
  echo "==> Starting docker services (Keycloak + PostgreSQL)..."
  docker compose up -d
  echo "    Waiting for Keycloak to be ready..."
  for i in $(seq 1 60); do
    if curl -sf http://localhost:8888/auth/realms/master > /dev/null 2>&1; then
      echo "    Keycloak is ready."
      break
    fi
    if [ "$i" -eq 60 ]; then
      echo "    ERROR: Keycloak did not become ready in time."
      exit 1
    fi
    sleep 2
  done
  echo ""

  # Step 4: Provision
  echo "==> Provisioning Keycloak realm and fixtures..."
  go run ./service provision keycloak
  go run ./service provision fixtures
  echo ""

  # Step 5: Start platform
  echo "==> Starting platform..."
  go run ./service start &
  local pid=$!
  echo "$pid" > "$PLATFORM_PID_FILE"
  echo "    Platform PID: $pid (saved to $PLATFORM_PID_FILE)"
  echo "    Waiting for platform to be ready..."
  for i in $(seq 1 60); do
    if curl -sf "$PLATFORM_ENDPOINT/.well-known/opentdf-configuration" > /dev/null 2>&1; then
      echo "    Platform is ready."
      break
    fi
    if [ "$i" -eq 60 ]; then
      echo "    ERROR: Platform did not become ready in time."
      exit 1
    fi
    sleep 2
  done

  echo ""
  echo "============================================"
  echo "  Setup complete. Platform running on $PLATFORM_ENDPOINT"
  echo "  Run tests with: ./scripts/e2e-hybrid-test.sh test"
  echo "  Teardown with:  ./scripts/e2e-hybrid-test.sh teardown"
  echo "============================================"

  # Wait for platform so this terminal stays attached
  wait "$pid" 2>/dev/null || true
}

#
# ── TEST ───────────────────────────────────────────────────────────────
#
do_test() {
  local test_alg=""

  while [ $# -gt 0 ]; do
    case "$1" in
      --alg) test_alg="$2"; shift 2 ;;
      *) echo "Unknown test option: $1"; usage ;;
    esac
  done

  # Select algorithms
  local algs=()
  if [ -n "$test_alg" ]; then
    algs=("$test_alg")
  else
    algs=("${ALL_ALGS[@]}")
  fi

  # Verify platform is reachable
  if ! curl -sf "$PLATFORM_ENDPOINT/.well-known/opentdf-configuration" > /dev/null 2>&1; then
    echo "ERROR: Platform is not reachable at $PLATFORM_ENDPOINT"
    echo "       Run './scripts/e2e-hybrid-test.sh setup' first."
    exit 1
  fi

  echo "============================================"
  echo "  OpenTDF Hybrid Key E2E Tests"
  echo "============================================"
  echo ""

  # Build examples CLI
  echo "==> Building examples CLI..."
  (cd examples && go build -o examples .)
  echo ""

  echo "==> Running encrypt/decrypt tests..."
  echo ""

  local passed=0
  local failed=0
  local results=()

  for alg in "${algs[@]}"; do
    local safe_name="${alg//:/-}"
    local outfile="test-output-${safe_name}.tdf"
    local manifest_file="test-manifest-${safe_name}.json"
    local plaintext="Hello from ${alg} at $(date +%s)!"

    echo "--- Testing algorithm: $alg ---"

    # Encrypt
    echo "    Encrypting..."
    if ! examples/examples encrypt "$plaintext" \
      -e "$PLATFORM_ENDPOINT" \
      --insecurePlaintextConn \
      --creds "$CREDS" \
      --autoconfigure=false \
      -A "$alg" \
      -o "$outfile" > "$manifest_file" 2>&1; then
      echo "    FAIL: Encrypt failed for $alg"
      cat "$manifest_file" 2>/dev/null
      failed=$((failed + 1))
      results+=("FAIL $alg (encrypt)")
      rm -f "$manifest_file"
      continue
    fi
    echo "    Encrypted -> $outfile ($(wc -c < "$outfile") bytes)"
    echo ""
    echo "    Key Access ($alg):"
    echo "    ----------------------------------------"
    python3 -c "
import json, sys
m = json.load(open(sys.argv[1]))
ka = m.get('encryptionInformation', {}).get('keyAccess', [])
print(json.dumps(ka, indent=2))
" "$manifest_file" | sed 's/^/    /'
    echo "    ----------------------------------------"
    rm -f "$manifest_file"

    # Decrypt (session key type defaults to rsa:2048 — independent of wrapping algorithm)
    echo "    Decrypting..."
    local decrypted
    decrypted=$(examples/examples decrypt "$outfile" \
      -e "$PLATFORM_ENDPOINT" \
      --insecurePlaintextConn \
      --creds "$CREDS" 2>&1) || true

    if [ "$decrypted" = "$plaintext" ]; then
      echo "    PASS: Round-trip successful"
      passed=$((passed + 1))
      results+=("PASS $alg")
    else
      echo "    FAIL: Decrypted text does not match"
      echo "      Expected: $plaintext"
      echo "      Got:      $decrypted"
      failed=$((failed + 1))
      results+=("FAIL $alg (decrypt mismatch)")
    fi

    rm -f "$outfile"
    echo ""
  done

  # Summary
  echo "============================================"
  echo "  Results: $passed passed, $failed failed"
  echo "============================================"
  for result in "${results[@]}"; do
    echo "  $result"
  done
  echo ""

  if [ "$failed" -gt 0 ]; then
    exit 1
  fi
}

#
# ── TEARDOWN ───────────────────────────────────────────────────────────
#
do_teardown() {
  echo "============================================"
  echo "  OpenTDF E2E Teardown"
  echo "============================================"
  echo ""

  # Stop platform
  if [ -f "$PLATFORM_PID_FILE" ]; then
    local pid
    pid=$(cat "$PLATFORM_PID_FILE")
    echo "==> Stopping platform (PID $pid)..."
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    rm -f "$PLATFORM_PID_FILE"
  else
    # Try to kill anything on port 8080
    local pid
    pid=$(lsof -ti :8080 2>/dev/null || true)
    if [ -n "$pid" ]; then
      echo "==> Stopping process on port 8080 (PID $pid)..."
      kill "$pid" 2>/dev/null || true
    fi
  fi

  # Stop docker
  echo "==> Stopping docker services..."
  docker compose down 2>/dev/null || true

  # Clean up test artifacts
  echo "==> Cleaning up test artifacts..."
  rm -f test-output-*.tdf test-manifest-*.json examples/examples

  echo ""
  echo "  Teardown complete."
}

#
# ── ALL (legacy: setup + test + teardown) ──────────────────────────────
#
do_all() {
  # Setup in background-ish: we need to not block on `wait`
  echo "============================================"
  echo "  OpenTDF E2E Full Run (setup + test + teardown)"
  echo "============================================"
  echo ""

  # Generate keys
  echo "==> Generating KAS keys (RSA, EC, hybrid PQ)..."
  .github/scripts/init-temp-keys.sh
  echo ""

  echo "==> Creating runtime config..."
  cp opentdf-dev.yaml opentdf.yaml
  echo ""

  echo "==> Starting docker services (Keycloak + PostgreSQL)..."
  docker compose up -d
  echo "    Waiting for Keycloak to be ready..."
  for i in $(seq 1 60); do
    if curl -sf http://localhost:8888/auth/realms/master > /dev/null 2>&1; then
      echo "    Keycloak is ready."
      break
    fi
    if [ "$i" -eq 60 ]; then
      echo "    ERROR: Keycloak did not become ready in time."
      exit 1
    fi
    sleep 2
  done
  echo ""

  echo "==> Provisioning Keycloak realm and fixtures..."
  go run ./service provision keycloak
  go run ./service provision fixtures
  echo ""

  echo "==> Starting platform..."
  go run ./service start &
  local platform_pid=$!
  echo "$platform_pid" > "$PLATFORM_PID_FILE"
  echo "    Platform PID: $platform_pid"
  echo "    Waiting for platform to be ready..."
  for i in $(seq 1 60); do
    if curl -sf "$PLATFORM_ENDPOINT/.well-known/opentdf-configuration" > /dev/null 2>&1; then
      echo "    Platform is ready."
      break
    fi
    if [ "$i" -eq 60 ]; then
      echo "    ERROR: Platform did not become ready in time."
      kill "$platform_pid" 2>/dev/null || true
      exit 1
    fi
    sleep 2
  done
  echo ""

  # Run tests (pass remaining args like --alg)
  local test_exit=0
  do_test "$@" || test_exit=$?

  # Teardown
  echo ""
  do_teardown

  exit "$test_exit"
}

#
# ── MAIN ───────────────────────────────────────────────────────────────
#
if [ $# -eq 0 ]; then
  usage
fi

COMMAND="$1"
shift

case "$COMMAND" in
  setup)    do_setup "$@" ;;
  test)     do_test "$@" ;;
  teardown) do_teardown "$@" ;;
  all)      do_all "$@" ;;
  -h|--help) usage ;;
  *)        echo "Unknown command: $COMMAND"; usage ;;
esac
