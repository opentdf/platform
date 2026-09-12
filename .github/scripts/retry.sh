#!/usr/bin/env sh
# Retry an arbitrary command with exponential backoff, e.g. to smooth over
# transient network errors (sum.golang.org / proxy.golang.org HTTP/2 resets)
# during go mod download/verify without failing the whole CI job on one blip.
# Usage: retry.sh <command> [args...]
# Env: RETRY_MAX_ATTEMPTS (default 5), RETRY_SLEEP_SECONDS (default 2)
# Defaults sleep 2s, 4s, 8s, 16s between attempts (~30s total) before giving up.
set -u

max_attempts="${RETRY_MAX_ATTEMPTS:-5}"
sleep_seconds="${RETRY_SLEEP_SECONDS:-2}" # initial delay; doubles after each retry

attempt=1
while true; do
  "$@" && exit 0
  status=$?
  echo "retry.sh: attempt $attempt/$max_attempts failed (exit $status) for: $*" >&2
  [ "$attempt" -ge "$max_attempts" ] && break
  sleep "$sleep_seconds"
  sleep_seconds=$((sleep_seconds * 2))
  attempt=$((attempt + 1))
done

echo "retry.sh: all $max_attempts attempts failed for: $*" >&2
exit "$status"
