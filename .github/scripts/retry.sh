#!/usr/bin/env sh
# Retry an arbitrary command with exponential backoff, e.g. to smooth over
# transient network errors (sum.golang.org / proxy.golang.org HTTP/2 resets)
# during go mod download/verify without failing the whole CI job on one blip.
# Usage: retry.sh <command> [args...]
# Env: RETRY_MAX_ATTEMPTS (default 5), RETRY_SLEEP_SECONDS (default 2)
# Defaults sleep 2s, 4s, 8s, 16s between attempts (~30s total) before giving up.
# Both env vars must be positive integers, and the total worst-case sleep time
# (RETRY_SLEEP_SECONDS doubling RETRY_MAX_ATTEMPTS-1 times) must stay under 10 minutes.
set -u

max_attempts="${RETRY_MAX_ATTEMPTS:-5}"
sleep_seconds="${RETRY_SLEEP_SECONDS:-2}" # initial delay; doubles after each retry

case "$max_attempts" in
  ''|*[!0-9]*) echo "retry.sh: RETRY_MAX_ATTEMPTS must be a positive integer, got '$max_attempts'" >&2; exit 1 ;;
esac
[ "$max_attempts" -ge 1 ] || { echo "retry.sh: RETRY_MAX_ATTEMPTS must be at least 1, got $max_attempts" >&2; exit 1; }

case "$sleep_seconds" in
  ''|*[!0-9]*) echo "retry.sh: RETRY_SLEEP_SECONDS must be a positive integer, got '$sleep_seconds'" >&2; exit 1 ;;
esac
[ "$sleep_seconds" -ge 1 ] || { echo "retry.sh: RETRY_SLEEP_SECONDS must be at least 1, got $sleep_seconds" >&2; exit 1; }

# Reject combinations whose total worst-case sleep time (sum of the doubling
# delays between attempts) would exceed a ~10 minute budget.
budget_seconds=600
total_sleep=0
s="$sleep_seconds"
i=1
while [ "$i" -lt "$max_attempts" ]; do
  total_sleep=$((total_sleep + s))
  if [ "$total_sleep" -gt "$budget_seconds" ]; then
    echo "retry.sh: RETRY_MAX_ATTEMPTS=$max_attempts with RETRY_SLEEP_SECONDS=$sleep_seconds would sleep over ${budget_seconds}s total; reduce RETRY_MAX_ATTEMPTS or RETRY_SLEEP_SECONDS" >&2
    exit 1
  fi
  s=$((s * 2))
  i=$((i + 1))
done

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
