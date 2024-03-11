#!/usr/bin/env bash
# Wait for the requested URL
# Example:
#   wait-for http://uri

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"

_wait-for() {
  local max_retries=7
  local wait_time=1
  while [[ $# -gt 0 ]]; do
    local key="$1"
    shift

    case "$key" in
      -h | --help)
        echo "wait-for-service (--max-retries 12 -q) service:uri"
        exit 0
        ;;
      -i | --max-retries)
        max_retries=$1
        shift
        if [ "$max_retries" -ge 0 ]; then
          echo "DEBUG max_retries: [${max_retries}]"
        else
          echo "ERROR not a valid number of retries: [${max_retries}]"
          exit 1
        fi
        ;;
      -q | --quadratic)
        local quadratic=1
        shift
        ;;
      *)
        local service_url="$key"
        if [[ $# -gt 0 ]]; then
          echo "ERROR Unrecognized options after service url: $*"
          exit 1
        fi
        ;;
    esac
  done

  if [ -z "$service_url" ]; then
    echo "ERROR Please specify a service url"
    exit 1
  fi

  local curl_opts=(--show-error --fail --insecure)
  curl_opts+=(--show-error)

  for i in {1..$max_retries}; do
    echo "DEBUG wait-for step ${i}/${max_retries}: [curl ${curl_opts[*]} ${service_url}]"
    curl "${curl_opts[@]}" "${service_url}"
    if [[ ${PIPESTATUS[0]} == 0 ]]; then
      return 0
    fi
    if [[ $i == $max_retries ]]; then
      break
    fi
    sleep $wait_time
    wait_time=$((wait_time * 2))
  done
  echo "ERROR Couldn't connect to $service_url"
  exit 1
}

_wait-for "$@"
