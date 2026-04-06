#!/usr/bin/env bash
set -euo pipefail

# ================================================================
# TestRail Integration Script for BATS TAP results
#
# This script:
#   1. Reads TestRail config from `testrail.config.json`
#   2. Reads mapping file `testname-to-testrail-id.json` (test name → case ID)
#   3. Parses BATS TAP results from `bats-results.tap`
#   4. Creates or finds a TestRail run by name
#   5. Uploads results for matched cases
#   6. Writes a local mapping report file (mapping-report.json)
#
# Dependencies: jq, curl
# ================================================================

# -----------------------------
# Load TestRail config
# -----------------------------

CONFIG_FILE="$(dirname "$0")/testrail.config.json"

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "❌ Missing $CONFIG_FILE. Copy testrail.config.example.json and update values."
  exit 1
fi

TESTRAIL_URL=$(jq -r '.url' "$CONFIG_FILE")
PROJECT_ID=$(jq -r '.projectId' "$CONFIG_FILE")
TAP_FILE=$(jq -r '.tapFile' "$CONFIG_FILE")

# -----------------------------
# Mapping config and report file
# -----------------------------
MAPPING_FILE="$(dirname "$0")/testname-to-testrail-id.json"
REPORT_FILE="mapping-report.txt"

if [ ! -f "$MAPPING_FILE" ]; then
  echo "❌ Missing $MAPPING_FILE. Copy testname-to-testrail-id.example.json and update with your case IDs."
  exit 1
fi

# -----------------------------
# Load TestRails credentials from env
# -----------------------------
TESTRAIL_USER=${TESTRAIL_USER:-""}
TESTRAIL_PASS=${TESTRAIL_PASS:-""}

if [[ -z "$TESTRAIL_USER" || -z "$TESTRAIL_PASS" ]]; then
  echo "❌ Missing TestRail credentials. Please set TESTRAIL_USER and TESTRAIL_PASS env vars."
  exit 1
fi

# -----------------------------
# Run name (env override or auto-generate)
# -----------------------------
RUN_NAME=${TESTRAIL_CLI_RUN_NAME:-"Otdfctl CLI auto tests - $(date -Iseconds)"}

# -----------------------------
# Functions
# -----------------------------

# ---- Lookup TestRail case ID in JSON mapping file by test name (case-insensitive names comparison to avoid accident failures) ----
lookup_case_id() {
  local name="$1"
  local lowercasename
  lowercasename=$(echo "$name" | tr '[:upper:]' '[:lower:]')

  # Detect whether JSON is nested (values are objects) or flat
  if jq -e 'map_values(type) | .[] | select(.=="object")' "$MAPPING_FILE" >/dev/null 2>&1; then
    # Nested JSON: preserve spaces in section names (allow multi words)
    while IFS= read -r section; do
      id=$(jq -r --arg n "$lowercasename" --arg s "$section" '
        reduce ( .[$s] | to_entries[] ) as $item (null;
          if ($item.key | ascii_downcase) == $n then $item.value else . end
        )
      ' "$MAPPING_FILE")

      if [[ -n "$id" && "$id" != "null" ]]; then
        echo "$id|$section"
        return 0
      fi
    done < <(jq -r 'keys[]' "$MAPPING_FILE")
  else
    # Flat JSON
    id=$(jq -r --arg n "$lowercasename" '
      reduce to_entries[] as $item (null;
        if ($item.key | ascii_downcase) == $n then $item.value else . end
      )
    ' "$MAPPING_FILE")

    if [[ -n "$id" && "$id" != "null" ]]; then
      echo "$id|"
      return 0
    fi
  fi

  echo ""
  return 1
}

# Parse TAP report and build results to push + generate mapping report to identify gaps more easily
parse_tap() {
  # Check if TAP file exists
  if [[ ! -f "$TAP_FILE" ]]; then
    echo "❌ TAP file not found: $TAP_FILE"
    exit 1
  fi

  : > "$REPORT_FILE" # truncate/clear old report

  while IFS= read -r line; do
    if [[ "$line" =~ ^(ok|not\ ok)\ ([0-9]+)\ (.*) ]]; then
      status="${BASH_REMATCH[1]}"
      name="${BASH_REMATCH[3]}"

      # Detect and handle skip
      if [[ "$line" =~ \#\ skip ]]; then
        status_id=2   # Skipped
        name=$(echo "$name" | sed -E 's/ +# skip.*//')  # remove trailing " # skip ..."
      elif [[ "$status" == "ok" ]]; then
        status_id=1   # Passed
      else
        status_id=5   # Failed
      fi

      mapping=$(lookup_case_id "$name" || true)
      if [[ -n "$mapping" ]]; then
        case_id="${mapping%%|*}"
        section="${mapping##*|}"
        echo "\"$name\" YES $case_id (Section: $section)"
        echo "\"$name\" YES $case_id" >> "$REPORT_FILE"
        results+=("{\"case_id\": ${case_id#C}, \"status_id\": $status_id, \"comment\": \"$name\"}")
      else
        echo "\"$name\" NO"
        echo "\"$name\" NO" >> "$REPORT_FILE"
      fi
    fi
  done < "$TAP_FILE"
}

find_existing_run() {
  curl -s -u "$TESTRAIL_USER:$TESTRAIL_PASS" \
    "$TESTRAIL_URL/index.php?/api/v2/get_runs/$PROJECT_ID" |
    jq ".runs[] | select(.name==\"$RUN_NAME\") | .id" | head -n1
}

create_run() {
  local case_ids_json
  case_ids_json=$(printf '%s\n' "${results[@]}" | jq -s '.[].case_id' | jq -s .)

  curl -s -u "$TESTRAIL_USER:$TESTRAIL_PASS" \
    -H "Content-Type: application/json" \
    -d "{\"name\": \"$RUN_NAME\", \"include_all\": false, \"case_ids\": $case_ids_json}" \
    "$TESTRAIL_URL/index.php?/api/v2/add_run/$PROJECT_ID" | jq .id
}

push_results() {
  local run_id="$1"
  local results_json
  results_json=$(printf '%s\n' "${results[@]}" | jq -s .)

  curl -s -u "$TESTRAIL_USER:$TESTRAIL_PASS" \
    -H "Content-Type: application/json" \
    -d "{\"results\": $results_json}" \
    "$TESTRAIL_URL/index.php?/api/v2/add_results_for_cases/$run_id" > /dev/null
}

# -----------------------------
# Main
# -----------------------------
declare -a results=()

parse_tap

run_id=$(find_existing_run)
if [[ -z "$run_id" ]]; then
  echo "ℹ️ No existing run found, creating new one..."
  run_id=$(create_run)
  echo "✅ Created new run ID: $run_id"
else
  echo "ℹ️ Found existing run ID: $run_id"
fi

push_results "$run_id"
echo "✅ Results uploaded to TestRail run $run_id"
echo "📄 Mapping report written to $REPORT_FILE"
