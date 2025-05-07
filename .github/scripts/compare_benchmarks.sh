#!/bin/bash

set -e # Exit on error

# Script to compare benchmark results from PR and Main branches

PR_RESULTS_DIR="$1"
MAIN_RESULTS_DIR="$2"
THRESHOLD_RAW="$3" # e.g., 0.05 for 5%
CHECK_ONLY_FLAG="$4" # Optional: --check-only

if [ -z "$PR_RESULTS_DIR" ] || [ -z "$MAIN_RESULTS_DIR" ] || [ -z "$THRESHOLD_RAW" ]; then
  echo "Usage: $0 <pr_results_dir> <main_results_dir> <threshold> [--check-only]"
  exit 1
fi

# Use bc for floating point arithmetic
THRESHOLD=$(echo "scale=4; $THRESHOLD_RAW" | bc)
ONE_PLUS_THRESHOLD=$(echo "scale=4; 1 + $THRESHOLD" | bc)
ONE_MINUS_THRESHOLD=$(echo "scale=4; 1 - $THRESHOLD" | bc)

DEGRADATION_FOUND=0 # 0 = no degradation, 1 = degradation found

# --- Helper function to extract metric ---
# Usage: get_metric <file> <metric_name>
get_metric() {
  local file="$1"
  local metric_name="$2"
  local value
  # Grep for the metric, get the last field (-F':'), remove leading/trailing whitespace
  value=$(grep "^BENCHMARK_METRIC:${metric_name}:" "$file" | cut -d':' -f3- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' || echo "N/A")
  # Handle potential "N/A" or empty values explicitly before math operations
  if [[ "$value" == "N/A" ]] || [[ -z "$value" ]]; then
      echo "0" # Return 0 or handle as error if preferred
  else
      # Remove units like 's' if they exist (though metrics should be unitless numbers)
      echo "$value" | sed 's/s$//'
  fi
}

# --- Helper function for comparison ---
# Usage: compare_metric <metric_name> <pr_value> <main_value> <higher_is_better>
compare_metric() {
  local name="$1"
  local pr_val="$2"
  local main_val="$3"
  local higher_better="$4" # "true" or "false"
  local result_md="| $name | $main_val | $pr_val |"
  local change_str="N/A"
  local is_degraded=0

  # Basic check for valid numbers (can be enhanced)
  if ! [[ "$pr_val" =~ ^[0-9.-]+$ ]] || ! [[ "$main_val" =~ ^[0-9.-]+$ ]]; then
      result_md+=" N/A | ⚠️ Invalid Data |"
      echo "$result_md"
      # Consider this a degradation? Maybe depends on the metric.
      # DEGRADATION_FOUND=1
      return
  fi

  # Avoid division by zero
  if (( $(echo "$main_val == 0" | bc -l) )); then
    if (( $(echo "$pr_val != 0" | bc -l) )); then
      change_str="+Inf%" # Or some indicator of change from zero
    else
      change_str="0.00%" # No change from zero to zero
    fi
    result_md+=" $change_str | -" # No degradation check possible
  else
    # Calculate percentage change: ((pr - main) / main) * 100
    local diff=$(echo "scale=6; $pr_val - $main_val" | bc)
    local change=$(echo "scale=2; ($diff / $main_val) * 100" | bc)
    change_str=$(printf "%+.2f%%" "$change") # Format with sign and 2 decimal places
    result_md+=" $change_str |"

    # Check for degradation
    local ratio=$(echo "scale=6; $pr_val / $main_val" | bc)
    if [[ "$higher_better" == "true" ]]; then
      # Higher is better (e.g., Ops/Sec). Degradation if PR is significantly LOWER.
      if (( $(echo "$ratio < $ONE_MINUS_THRESHOLD" | bc -l) )); then
        is_degraded=1
      fi
    else
      # Lower is better (e.g., Time). Degradation if PR is significantly HIGHER.
      if (( $(echo "$ratio > $ONE_PLUS_THRESHOLD" | bc -l) )); then
        is_degraded=1
      fi
    fi

    if [ "$is_degraded" -eq 1 ]; then
       result_md+=" 📉 Degradation |"
       DEGRADATION_FOUND=1
    else
       result_md+=" ✅ OK |"
    fi
  fi

  echo "$result_md"
}


# --- Perform Comparisons ---

# Generate Markdown Header
COMPARISON_OUTPUT="| Metric                  | Main Branch | PR Branch | Change  | Status        |\n"
COMPARISON_OUTPUT+="|-------------------------|-------------|-----------|---------|---------------|\n"

# Decision Benchmark
pr_decision_time=$(get_metric "$PR_RESULTS_DIR/decision.txt" "TotalTimeSeconds")
main_decision_time=$(get_metric "$MAIN_RESULTS_DIR/decision.txt" "TotalTimeSeconds")
COMPARISON_OUTPUT+=$(compare_metric "Decision Time (s)" "$pr_decision_time" "$main_decision_time" "false")"\n" # Lower is better

pr_decision_ops=$(get_metric "$PR_RESULTS_DIR/decision.txt" "DecisionsPerSecond")
main_decision_ops=$(get_metric "$MAIN_RESULTS_DIR/decision.txt" "DecisionsPerSecond")
COMPARISON_OUTPUT+=$(compare_metric "Decisions/Sec" "$pr_decision_ops" "$main_decision_ops" "true")"\n" # Higher is better

# --- Add other benchmarks here ---
# Example: TDF3 Benchmark (assuming OpsPerSecond metric)
# pr_tdf3_ops=$(get_metric "$PR_RESULTS_DIR/tdf3.txt" "OpsPerSecond")
# main_tdf3_ops=$(get_metric "$MAIN_RESULTS_DIR/tdf3.txt" "OpsPerSecond")
# COMPARISON_OUTPUT+=$(compare_metric "TDF3 Ops/Sec" "$pr_tdf3_ops" "$main_tdf3_ops" "true")"\n"

# Example: Bulk Rewrap Time
# pr_bulk_time=$(get_metric "$PR_RESULTS_DIR/bulk.txt" "TotalTimeSeconds")
# main_bulk_time=$(get_metric "$MAIN_RESULTS_DIR/bulk.txt" "TotalTimeSeconds")
# COMPARISON_OUTPUT+=$(compare_metric "Bulk Rewrap Time (s)" "$pr_bulk_time" "$main_bulk_time" "false")"\n"


# --- Output Results ---
if [[ "$CHECK_ONLY_FLAG" == "--check-only" ]]; then
  # Only interested in the exit code
  exit $DEGRADATION_FOUND
else
  # Print the full comparison table
  echo -e "$COMPARISON_OUTPUT"
  # Final exit code reflects degradation status
  exit $DEGRADATION_FOUND
fi
