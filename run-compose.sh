#!/bin/bash

# This script detects the host CPU architecture and specific Apple Silicon model
# to apply necessary Java options for Keycloak to avoid SIGILL errors.

HOST_ARCH=$(uname -m)
OSTYPE=$(uname)
EXTRA_JAVA_OPTS=""

echo "Detecting host architecture: $HOST_ARCH on $OSTYPE"

if [[ "$OSTYPE" == "Darwin" && "$HOST_ARCH" == "arm64" ]]; then
    # Running on macOS ARM (Apple Silicon)
    CPU_BRAND_STRING=$(sysctl -n machdep.cpu.brand_string)
    echo "Detected Apple Silicon CPU: $CPU_BRAND_STRING"

    # Check if the CPU brand string contains "M4"
    # This pattern might need adjustment if future M-series chips behave differently.
    # The "*-Pro", "*-Max", "*-Ultra" variants usually share the base chip generation.
    if [[ "$CPU_BRAND_STRING" == *"M4"* ]]; then
        echo "Detected M4 chip. Setting JAVA_OPTS_APPEND for SVE workaround."
        EXTRA_JAVA_OPTS="-XX:UseSVE=0"
    else
        # Assume M1, M2, M3, or other future chips not needing the workaround
        echo "Detected M1, M2, M3, or other chip. No specific JAVA_OPTS_APPEND needed."
        EXTRA_JAVA_OPTS="" # Ensure it's empty if not M4
    fi
else
    # Not running on macOS ARM (either x86_64 or Linux ARM, etc.)
    echo "Not running on macOS ARM. No specific JAVA_OPTS_APPEND needed."
    EXTRA_JAVA_OPTS="" # Ensure it's empty
fi

export EXTRA_JAVA_OPTS
echo "EXTRA_JAVA_OPTS set to: '$EXTRA_JAVA_OPTS'"

# Now run docker compose, passing the EXTRA_JAVA_OPTS environment variable.
# The ${EXTRA_JAVA_OPTS} syntax in the docker-compose.yaml will pick this up.
docker compose "$@" # Pass along any arguments given to the script (e.g., up -d)