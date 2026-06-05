#!/bin/bash

####
# Make sure we can load BATS dependencies
####

setup_suite(){

    bats_require_minimum_version 1.7.0

    if [[ "$(which bats)" == *"homebrew"* ]]; then
        BATS_LIB_PATH=$(brew --prefix)/lib
    fi

    # Check if BATS_LIB_PATH environment variable exists
    if [ -z "${BATS_LIB_PATH}" ]; then
    # Check if bats bin has homebrew in path name
    if [[ "$(which bats)" == *"homebrew"* ]]; then
        BATS_LIB_PATH=$(dirname "$(which bats)")/../lib
    elif [ -d "/usr/lib/bats-support" ]; then
        BATS_LIB_PATH="/usr/lib"
    elif [ -d "/usr/local/lib/bats-support" ]; then
        # Check if bats-support exists in /usr/local/lib
        BATS_LIB_PATH="/usr/local/lib"
    fi
    fi
    echo "BATS_LIB_PATH: $BATS_LIB_PATH"
    export BATS_LIB_PATH=$BATS_LIB_PATH

    echo -n '{"clientId":"opentdf","clientSecret":"secret"}' > creds.json
}