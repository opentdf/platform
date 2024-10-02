#!/usr/bin/env bash

# Randomly drop db connections to test CLI connectivity for 15 minutes total
start_time=$(date +%s)
postgresql_container_id=$(docker ps --filter "name=platform-opentdfdb-1" -q)

resource_subcommands=("attributes" "attributes namespaces" "subject-mappings" "resource-mappings" "kas-registry")

while true; do
    # Randomly wait before running the connectivity test (between 1 and 10 seconds)
    sleep $((RANDOM % 10 + 1))

    echo "Restarting PostgreSQL container..."
    docker restart $postgresql_container_id

    # Determine how many random otdfctl commands to run after the restart
    num_runs=$((RANDOM % 5 + 1))  # Randomly choose to run between 1 and 5 times

    for ((i=0; i<num_runs; i++)); do
        random_subcommand=${resource_subcommands[$RANDOM % ${#resource_subcommands[@]}]}
        
        # Introduce random delay before each execution (between 1 and 4 seconds)
        sleep $((RANDOM % 4 + 1))
        
        echo "Running randomly selected command './otdfctl policy $random_subcommand list...'"
        result=$(./otdfctl policy $random_subcommand list --with-client-creds '{"clientId":"opentdf","clientSecret":"secret"}' --host http://localhost:8080 | grep -i "success")
        echo $result
        if [ -z "$result" ]; then
        echo "Failure: 'success' not found in output; CLI failed."
        exit 1
        fi
    done
    # Exit if 15 minutes have passed (900 seconds)
    current_time=$(date +%s)
    elapsed_time=$((current_time - start_time))

    if [ $elapsed_time -ge 120 ]; then 
    # if [ $elapsed_time -ge 900 ]; then 
        exit 0
    fi
done