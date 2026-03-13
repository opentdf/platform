#!/usr/bin/env bats

wait_for_green() {
  local limit=15
  local i
  for i in $(seq 1 "$limit"); do
    if grpcurl "localhost:8080" "grpc.health.v1.Health.Check" >/tmp/embedded-postgres-health.json 2>/dev/null; then
      if [ "$(jq -r .status </tmp/embedded-postgres-health.json)" = "SERVING" ]; then
        return 0
      fi
    fi
    sleep 2
  done

  return 1
}

wait_for_restart_cycle() {
  local limit=30
  local saw_failure=0
  local i
  for i in $(seq 1 "$limit"); do
    if grpcurl "localhost:8080" "grpc.health.v1.Health.Check" >/tmp/embedded-postgres-health.json 2>/dev/null; then
      if [ "$(jq -r .status </tmp/embedded-postgres-health.json)" = "SERVING" ] && [ "$saw_failure" -eq 1 ]; then
        return 0
      fi
    else
      saw_failure=1
    fi
    sleep 2
  done

  return 1
}

@test "embedded postgres: policy state survives platform restart" {
  if [[ "${OTDF_E2E_DB_PROVIDER:-}" != "embedded" ]]; then
    skip "embedded postgres persistence check only runs in embedded DB mode"
  fi

  local attr="https://example.io/attr/PersistenceCheck"

  run go run ./examples --creds opentdf:secret attributes add -a "${attr}" -v "One,Two" --rule hierarchy
  echo "$output"
  [ "$status" -eq 0 ]
  [[ "$output" = *"created attribute"* ]]

  run go run ./examples --creds opentdf:secret attributes ls
  echo "$output"
  [ "$status" -eq 0 ]
  [[ "$output" = *"persistencecheck"* ]]

  run touch opentdf.yaml
  [ "$status" -eq 0 ]

  run wait_for_restart_cycle
  [ "$status" -eq 0 ]

  run go run ./examples --creds opentdf:secret attributes ls
  echo "$output"
  [ "$status" -eq 0 ]
  [[ "$output" = *"persistencecheck"* ]]

  run go run ./examples --creds opentdf:secret attributes rm -f -a "${attr}"
  echo "$output"
  [ "$status" -eq 0 ]
  [[ "$output" = *"deleted attribute"* ]]
}
