#!/usr/bin/env bats

# Running locally (shared backend)
# ```sh
# docker compose up
# go run ./service provision keycloak
# go run ./service provision fixtures
# go run ./service start
# <opentdf.yaml >opentdf-beta.yaml yq e '(.server.port = 8282) | (.services.authorization.ersurl = "http://localhost:8282/entityresolution/resolve")'
# go run ./service --config-file ./opentdf-beta.yaml start
# ```

@test "examples: two kas (shared key) file" {
  # TODO: add subject mapping here to remove reliance on `provision fixtures`
  echo "[INFO] configure attribute with grant for local kas"
  app_dir="$(cd "$BATS_TEST_DIRNAME"/.. >/dev/null && pwd)"
  std_cmd=( go run "${app_dir}/examples" )
  admin_cmd=( "${std_cmd[@]}" --creds "opentdf:secret" )
  "${admin_cmd[@]}" kas add --kas "http://localhost:8080" --public-key "$(<${app_dir}/kas-cert.pem)"
  "${admin_cmd[@]}" kas add --kas "http://localhost:8282" --public-key "$(<${app_dir}/kas-cert.pem)"
  "${admin_cmd[@]}" attributes unassign -a https://example.com/attr/attr1 -v value1
  "${admin_cmd[@]}" attributes unassign -a https://example.com/attr/attr1 -v value2
  "${admin_cmd[@]}" attributes unassign -a https://example.com/attr/attr1
  "${admin_cmd[@]}" attributes assign -a https://example.com/attr/attr1 -v value1 -k "http://localhost:8080"
  "${admin_cmd[@]}" attributes assign -a https://example.com/attr/attr1 -v value2 -k "http://localhost:8282"

  echo "[INFO] create a tdf3 format file"
  run "${std_cmd[@]}" encrypt --data-attributes=https://example.com/attr/attr1/value/{value1,value2} "Hello Zero Trust"
  echo "[INFO] echoing output; if successful, this is just the manifest"
  echo "$output"

  echo "[INFO] Validate the manifest lists the expected kid in its KAO"
  kases=$(jq -r '.encryptionInformation.keyAccess[].url' <<<"${output}")
  grep http://localhost:8080 <<<"${kases}"
  grep http://localhost:8282 <<<"${kases}"

  echo "[INFO] decrypting..."
  run "${std_cmd[@]}" decrypt sensitive.txt.tdf
  echo "$output"
  printf '%s\n' "$output" | grep "Hello Zero Trust"
}
