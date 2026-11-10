#!/usr/bin/env bats

# Tests for encrypt decrypt

setup_file() {
  export CREDSFILE=creds.json
  echo -n '{"clientId":"opentdf","clientSecret":"secret"}' > $CREDSFILE
  export WITH_CREDS="--with-client-creds-file $CREDSFILE"
  export DEBUG_LEVEL="--log-level debug"
  export HOST=http://localhost:8080

  export INFILE_GO_MOD=go.mod
  export OUTFILE_GO_MOD=go.mod.tdf
  export RESULTFILE_GO_MOD=result.mod
  export SESSION_KEY_ALGORITHM=ec:secp256r1
  export WRAPPING_KEY_ALGORITHM=ec:secp256r1

  export SECRET_TEXT="my special secret"
  export OUT_TXT=secret.txt
  export OUTFILE_TXT=secret.txt.tdf

  NS_ID=$(./otdfctl --host $HOST $WITH_CREDS $DEBUG_LEVEL policy attributes namespaces create -n "testing-enc-dec.io" --json | jq -r '.id')
  ATTR_ID=$(./otdfctl --host $HOST $WITH_CREDS $DEBUG_LEVEL policy attributes create --namespace "$NS_ID" -n attr1 -r ALL_OF --json | jq -r '.id')
  VAL_ID=$(./otdfctl --host $HOST $WITH_CREDS $DEBUG_LEVEL policy attributes values create --attribute-id "$ATTR_ID" -v value1 --json | jq -r '.id')
  ATTR_OBL_VAL_OUTPUT=$(./otdfctl --host $HOST $WITH_CREDS $DEBUG_LEVEL policy attributes values create --attribute-id "$ATTR_ID" -v test_attr_obligation_value --json)
  export ATTR_OBL_VAL_ID=$(echo $ATTR_OBL_VAL_OUTPUT | jq -r '.id')
  export ATTR_OBL_VAL_FQN=$(echo $ATTR_OBL_VAL_OUTPUT | jq -r '.fqn')

  # Create obligations
  OBL_ID=$(./otdfctl --host $HOST $WITH_CREDS $DEBUG_LEVEL policy obligations create -n test_obligation -s "$NS_ID" --json | jq -r '.id')
  OBL_VAL_OUTPUT=$(./otdfctl --host $HOST $WITH_CREDS $DEBUG_LEVEL policy obligations values create -o "$OBL_ID" -v test_obligation_value --json)
  OBL_VAL_ID=$(echo $OBL_VAL_OUTPUT | jq -r '.id')
  export OBL_VAL_FQN=$(echo $OBL_VAL_OUTPUT | jq -r '.fqn')
  OBL_TRIG_ID=$(./otdfctl --host $HOST $WITH_CREDS $DEBUG_LEVEL policy obligations triggers create --obligation-value "$OBL_VAL_ID" --attribute-value "$ATTR_OBL_VAL_FQN" --action "read" --json | jq -r '.id')

  # entitles opentdf client id for client credentials CLI user
  SCS='[{"condition_groups":[{"conditions":[{"operator":1,"subject_external_values":["opentdf"],"subject_external_selector_value":".clientId"}],"boolean_operator":2}]}]'
  
  # assertions setup
  HS256_KEY=$(openssl rand -base64 32)
  RS_PRIVATE_KEY=rs_private_key.pem
  RS_PUBLIC_KEY=rs_public_key.pem
  openssl genpkey -algorithm RSA -out $RS_PRIVATE_KEY -pkeyopt rsa_keygen_bits:2048
  openssl rsa -pubout -in $RS_PRIVATE_KEY -out $RS_PUBLIC_KEY

  export ASSERTIONS='[{"id":"assertion1","type":"handling","scope":"tdo","appliesToState":"encrypted","statement":{"format":"json+stanag5636","schema":"urn:nato:stanag:5636:A:1:elements:json","value":"{\"ocl\":\"2024-10-21T20:47:36Z\"}"}}]'

  export SIGNED_ASSERTIONS_HS256=signed_assertions_hs256.json
  export SIGNED_ASSERTION_VERIFICATON_HS256=assertion_verification_hs256.json
  export SIGNED_ASSERTIONS_RS256=signed_assertion_rs256.json
  export SIGNED_ASSERTION_VERIFICATON_RS256=assertion_verification_rs256.json
  echo '[{"id":"assertion1","type":"handling","scope":"tdo","appliesToState":"encrypted","statement":{"format":"json+stanag5636","schema":"urn:nato:stanag:5636:A:1:elements:json","value":"{\"ocl\":\"2024-10-21T20:47:36Z\"}"},"signingKey":{"alg":"HS256","key":"replace"}}]' > $SIGNED_ASSERTIONS_HS256
  jq --arg pem "$(echo $HS256_KEY)" '.[0].signingKey.key = $pem' $SIGNED_ASSERTIONS_HS256 > tmp.json && mv tmp.json $SIGNED_ASSERTIONS_HS256
  echo '{"keys":{"assertion1":{"alg":"HS256","key":"replace"}}}' > $SIGNED_ASSERTION_VERIFICATON_HS256
  jq --arg pem "$(echo $HS256_KEY)" '.keys.assertion1.key = $pem' $SIGNED_ASSERTION_VERIFICATON_HS256 > tmp.json && mv tmp.json $SIGNED_ASSERTION_VERIFICATON_HS256
  echo '[{"id":"assertion1","type":"handling","scope":"tdo","appliesToState":"encrypted","statement":{"format":"json+stanag5636","schema":"urn:nato:stanag:5636:A:1:elements:json","value":"{\"ocl\":\"2024-10-21T20:47:36Z\"}"},"signingKey":{"alg":"RS256","key":"replace"}}]' > $SIGNED_ASSERTIONS_RS256
  jq --arg pem "$(<$RS_PRIVATE_KEY)" '.[0].signingKey.key = $pem' $SIGNED_ASSERTIONS_RS256 > tmp.json && mv tmp.json $SIGNED_ASSERTIONS_RS256
  echo '{"keys":{"assertion1":{"alg":"RS256","key":"replace"}}}' > $SIGNED_ASSERTION_VERIFICATON_RS256
  jq --arg pem "$(<$RS_PUBLIC_KEY)" '.keys.assertion1.key = $pem' $SIGNED_ASSERTION_VERIFICATON_RS256 > tmp.json && mv tmp.json $SIGNED_ASSERTION_VERIFICATON_RS256

  
  SM=$(./otdfctl --host $HOST $WITH_CREDS $DEBUG_LEVEL policy subject-mappings create --action 'read' -a "$VAL_ID" --subject-condition-set-new "$SCS")
  export FQN="https://testing-enc-dec.io/attr/attr1/value/value1"
  export MIXED_CASE_FQN="https://Testing-Enc-Dec.io/attr/Attr1/value/VALUE1"
}

setup() {
    load "${BATS_LIB_PATH}/bats-support/load.bash"
    load "${BATS_LIB_PATH}/bats-assert/load.bash"
}

teardown() {
    rm -f $OUTFILE_GO_MOD $RESULTFILE_GO_MOD $OUTFILE_TXT
}

teardown_file(){
    ./otdfctl --host "$HOST" $WITH_CREDS policy attributes namespaces unsafe delete --id "$NS_ID" --force
    rm -f $SIGNED_ASSERTIONS_HS256 $SIGNED_ASSERTION_VERIFICATON_HS256 $SIGNED_ASSERTIONS_RS256 $SIGNED_ASSERTION_VERIFICATON_RS256
}

@test "roundtrip TDF3, no attributes, file" {
  ./otdfctl encrypt -o $OUTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type tdf3 $INFILE_GO_MOD
  ./otdfctl decrypt -o $RESULTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type tdf3 $OUTFILE_GO_MOD
  diff $INFILE_GO_MOD $RESULTFILE_GO_MOD
}

@test "roundtrip TDF3, no attributes, ec-wrapping, file" {
  ./otdfctl encrypt -o $OUTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type tdf3 --wrapping-key-algorithm $WRAPPING_KEY_ALGORITHM $INFILE_GO_MOD
  ./otdfctl decrypt -o $RESULTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type tdf3 --session-key-algorithm $SESSION_KEY_ALGORITHM $OUTFILE_GO_MOD
  diff $INFILE_GO_MOD $RESULTFILE_GO_MOD
}

@test "roundtrip TDF3, one attribute, stdin" {
  echo $SECRET_TEXT | ./otdfctl encrypt -o $OUT_TXT --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS -a $FQN
  ./otdfctl decrypt --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS $OUTFILE_TXT | grep "$SECRET_TEXT"
}

@test "roundtrip TDF3, one attribute, mixed case FQN, stdin" {
  echo $SECRET_TEXT | ./otdfctl encrypt -o $OUT_TXT --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS -a $MIXED_CASE_FQN
  ./otdfctl decrypt --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS $OUTFILE_TXT | grep "$SECRET_TEXT"
}

@test "roundtrip TDF3, assertions, stdin" {
  echo $SECRET_TEXT | ./otdfctl encrypt -o $OUT_TXT --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS -a $FQN --with-assertions "$ASSERTIONS"
  ./otdfctl decrypt --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS $OUTFILE_TXT | grep "$SECRET_TEXT"
  ./otdfctl --host $HOST --tls-no-verify $WITH_CREDS inspect $OUTFILE_TXT
  assertions_present=$(./otdfctl --host $HOST --tls-no-verify $WITH_CREDS inspect $OUTFILE_TXT | jq '.manifest.assertions[0].id')
  [[ $assertions_present == "\"assertion1\"" ]]
}

@test "roundtrip TDF3, assertions with HS256 keys and verification, file" {
  ./otdfctl encrypt -o $OUTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS -a $FQN --with-assertions $SIGNED_ASSERTIONS_HS256 --tdf-type tdf3 $INFILE_GO_MOD
  ./otdfctl decrypt -o $RESULTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --with-assertion-verification-keys $SIGNED_ASSERTION_VERIFICATON_HS256 --tdf-type tdf3 $OUTFILE_GO_MOD
  diff $INFILE_GO_MOD $RESULTFILE_GO_MOD
  ./otdfctl --host $HOST --tls-no-verify $WITH_CREDS inspect $OUTFILE_GO_MOD
  assertions_present=$(./otdfctl --host $HOST --tls-no-verify $WITH_CREDS inspect $OUTFILE_GO_MOD | jq '.manifest.assertions[0].id')
  [[ $assertions_present == "\"assertion1\"" ]]
}

@test "roundtrip TDF3, assertions with RS256 keys and verification, file" {
  ./otdfctl encrypt -o $OUTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS -a $FQN --with-assertions $SIGNED_ASSERTIONS_RS256 --tdf-type tdf3 $INFILE_GO_MOD
  ./otdfctl decrypt -o $RESULTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --with-assertion-verification-keys $SIGNED_ASSERTION_VERIFICATON_RS256 --tdf-type tdf3 $OUTFILE_GO_MOD
  diff $INFILE_GO_MOD $RESULTFILE_GO_MOD
  ./otdfctl --host $HOST --tls-no-verify $WITH_CREDS inspect $OUTFILE_GO_MOD
  assertions_present=$(./otdfctl --host $HOST --tls-no-verify $WITH_CREDS inspect $OUTFILE_GO_MOD | jq '.manifest.assertions[0].id')
  [[ $assertions_present == "\"assertion1\"" ]]
}

@test "roundtrip NANO, no attributes, file" {
  ./otdfctl encrypt -o $OUTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type nano $INFILE_GO_MOD
  ./otdfctl decrypt -o $RESULTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type nano $OUTFILE_GO_MOD
  diff $INFILE_GO_MOD $RESULTFILE_GO_MOD
}

@test "roundtrip NANO, no attributes, file, ecdsa binding" {
  ./otdfctl encrypt -o $OUTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --ecdsa-binding --tdf-type nano $INFILE_GO_MOD
  ./otdfctl decrypt -o $RESULTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type nano $OUTFILE_GO_MOD
  diff $INFILE_GO_MOD $RESULTFILE_GO_MOD
  ./otdfctl --host $HOST --tls-no-verify $WITH_CREDS inspect $OUTFILE_GO_MOD
  ecdsa_enabled="$(./otdfctl --host $HOST --tls-no-verify $WITH_CREDS inspect $OUTFILE_GO_MOD | jq .ecdsaEnabled)"
  [[ "$ecdsa_enabled" == true ]]
}

@test "roundtrip NANO, one attribute, stdin" {
  echo $SECRET_TEXT | ./otdfctl encrypt --tdf-type nano -o $OUT_TXT --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS -a $FQN
  ./otdfctl decrypt --tdf-type nano --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS $OUTFILE_TXT | grep "$SECRET_TEXT"
}

@test "roundtrip NANO, one attribute, stdin, plaintext policy mode" {
  echo $SECRET_TEXT | ./otdfctl encrypt --tdf-type nano -o $OUT_TXT --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS -a $MIXED_CASE_FQN --policy-mode plaintext
  ./otdfctl decrypt --tdf-type nano --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS $OUTFILE_TXT | grep "$SECRET_TEXT"
  grep -a "$MIXED_CASE_FQN" "$OUTFILE_TXT"
}

@test "roundtrip NANO, one attribute, mixed case FQN, stdin" {
  echo $SECRET_TEXT | ./otdfctl encrypt --tdf-type nano -o $OUT_TXT --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS -a $MIXED_CASE_FQN
  ./otdfctl decrypt --tdf-type nano --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS $OUTFILE_TXT | grep "$SECRET_TEXT"
}

@test "roundtrip TDF3, with target version < 4.3.0" {
  ./otdfctl encrypt -o $OUTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type tdf3 --target-mode v4.2.2 $INFILE_GO_MOD
  ./otdfctl decrypt -o $RESULTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type tdf3 $OUTFILE_GO_MOD
  diff $INFILE_GO_MOD $RESULTFILE_GO_MOD

  schema_version_present=$(./otdfctl --host $HOST --tls-no-verify $WITH_CREDS inspect $OUTFILE_GO_MOD | jq '.manifest | has("schemaVersion")')
  [[ $schema_version_present == false ]]
}

@test "roundtrip TDF3, with target version >= 4.3.0" {
  ./otdfctl encrypt -o $OUTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type tdf3 --target-mode v4.3.1 $INFILE_GO_MOD
  ./otdfctl decrypt -o $RESULTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type tdf3 $OUTFILE_GO_MOD
  diff $INFILE_GO_MOD $RESULTFILE_GO_MOD

  schema_version_present=$(./otdfctl --host $HOST --tls-no-verify $WITH_CREDS inspect $OUTFILE_GO_MOD | jq '.manifest | has("schemaVersion")')
  [[ $schema_version_present == true ]]
}

@test "roundtrip TDF3, with allowlist containing platform kas" {
  ./otdfctl encrypt -o $OUTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type tdf3  $INFILE_GO_MOD
  run sh -c "./otdfctl decrypt --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type tdf3 --kas-allowlist http://localhost:8080/kas $OUTFILE_GO_MOD"
  assert_success
}

@test "roundtrip TDF3, with allowlist containing non existent kas (should fail)" {
  ./otdfctl encrypt -o $OUTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type tdf3 $INFILE_GO_MOD
  run sh -c "./otdfctl decrypt --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type tdf3 --kas-allowlist http://not-a-real-kas.com/kas $OUTFILE_GO_MOD"
  assert_failure
  assert_output --partial "KasAllowlist: kas url http://localhost:8080/kas is not allowed"
}

@test "roundtrip TDF3, ignoring allowlist" {
  ./otdfctl encrypt -o $OUTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type tdf3  $INFILE_GO_MOD
  run sh -c "./otdfctl decrypt --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type tdf3 --kas-allowlist '*' $OUTFILE_GO_MOD"
  assert_success
  assert_output --partial "kasAllowlist is ignored"
}

@test "roundtrip NANO, with allowlist containing platform kas" {
  ./otdfctl encrypt -o $OUTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type nano  $INFILE_GO_MOD
  run sh -c "./otdfctl decrypt --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type nano --kas-allowlist http://localhost:8080/kas $OUTFILE_GO_MOD"
  assert_success
}

@test "roundtrip NANO, with allowlist containing non existent kas (should fail)" {
  ./otdfctl encrypt -o $OUTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type nano $INFILE_GO_MOD
  run sh -c "./otdfctl decrypt --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type nano --kas-allowlist http://not-a-real-kas.com/kas $OUTFILE_GO_MOD"
  assert_failure
  assert_output --partial "KasAllowlist: kas url http://localhost:8080/kas is not allowed"
}

@test "roundtrip NANO, ignoring allowlist" {
  ./otdfctl encrypt -o $OUTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type nano  $INFILE_GO_MOD
  run sh -c "./otdfctl decrypt --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS --tdf-type nano --kas-allowlist '*' $OUTFILE_GO_MOD"
  assert_success
  assert_output --partial "kasAllowlist is ignored"
}

@test "roundtrip TDF3/Nano, not entitled to data, no required obligations returned" {
  # TDF3
  run sh -c "./otdfctl encrypt -o $OUTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS -a $ATTR_OBL_VAL_FQN $INFILE_GO_MOD"
  assert_success
  run sh -c "./otdfctl decrypt --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS $OUTFILE_GO_MOD"
  assert_failure
  refute_output --partial "required obligations"

  # NANO
  run sh -c "./otdfctl encrypt -o $OUTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS -a $ATTR_OBL_VAL_FQN --tdf-type nano $INFILE_GO_MOD"
  assert_success
  run sh -c "./otdfctl decrypt --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS $OUTFILE_GO_MOD"
  assert_failure
  refute_output --partial "required obligations"
}

@test "roundtrip TDF3/Nano, entitled to data, required obligations returned" {
  # Handle subject mapping
  run sh -c "./otdfctl policy subject-mappings create --attribute-value-id $ATTR_OBL_VAL_ID --action read --subject-condition-set-new '[{\"conditionGroups\":[{\"conditions\":[{\"operator\":\"SUBJECT_MAPPING_OPERATOR_ENUM_IN\",\"subjectExternalValues\":[\"opentdf\"],\"subjectExternalSelectorValue\":\".clientId\"}], \"booleanOperator\":\"CONDITION_BOOLEAN_TYPE_ENUM_OR\"}]}]' --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS"
  assert_success

  # TDF3
  run sh -c "./otdfctl encrypt -o $OUTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS -a $ATTR_OBL_VAL_FQN $INFILE_GO_MOD"
  assert_success
  run sh -c "./otdfctl decrypt --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS $OUTFILE_GO_MOD"
  assert_failure
  assert_output --partial "required obligations: [$OBL_VAL_FQN]"

  # NANO
  run sh -c "./otdfctl encrypt -o $OUTFILE_GO_MOD --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS -a $ATTR_OBL_VAL_FQN --tdf-type nano $INFILE_GO_MOD"
  assert_success
  run sh -c "./otdfctl decrypt --host $HOST --tls-no-verify $DEBUG_LEVEL $WITH_CREDS $OUTFILE_GO_MOD"
  assert_failure
  assert_output --partial "required obligations: [$OBL_VAL_FQN]"
}
