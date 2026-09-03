#!/usr/bin/env bats

# bats file_tags=payload_streaming

# Streaming encrypt/decrypt/inspect (DSPX-4499).
#
# These live outside encrypt-decrypt.bats deliberately. That file carries a
# file-level skip pending the namespaced-subject-mappings migration, so anything
# added to it would not run. None of the cases here need an entitlement: the
# round-trips encrypt with no attributes, and the two failure cases are forced
# with an unresolvable attribute FQN and a KAS allowlist that excludes the
# platform, neither of which requires policy fixtures.
#
# The payload_streaming tag exists so action.yaml can run this file before the
# parallel batch, and it is load-bearing. Encrypting with no attributes falls
# back to the platform base key, and key-base.bats sets one pointing at
# https://test-kas-for-base-keys.com, which does not resolve. It cannot put
# things back: a base key can be replaced but not cleared, so its teardown
# leaves the platform unable to decrypt anything unattributed for the rest of
# the run. encrypt-decrypt.bats would hit the same wall today if it were not
# skipped. Running before key-base.bats is a workaround, not a fix -- the leak
# is worth closing on its own.

setup_file() {
  export HOST=http://localhost:8080
  export CREDSFILE=creds.json
  echo -n '{"clientId":"opentdf","clientSecret":"secret"}' >"$CREDSFILE"
  export WITH_CREDS="--with-client-creds-file $CREDSFILE"
  export COMMON="--host $HOST --tls-no-verify $WITH_CREDS"

  export SECRET_TEXT="my special streaming secret"
}

setup() {
  bats_load_library bats-support
  bats_load_library bats-assert

  PLAIN="$BATS_TEST_TMPDIR/payload.txt"
  TDF_OUT="$BATS_TEST_TMPDIR/payload.txt.tdf"
  RESULT="$BATS_TEST_TMPDIR/payload.out"
  printf '%s\n' "$SECRET_TEXT" >"$PLAIN"
}

# Baseline: both ends are seekable files, so nothing is spooled.
@test "roundtrip TDF3, no attributes, file to file" {
  ./otdfctl encrypt -o "$TDF_OUT" $COMMON "$PLAIN"
  ./otdfctl decrypt -o "$RESULT" $COMMON "$TDF_OUT"
  diff "$PLAIN" "$RESULT"
}

@test "roundtrip TDF3, no attributes, file to stdout" {
  ./otdfctl encrypt $COMMON "$PLAIN" >"$TDF_OUT"
  ./otdfctl decrypt -o "$RESULT" $COMMON "$TDF_OUT"
  diff "$PLAIN" "$RESULT"
}

# The fully piped form is the one documented in docs/man/encrypt/_index.md, and
# the one with no seekable input on either end.
@test "roundtrip TDF3, stdin to stdout, fully piped" {
  run bash -c "echo '$SECRET_TEXT' | ./otdfctl encrypt $COMMON | ./otdfctl decrypt $COMMON"
  assert_success
  assert_output --partial "$SECRET_TEXT"
}

# A TDF's manifest lives at the end of the archive, so decrypt spools a pipe to
# disk to get a seekable view. Verify it round-trips and removes the spool.
@test "roundtrip TDF3, decrypt reading the TDF from stdin" {
  ./otdfctl encrypt -o "$TDF_OUT" $COMMON "$PLAIN"
  # Scope TMPDIR to this test so the leftover check cannot see another test's
  # spool, and cannot be fooled by one either.
  TMPDIR="$BATS_TEST_TMPDIR" ./otdfctl decrypt $COMMON <"$TDF_OUT" >"$RESULT"
  diff "$PLAIN" "$RESULT"

  run bash -c "ls $BATS_TEST_TMPDIR/otdfctl-spool-* 2>/dev/null | wc -l"
  assert_output "0"
}

@test "inspect reads a TDF from a file and from stdin" {
  ./otdfctl encrypt -o "$TDF_OUT" $COMMON "$PLAIN"

  run bash -c "./otdfctl inspect $COMMON '$TDF_OUT' | jq -r '.manifest.protocol'"
  assert_success
  assert_output "zip"

  run bash -c "TMPDIR='$BATS_TEST_TMPDIR' ./otdfctl inspect $COMMON < '$TDF_OUT' | jq -r '.manifest.protocol'"
  assert_success
  assert_output "zip"

  # inspect spools piped input too, and exits via os.Exit on the success path.
  run bash -c "ls $BATS_TEST_TMPDIR/otdfctl-spool-* 2>/dev/null | wc -l"
  assert_output "0"
}

# An empty redirect is 'no input', not 'a zero-byte payload'. Presence is
# detected with a peek rather than a read, so this must stay an error.
@test "encrypt rejects empty stdin" {
  run bash -c "./otdfctl encrypt $COMMON < /dev/null"
  assert_failure
}

@test "decrypt rejects empty stdin" {
  run bash -c "./otdfctl decrypt $COMMON < /dev/null"
  assert_failure
}

# Output goes to a temp sibling and is renamed only on success, so a failed run
# must leave neither a partial .tdf nor the temp file behind.
@test "encrypt leaves no output behind when it fails" {
  run bash -c "echo '$SECRET_TEXT' | ./otdfctl encrypt -o '$TDF_OUT' $COMMON -a 'https://streaming-does-not-exist.io/attr/nope/value/nope'"
  assert_failure
  [ ! -f "$TDF_OUT" ]

  run bash -c "ls $BATS_TEST_TMPDIR/.payload.txt.tdf.tmp-* 2>/dev/null | wc -l"
  assert_output "0"
}

@test "decrypt leaves no output behind when it fails" {
  ./otdfctl encrypt -o "$TDF_OUT" $COMMON "$PLAIN"

  # An allowlist with no entry for the platform KAS fails the rewrap.
  run ./otdfctl decrypt -o "$RESULT" $COMMON --kas-allowlist "https://nowhere.example.com" "$TDF_OUT"
  assert_failure
  [ ! -f "$RESULT" ]

  run bash -c "ls $BATS_TEST_TMPDIR/.payload.out.tmp-* 2>/dev/null | wc -l"
  assert_output "0"
}

# The point of DSPX-4499: peak RSS is bounded by segment size, not payload size.
# Needs GNU time for 'Maximum resident set size'; BSD/shell time cannot report it.
@test "encrypt and decrypt peak memory stay bounded on a large payload" {
  GNU_TIME=$(command -v gtime || command -v /usr/bin/time)
  if [ -z "$GNU_TIME" ] || ! $GNU_TIME -v true 2>&1 | grep -q "Maximum resident set size"; then
    skip "GNU time not available"
  fi

  local big="$BATS_TEST_TMPDIR/big.bin"
  local bigtdf="$BATS_TEST_TMPDIR/big.bin.tdf"
  local bigout="$BATS_TEST_TMPDIR/big.out"
  local enclog="$BATS_TEST_TMPDIR/enc.log"
  local declog="$BATS_TEST_TMPDIR/dec.log"

  # 1 GiB. The buffered implementation peaked around 3.6x this for both commands.
  dd if=/dev/zero of="$big" bs=1048576 count=1024 status=none

  $GNU_TIME -v -o "$enclog" ./otdfctl encrypt -o "$bigtdf" $COMMON "$big"
  $GNU_TIME -v -o "$declog" ./otdfctl decrypt -o "$bigout" $COMMON "$bigtdf"
  cmp "$big" "$bigout"

  local enc_kb dec_kb
  enc_kb=$(grep "Maximum resident set size" "$enclog" | grep -o '[0-9]*')
  dec_kb=$(grep "Maximum resident set size" "$declog" | grep -o '[0-9]*')
  rm -f "$big" "$bigtdf" "$bigout"

  echo "peak RSS: encrypt ${enc_kb} KB, decrypt ${dec_kb} KB"
  # 512 MiB leaves generous headroom over the ~66 MiB a 1 MiB payload used, while
  # still failing loudly on any return to whole-payload buffering.
  [ "$enc_kb" -lt 524288 ]
  [ "$dec_kb" -lt 524288 ]
}
