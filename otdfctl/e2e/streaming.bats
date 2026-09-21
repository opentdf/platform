#!/usr/bin/env bats

# bats file_tags=unattributed_encrypt

# Streaming encrypt/decrypt/inspect (DSPX-4499).
#
# These live outside encrypt-decrypt.bats to keep the streaming concerns --
# spooling, temp output, peak memory -- separate from that file's entitlement
# fixtures. None of the cases here need an entitlement: the round-trips encrypt
# with no attributes, and the failure cases are forced with an unresolvable
# attribute FQN and a KAS allowlist that excludes the platform, neither of which
# requires policy fixtures.
#
# The unattributed_encrypt tag is load-bearing, and is shared with
# encrypt-decrypt.bats. Encrypting with no attributes falls back to the platform
# base key, and key-base.bats sets one pointing at
# https://test-kas-for-base-keys.com, which does not resolve. It cannot put
# things back: a base key can be replaced but not cleared, so its teardown
# leaves the platform unable to decrypt anything unattributed for the rest of
# the run. The tag lets action.yaml run every file that encrypts without
# attributes ahead of the parallel batch rather than racing key-base.bats for a
# slot. That is a workaround, not a fix -- the leak is worth closing on its own.

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

teardown() {
  # The large-payload case below leaves ~3 GiB in BATS_TEST_TMPDIR. An assertion
  # failure aborts the test body, so cleanup placed inline would be skipped
  # exactly when the files are largest. Harmless for every other test here.
  rm -f "$BATS_TEST_TMPDIR/big.bin" "$BATS_TEST_TMPDIR/big.bin.tdf" "$BATS_TEST_TMPDIR/big.out"
}

# assert_no_leftovers fails if anything matches the given glob, naming what it
# found. Listing the paths rather than counting them keeps this portable: BSD
# `wc -l` pads its output to a fixed width, so counting passes on CI's coreutils
# and fails on a developer's macOS for no real reason.
assert_no_leftovers() {
  run bash -c "ls -d $1 2>/dev/null"
  assert_output "" "expected no files matching $1"
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

  assert_no_leftovers "$BATS_TEST_TMPDIR/otdfctl-spool-*"
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
  assert_no_leftovers "$BATS_TEST_TMPDIR/otdfctl-spool-*"
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

  assert_no_leftovers "$BATS_TEST_TMPDIR/.otdfctl.tmp-*"
}

@test "decrypt leaves no output behind when it fails" {
  ./otdfctl encrypt -o "$TDF_OUT" $COMMON "$PLAIN"

  # An allowlist with no entry for the platform KAS fails the rewrap.
  run ./otdfctl decrypt -o "$RESULT" $COMMON --kas-allowlist "https://nowhere.example.com" "$TDF_OUT"
  assert_failure
  [ ! -f "$RESULT" ]

  assert_no_leftovers "$BATS_TEST_TMPDIR/.otdfctl.tmp-*"
}

# The payoff of writing to a temp sibling: a failed decrypt over an existing
# file leaves the old contents intact, where writing straight to the destination
# would have truncated it before discovering the failure.
@test "decrypt leaves an existing output file untouched when it fails" {
  ./otdfctl encrypt -o "$TDF_OUT" $COMMON "$PLAIN"
  printf 'do not clobber me\n' >"$RESULT"

  run ./otdfctl decrypt -o "$RESULT" $COMMON --kas-allowlist "https://nowhere.example.com" "$TDF_OUT"
  assert_failure

  run cat "$RESULT"
  assert_output "do not clobber me"
}

# -o at a path a rename cannot stand in for is written through directly, the way
# os.Create did. /dev/null is the case people actually use, to time a decrypt or
# to check one succeeds without keeping the plaintext.
@test "decrypt to /dev/null succeeds and leaves the device node alone" {
  ./otdfctl encrypt -o "$TDF_OUT" $COMMON "$PLAIN"

  run ./otdfctl decrypt -o /dev/null $COMMON "$TDF_OUT"
  assert_success
  [ -c /dev/null ]
}

# The other side of writing through: -o at a symlink resolving to the input
# would truncate the input at open, before it has been read. Both commands open
# their input first, so both could destroy a file they were only asked to read.
@test "decrypt refuses an output symlink pointing at its input" {
  ./otdfctl encrypt -o "$TDF_OUT" $COMMON "$PLAIN"
  ln -s "$TDF_OUT" "$BATS_TEST_TMPDIR/alias.tdf"

  run ./otdfctl decrypt -o "$BATS_TEST_TMPDIR/alias.tdf" $COMMON "$TDF_OUT"
  assert_failure
  assert_output --partial "output would overwrite the input"

  # The TDF is still a TDF, not a zero-byte file.
  ./otdfctl decrypt -o "$RESULT" $COMMON "$TDF_OUT"
  diff "$PLAIN" "$RESULT"
}

@test "encrypt refuses an output symlink pointing at its input" {
  ln -s "$PLAIN" "$BATS_TEST_TMPDIR/alias.tdf"

  run ./otdfctl encrypt -o "$BATS_TEST_TMPDIR/alias.tdf" $COMMON "$PLAIN"
  assert_failure
  assert_output --partial "output would overwrite the input"

  run cat "$PLAIN"
  assert_output "$SECRET_TEXT"
}

# The point of DSPX-4499: peak RSS is bounded by segment size, not payload size.
# Needs GNU time for 'Maximum resident set size'; BSD/shell time cannot report it.
@test "encrypt and decrypt peak memory stay bounded on a large payload" {
  # '|| true' so that finding neither binary reaches the skip below: bats runs
  # tests under errexit, and a bare failing assignment would abort the test with
  # no message rather than skipping it.
  GNU_TIME=$(command -v gtime || command -v /usr/bin/time || true)
  if [ -z "$GNU_TIME" ] || ! $GNU_TIME -v true 2>&1 | grep -q "Maximum resident set size"; then
    # In CI this must not skip. It is the only test that demonstrates the fix,
    # and a silent skip would let a return to whole-payload buffering through.
    # action.yaml installs the 'time' package for exactly this reason.
    [ -z "$CI" ] || fail "GNU time is required in CI: install the 'time' package"
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

  echo "peak RSS: encrypt ${enc_kb} KB, decrypt ${dec_kb} KB"
  # 512 MiB leaves generous headroom over the ~66 MiB a 1 MiB payload used, while
  # still failing loudly on any return to whole-payload buffering.
  [ "$enc_kb" -lt 524288 ]
  [ "$dec_kb" -lt 524288 ]
}
