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

# A TDF's manifest lives at the end of the archive, so decrypt needs a seekable
# view of it. A pipe cannot give one, so it is spooled to disk. Verify it
# round-trips and removes the spool.
@test "roundtrip TDF3, decrypt reading the TDF from a pipe" {
  ./otdfctl encrypt -o "$TDF_OUT" $COMMON "$PLAIN"
  # Scope TMPDIR to this test so the leftover check cannot see another test's
  # spool, and cannot be fooled by one either.
  run bash -c "TMPDIR='$BATS_TEST_TMPDIR' cat '$TDF_OUT' | ./otdfctl decrypt $COMMON >'$RESULT'"
  assert_success
  diff "$PLAIN" "$RESULT"

  assert_no_leftovers "$BATS_TEST_TMPDIR/otdfctl-spool-*"
}

# A redirect from a regular file seeks already, so there is nothing to spool.
# What this pins is the round-trip; that no spool is created at all is not
# observable from out here, and TestOpenSeekableDoesNotSpoolARegularFileStdin
# covers it.
@test "roundtrip TDF3, decrypt reading the TDF from a redirect" {
  ./otdfctl encrypt -o "$TDF_OUT" $COMMON "$PLAIN"
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

  assert_no_leftovers "$BATS_TEST_TMPDIR/.payload.txt.tdf.tmp-*"
}

@test "decrypt leaves no output behind when it fails" {
  ./otdfctl encrypt -o "$TDF_OUT" $COMMON "$PLAIN"

  # An allowlist with no entry for the platform KAS fails the rewrap.
  run ./otdfctl decrypt -o "$RESULT" $COMMON --kas-allowlist "https://nowhere.example.com" "$TDF_OUT"
  assert_failure
  [ ! -f "$RESULT" ]

  assert_no_leftovers "$BATS_TEST_TMPDIR/.payload.out.tmp-*"
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

# assert_payload_first checks the premise extra_field_len rests on: the archive
# opens with the payload's local file header. If the SDK ever reorders entries,
# this fails here rather than letting extra_field_len read two arbitrary bytes.
assert_payload_first() {
  [ -s "$1" ] || fail "$1 is missing or empty"
  # 'PK\3\4' as decimal bytes; xargs normalizes od's column padding, which BSD
  # and GNU space differently.
  run bash -c "od -An -tu1 -N4 '$1' | xargs"
  assert_output "80 75 3 4"
  # The filename follows the 30-byte header. Always '0.payload', so 9 bytes.
  run bash -c "dd if='$1' bs=1 skip=30 count=9 status=none"
  assert_output "0.payload"
}

# extra_field_len reads the extra field length at offset 28 of the payload's
# local file header: non-zero for ZIP64, which carries the extended information
# extra field there, zero for ZIP32. od -tu1 rather than -tu2 because only GNU od
# can be told the endianness.
#
# It fails rather than returning a number when it cannot read a full header --
# empty output would evaluate to 0, which is what the ZIP32 assertions pass on.
extra_field_len() {
  local lo hi
  [ -s "$1" ] || { echo "extra_field_len: $1 is missing or empty" >&2; return 1; }
  read -r lo hi <<<"$(od -An -tu1 -j28 -N2 "$1")"
  if [ -z "$lo" ] || [ -z "$hi" ]; then
    echo "extra_field_len: $1 is too short to hold a local file header" >&2
    return 1
  fi
  echo $((lo + hi * 256))
}

# Encrypting from a pipe no longer spools, so the payload cannot be measured and
# the archive has to be ZIP64; anything measurable stays ZIP32. The layout is what
# to assert on, since both forms round-trip and a quiet return to spooling would
# show up nowhere else.
@test "encrypt measures a file and streams a pipe" {
  ./otdfctl encrypt -o "$TDF_OUT" $COMMON "$PLAIN"
  assert_payload_first "$TDF_OUT"
  [ "$(extra_field_len "$TDF_OUT")" -eq 0 ]

  # --mime-type skips detection entirely, which is the one thing that could have
  # wrapped the file and cost it the ZIP32 layout. It must not change the layout.
  local typed_tdf="$BATS_TEST_TMPDIR/typed.tdf"
  ./otdfctl encrypt -o "$typed_tdf" $COMMON --mime-type text/plain "$PLAIN"
  assert_payload_first "$typed_tdf"
  [ "$(extra_field_len "$typed_tdf")" -eq 0 ]

  # A redirect arrives on stdin but seeks, so it stays ZIP32. Dropping the spool
  # must not turn the whole of stdin into a stream.
  local redirected_tdf="$BATS_TEST_TMPDIR/redirected.tdf"
  run bash -c "./otdfctl encrypt $COMMON <'$PLAIN' >'$redirected_tdf'"
  assert_success
  assert_payload_first "$redirected_tdf"
  [ "$(extra_field_len "$redirected_tdf")" -eq 0 ]

  local piped_tdf="$BATS_TEST_TMPDIR/piped.tdf"
  run bash -c "echo '$SECRET_TEXT' | ./otdfctl encrypt $COMMON >'$piped_tdf'"
  assert_success
  assert_payload_first "$piped_tdf"
  [ "$(extra_field_len "$piped_tdf")" -gt 0 ]

  ./otdfctl decrypt -o "$RESULT" $COMMON "$piped_tdf"
  run cat "$RESULT"
  assert_output "$SECRET_TEXT"
}

# Process substitution is the shape a type assertion gets wrong: bash hands us
# /dev/fd/63, which opens as an *os.File and so satisfies io.Seeker, and then
# every seek returns ESPIPE. Only unit tests with a hand-written fake model that,
# so it is worth an end-to-end case.
@test "encrypt streams a process substitution" {
  local subst_tdf="$BATS_TEST_TMPDIR/subst.tdf"
  run bash -c "./otdfctl encrypt $COMMON <(cat '$PLAIN') >'$subst_tdf'"
  assert_success
  assert_payload_first "$subst_tdf"
  # Unmeasurable, so ZIP64, exactly like a pipe.
  [ "$(extra_field_len "$subst_tdf")" -gt 0 ]

  ./otdfctl decrypt -o "$RESULT" $COMMON "$subst_tdf"
  diff "$PLAIN" "$RESULT"

  # --mime-type skips detection, so the ESPIPE is hit later, by the SDK's own
  # sizing attempt rather than by detectMimeType's.
  local typed_subst_tdf="$BATS_TEST_TMPDIR/subst-typed.tdf"
  run bash -c "./otdfctl encrypt $COMMON --mime-type text/plain <(cat '$PLAIN') >'$typed_subst_tdf'"
  assert_success
  assert_payload_first "$typed_subst_tdf"
  [ "$(extra_field_len "$typed_subst_tdf")" -gt 0 ]

  ./otdfctl decrypt -o "$RESULT" $COMMON "$typed_subst_tdf"
  diff "$PLAIN" "$RESULT"
}

# 3 MiB clears the SDK's 2 MiB default segment size, so the archive spans several
# segments whose hashes are combined on the way out and verified on the way back
# in. A pipe also feeds the encoder short reads at segment boundaries; a file
# does not.
@test "encrypt streams a multi-segment pipe" {
  local big="$BATS_TEST_TMPDIR/multi.bin"
  local bigtdf="$BATS_TEST_TMPDIR/multi.tdf"
  local bigout="$BATS_TEST_TMPDIR/multi.out"
  dd if=/dev/urandom of="$big" bs=1048576 count=3 status=none

  # A real pipe, not a redirect: a redirect from a regular file seeks, and would
  # be measured and written as ZIP32.
  run bash -c "cat '$big' | ./otdfctl encrypt $COMMON >'$bigtdf'"
  assert_success
  assert_payload_first "$bigtdf"
  [ "$(extra_field_len "$bigtdf")" -gt 0 ]

  ./otdfctl decrypt -o "$bigout" $COMMON "$bigtdf"
  cmp "$big" "$bigout"
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
