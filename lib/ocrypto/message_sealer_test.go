package ocrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requireDeterministic skips a test that can only run where Go permits
// caller-supplied AES-GCM IVs -- i.e. not under GODEBUG=fips140=only, and not
// with FIPS 140-3 enabled, where NewAESGcmSealer falls back to random IVs.
func requireDeterministic(t *testing.T) {
	t.Helper()
	if !deterministicIVs() {
		t.Skip("deterministic IV construction unavailable in this build/mode")
	}
}

func testMessageID(t *testing.T, hexID string) MessageID {
	t.Helper()
	b, err := hex.DecodeString(hexID)
	require.NoError(t, err)
	id, err := MessageIDFromBytes(b)
	require.NoError(t, err)
	return id
}

func TestMessageIDSizeFillsTheNonce(t *testing.T) {
	assert.Equal(t, GcmStandardNonceSize, MessageIDSize+messagePartSize)
}

func TestMessageIDFromBytesRejectsWrongLength(t *testing.T) {
	for _, n := range []int{0, 1, 7, 9, 12, 16} {
		_, err := MessageIDFromBytes(make([]byte, n))
		require.ErrorIs(t, err, ErrInvalidMessageID, "length %d", n)
	}
}

func TestMessageIDFromBytesCopies(t *testing.T) {
	buf := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	id, err := MessageIDFromBytes(buf)
	require.NoError(t, err)

	// A caller reusing its randomness buffer must not change the ID.
	for i := range buf {
		buf[i] = 0xFF
	}
	assert.Equal(t, []byte{1, 2, 3, 4, 5, 6, 7, 8}, id.Bytes())

	// Nor may a caller mutate it through Bytes.
	out := id.Bytes()
	out[0] = 0x00
	assert.Equal(t, byte(1), id.Bytes()[0])
}

func TestNewMessageID(t *testing.T) {
	id, err := NewMessageID(rand.Reader)
	require.NoError(t, err)
	assert.Len(t, id.Bytes(), MessageIDSize)

	other, err := NewMessageID(rand.Reader)
	require.NoError(t, err)
	assert.NotEqual(t, id.Bytes(), other.Bytes())

	_, err = NewMessageID(strings.NewReader("short"))
	require.Error(t, err)
}

func TestMaxMessagePartsMatchesMode(t *testing.T) {
	if deterministicIVs() {
		assert.Equal(t, maxDeterministicParts, MaxMessageParts())
	} else {
		assert.Equal(t, maxRandomNonceParts, MaxMessageParts())
	}
}

// TestAesGcmSealerHeaderLayout pins the exact IV bytes: the message ID
// verbatim, then the part number big-endian.
func TestAesGcmSealerHeaderLayout(t *testing.T) {
	requireDeterministic(t)

	id := testMessageID(t, "0011223344556677")
	sealer, err := NewAESGcmSealer(make([]byte, 32), id)
	require.NoError(t, err)

	for _, part := range []uint32{0, 1, 2, 0x01020304, maxDeterministicParts - 1} {
		header, _, err := sealer.Seal(part, []byte("payload"))
		require.NoError(t, err, "part %d", part)

		want := append(id.Bytes(), 0, 0, 0, 0)
		binary.BigEndian.PutUint32(want[MessageIDSize:], part)
		assert.Equal(t, want, header, "part %d", part)
	}
}

func TestAesGcmSealerHeadersAreDistinctPerPart(t *testing.T) {
	requireDeterministic(t)

	id, err := NewMessageID(rand.Reader)
	require.NoError(t, err)
	sealer, err := NewAESGcmSealer(make([]byte, 32), id)
	require.NoError(t, err)

	seen := make(map[string]bool)
	for part := range uint32(64) {
		header, _, err := sealer.Seal(part, []byte("payload"))
		require.NoError(t, err)
		require.False(t, seen[string(header)], "header repeated at part %d", part)
		seen[string(header)] = true
	}
}

// TestAesGcmSealerKnownAnswers pins the construction against fixed vectors
// rather than against itself. The IVs are the decrypt vectors from
// aes_gcm_test.go, split at MessageIDSize into a message ID and a part number:
// sealing that part under that ID must reproduce the IV *and* the ciphertext.
func TestAesGcmSealerKnownAnswers(t *testing.T) {
	requireDeterministic(t)

	tests := []struct {
		symmetricKey string
		iv           string
		cipherText   string
		plainText    string
	}{
		{
			"66af5c10753139c6161d0f0eee125bbc9545d6704d64890e396c5c8d4f4820d4",
			"d2c32fa42f97341e97a33b58",
			"a89d8e00e3bacacc2ed13bbc602a191d60584af3a933",
			"virtru",
		},
		{
			"120fba31c537d99ade0a0a8c8e6df535f7de86fb6e1d5948317b4596982a5e1b",
			"591a6f1e947dd887d72610c8",
			"83aaba876616c02bfaf5120c785ac92c",
			"",
		},
		{
			"9895f395913a3cfd974ea53c0735030c7df4602d699c986afdc5fdd10071c0a5",
			"71c291bc41aacde6e0b57e7d",
			`7b19b61dc053c3ffeaba57195356025a05600b071a4618912917681480f1eb62afb9ecc
ff7a90d6cba96275bd52bd8d6afa4fcbae6a400ce7033e7abd58e301ab9b4a9c3e7f4c0f55256d250faf8ce0c22bdd
9b79654842a6186df98831289eeee66fac014390a4363034d64e44fc9a2c0e0231d69c78f0a8049d8b458579041858
d4f6da9f39542d2287d20d19dd99db339c038e3b6e1720c97ff73adda5ca4fac7da70c7d53f97a5aa346e93af`,
			`In cryptography, Galois/Counter Mode (GCM)[1] is a mode of operation
for symmetric-key cryptographic block ciphers which is
widely adopted for its performance`,
		},
	}

	for _, test := range tests {
		key, err := hex.DecodeString(test.symmetricKey)
		require.NoError(t, err)
		iv, err := hex.DecodeString(test.iv)
		require.NoError(t, err)
		wantCipher, err := hex.DecodeString(strings.ReplaceAll(test.cipherText, "\n", ""))
		require.NoError(t, err)

		id, err := MessageIDFromBytes(iv[:MessageIDSize])
		require.NoError(t, err)
		part := binary.BigEndian.Uint32(iv[MessageIDSize:])

		sealer, err := NewAESGcmSealer(key, id)
		require.NoError(t, err)

		header, ciphertext, err := sealer.Seal(part, []byte(test.plainText))
		require.NoError(t, err)
		assert.Equal(t, iv, header)
		assert.Equal(t, wantCipher, ciphertext)

		// And the existing reader path still opens header||ciphertext.
		aesGcm, err := NewAESGcm(key)
		require.NoError(t, err)
		plain, err := aesGcm.Decrypt(append(header, ciphertext...))
		require.NoError(t, err)
		assert.Equal(t, test.plainText, string(plain))
	}
}

func TestAesGcmSealerIsDeterministic(t *testing.T) {
	requireDeterministic(t)

	id, err := NewMessageID(rand.Reader)
	require.NoError(t, err)
	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)

	sealer, err := NewAESGcmSealer(key, id)
	require.NoError(t, err)

	h1, c1, err := sealer.Seal(7, []byte("same plaintext"))
	require.NoError(t, err)
	h2, c2, err := sealer.Seal(7, []byte("same plaintext"))
	require.NoError(t, err)

	assert.Equal(t, h1, h2)
	assert.Equal(t, c1, c2)

	// A second sealer over the same key and ID agrees, which is what makes a
	// retry of a failed part safe.
	other, err := NewAESGcmSealer(key, id)
	require.NoError(t, err)
	h3, c3, err := other.Seal(7, []byte("same plaintext"))
	require.NoError(t, err)
	assert.Equal(t, h1, h3)
	assert.Equal(t, c1, c3)
}

func TestAesGcmSealerRejectsExhaustedParts(t *testing.T) {
	id, err := NewMessageID(rand.Reader)
	require.NoError(t, err)
	sealer, err := NewAESGcmSealer(make([]byte, 32), id)
	require.NoError(t, err)

	maxParts := MaxMessageParts()
	_, _, err = sealer.Seal(maxParts-1, []byte("payload"))
	require.NoError(t, err)

	parts := []uint32{maxParts}
	if maxParts < math.MaxUint32 {
		parts = append(parts, maxParts+1, math.MaxUint32)
	}
	for _, part := range parts {
		_, _, err = sealer.Seal(part, []byte("payload"))
		require.ErrorIs(t, err, ErrMessagePartsExhausted, "part %d", part)
	}
}

func TestAesGcmSealerRejectsBadKey(t *testing.T) {
	id, err := NewMessageID(rand.Reader)
	require.NoError(t, err)

	_, err = NewAESGcmSealer(nil, id)
	require.ErrorIs(t, err, ErrInvalidKeyData)

	_, err = NewAESGcmSealer(make([]byte, 7), id)
	require.ErrorIs(t, err, ErrInvalidKeyData)
}

func TestAesGcmSealerZeroValueFails(t *testing.T) {
	var sealer AesGcmSealer
	_, _, err := sealer.Seal(1, []byte("payload"))
	require.ErrorIs(t, err, ErrInvalidKeyData)
}

func TestAesGcmSealerConcurrentSeal(t *testing.T) {
	id, err := NewMessageID(rand.Reader)
	require.NoError(t, err)
	sealer, err := NewAESGcmSealer(make([]byte, 32), id)
	require.NoError(t, err)

	const parts = 128
	headers := make([][]byte, parts)

	var wg sync.WaitGroup
	for part := range uint32(parts) {
		wg.Go(func() {
			header, _, err := sealer.Seal(part, []byte("payload"))
			assert.NoError(t, err)
			headers[part] = header
		})
	}
	wg.Wait()

	seen := make(map[string]bool, parts)
	for part, header := range headers {
		require.Len(t, header, GcmStandardNonceSize, "part %d", part)
		require.False(t, seen[string(header)], "header repeated at part %d", part)
		seen[string(header)] = true
	}
}

// --- random-IV fallback -----------------------------------------------------
//
// These exercise the path taken under FIPS 140-3 without needing a FIPS build,
// by constructing the sealer through the injectable form.

func TestRandomFallbackProducesDistinctHeaders(t *testing.T) {
	id, err := NewMessageID(rand.Reader)
	require.NoError(t, err)
	key := make([]byte, 32)
	_, err = rand.Read(key)
	require.NoError(t, err)

	sealer, err := newAESGcmSealer(key, id, true, maxRandomNonceParts)
	require.NoError(t, err)

	aesGcm, err := NewAESGcm(key)
	require.NoError(t, err)

	seen := make(map[string]bool)
	for part := range uint32(32) {
		header, ciphertext, err := sealer.Seal(part, []byte("payload"))
		require.NoError(t, err)

		// Same shape as the deterministic path: a 12-byte header the reader
		// takes as the part prefix, and a ciphertext ending in the tag.
		require.Len(t, header, GcmStandardNonceSize)
		require.False(t, seen[string(header)], "random header repeated at part %d", part)
		seen[string(header)] = true

		// The header is *not* derived from the ID and part here -- that is the
		// whole difference -- but the wire bytes still round-trip.
		assert.False(t, bytes.HasPrefix(header, id.Bytes()))

		plain, err := aesGcm.Decrypt(append(header, ciphertext...))
		require.NoError(t, err)
		assert.Equal(t, "payload", string(plain))
	}
}

func TestRandomFallbackRejectsExhaustedParts(t *testing.T) {
	id, err := NewMessageID(rand.Reader)
	require.NoError(t, err)
	sealer, err := newAESGcmSealer(make([]byte, 32), id, true, maxRandomNonceParts)
	require.NoError(t, err)

	_, _, err = sealer.Seal(maxRandomNonceParts, []byte("payload"))
	require.ErrorIs(t, err, ErrMessagePartsExhausted)
}

// TestRandomFallbackBudgetCountsAttempts is the difference between the two
// exhaustion errors: on this path re-sealing one part still spends budget,
// because each call draws a fresh IV.
func TestRandomFallbackBudgetCountsAttempts(t *testing.T) {
	id, err := NewMessageID(rand.Reader)
	require.NoError(t, err)

	const budget = 4
	sealer, err := newAESGcmSealer(make([]byte, 32), id, true, budget)
	require.NoError(t, err)

	for i := range budget {
		_, _, err = sealer.Seal(0, []byte("payload"))
		require.NoError(t, err, "attempt %d", i)
	}

	// Part 0 is well inside the ordinal limit; it is the budget that is gone.
	_, _, err = sealer.Seal(0, []byte("payload"))
	require.ErrorIs(t, err, ErrMessageInvocationsExhausted)
	require.NotErrorIs(t, err, ErrMessagePartsExhausted)
}

func TestRandomFallbackBudgetIsSharedByCopies(t *testing.T) {
	id, err := NewMessageID(rand.Reader)
	require.NoError(t, err)

	const budget = 2
	sealer, err := newAESGcmSealer(make([]byte, 32), id, true, budget)
	require.NoError(t, err)
	copied := sealer

	_, _, err = sealer.Seal(0, []byte("payload"))
	require.NoError(t, err)
	_, _, err = copied.Seal(1, []byte("payload"))
	require.NoError(t, err)

	_, _, err = copied.Seal(0, []byte("payload"))
	require.ErrorIs(t, err, ErrMessageInvocationsExhausted)
}

func TestRandomFallbackBudgetIsConcurrencySafe(t *testing.T) {
	id, err := NewMessageID(rand.Reader)
	require.NoError(t, err)

	const budget = 64
	const attempts = 256
	sealer, err := newAESGcmSealer(make([]byte, 32), id, true, budget)
	require.NoError(t, err)

	var mu sync.Mutex
	var sealed int

	var wg sync.WaitGroup
	for range attempts {
		wg.Go(func() {
			if _, _, err := sealer.Seal(0, []byte("payload")); err == nil {
				mu.Lock()
				sealed++
				mu.Unlock()
			}
		})
	}
	wg.Wait()

	// Saturating, never wrapping: exactly the budget gets through no matter
	// how many callers race for it.
	assert.Equal(t, budget, sealed)
}
