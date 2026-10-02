package ocrypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
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

func testFixedField(t *testing.T, hexFixed string) [fixedFieldSize]byte {
	t.Helper()
	b, err := hex.DecodeString(hexFixed)
	require.NoError(t, err)
	require.Len(t, b, fixedFieldSize)
	var fixed [fixedFieldSize]byte
	copy(fixed[:], b)
	return fixed
}

func TestFixedFieldAndCounterFillTheNonce(t *testing.T) {
	assert.Equal(t, GcmStandardNonceSize, fixedFieldSize+sealCounterSize)
}

func TestMaxSealsMatchesMode(t *testing.T) {
	if deterministicIVs() {
		assert.Equal(t, maxDeterministicSeals, MaxSeals())
	} else {
		assert.Equal(t, maxRandomNonceSeals, MaxSeals())
	}
}

// TestAesGcmSealerHeaderLayout pins the exact IV bytes: the fixed field
// verbatim, then the invocation counter big-endian, starting at zero.
func TestAesGcmSealerHeaderLayout(t *testing.T) {
	requireDeterministic(t)

	fixed := testFixedField(t, "0011223344556677")
	sealer, err := newAESGcmSealer(make([]byte, 32), fixed, false, maxDeterministicSeals)
	require.NoError(t, err)

	for n := range uint32(4) {
		header, _, err := sealer.Seal([]byte("payload"))
		require.NoError(t, err, "seal %d", n)

		want := append(fixed[:], 0, 0, 0, 0)
		binary.BigEndian.PutUint32(want[fixedFieldSize:], n)
		assert.Equal(t, want, header, "seal %d", n)
	}

	// And the last value below the ceiling.
	sealer.next.Store(uint64(maxDeterministicSeals - 1))
	header, _, err := sealer.Seal([]byte("payload"))
	require.NoError(t, err)
	assert.Equal(t, []byte{0xff, 0xff, 0xff, 0xfe}, header[fixedFieldSize:])
}

func TestAesGcmSealerRepeatedPlaintextGetsFreshHeader(t *testing.T) {
	requireDeterministic(t)

	sealer, err := NewAESGcmSealer(make([]byte, 32))
	require.NoError(t, err)

	h1, c1, err := sealer.Seal([]byte("same plaintext"))
	require.NoError(t, err)
	h2, c2, err := sealer.Seal([]byte("same plaintext"))
	require.NoError(t, err)

	// What makes a retry safe: the second call never reuses the first's IV.
	assert.Equal(t, h1[:fixedFieldSize], h2[:fixedFieldSize])
	assert.NotEqual(t, h1, h2)
	assert.NotEqual(t, c1, c2)
}

func TestAesGcmSealersOverOneKeyDrawDistinctFixedFields(t *testing.T) {
	requireDeterministic(t)

	key := make([]byte, 32)
	a, err := NewAESGcmSealer(key)
	require.NoError(t, err)
	b, err := NewAESGcmSealer(key)
	require.NoError(t, err)

	ha, _, err := a.Seal([]byte("payload"))
	require.NoError(t, err)
	hb, _, err := b.Seal([]byte("payload"))
	require.NoError(t, err)

	// Both at counter 0; only the fixed field keeps them apart.
	assert.Equal(t, ha[fixedFieldSize:], hb[fixedFieldSize:])
	assert.NotEqual(t, ha[:fixedFieldSize], hb[:fixedFieldSize])
}

// TestAesGcmSealerKnownAnswers pins the construction against fixed vectors
// rather than against itself. The IVs are the decrypt vectors from
// aes_gcm_test.go, split at fixedFieldSize into a fixed field and a counter:
// sealing at that counter under that fixed field must reproduce the IV *and*
// the ciphertext.
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

		var fixed [fixedFieldSize]byte
		copy(fixed[:], iv[:fixedFieldSize])
		counter := binary.BigEndian.Uint32(iv[fixedFieldSize:])

		sealer, err := newAESGcmSealer(key, fixed, false, maxDeterministicSeals)
		require.NoError(t, err)
		sealer.next.Store(uint64(counter))

		header, ciphertext, err := sealer.Seal([]byte(test.plainText))
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

func TestAesGcmSealerExhaustsWithoutWrapping(t *testing.T) {
	requireDeterministic(t)

	const limit = 3
	sealer, err := newAESGcmSealer(make([]byte, 32), testFixedField(t, "0011223344556677"), false, limit)
	require.NoError(t, err)

	for n := range limit {
		_, _, err = sealer.Seal([]byte("payload"))
		require.NoError(t, err, "seal %d", n)
	}
	// Every later call fails; none wraps back to counter 0.
	for range 3 {
		header, ciphertext, err := sealer.Seal([]byte("payload"))
		require.ErrorIs(t, err, ErrSealerExhausted)
		assert.Nil(t, header)
		assert.Nil(t, ciphertext)
	}
}

func TestAesGcmSealerRejectsBadKey(t *testing.T) {
	_, err := NewAESGcmSealer(nil)
	require.ErrorIs(t, err, ErrInvalidKeyData)

	_, err = NewAESGcmSealer(make([]byte, 7))
	require.ErrorIs(t, err, ErrInvalidKeyData)
}

func TestAesGcmSealerZeroValueFails(t *testing.T) {
	var sealer AesGcmSealer
	_, _, err := sealer.Seal([]byte("payload"))
	require.ErrorIs(t, err, ErrInvalidKeyData)

	var nilSealer *AesGcmSealer
	_, _, err = nilSealer.Seal([]byte("payload"))
	require.ErrorIs(t, err, ErrInvalidKeyData)
}

// TestAesGcmSealerConcurrentSeal: racing callers take exactly the counters
// 0..n-1, each once.
func TestAesGcmSealerConcurrentSeal(t *testing.T) {
	requireDeterministic(t)

	fixed := testFixedField(t, "8899aabbccddeeff")
	sealer, err := newAESGcmSealer(make([]byte, 32), fixed, false, maxDeterministicSeals)
	require.NoError(t, err)

	const seals = 128
	headers := make([][]byte, seals)

	var wg sync.WaitGroup
	for i := range seals {
		wg.Go(func() {
			header, _, err := sealer.Seal([]byte("payload"))
			assert.NoError(t, err)
			headers[i] = header
		})
	}
	wg.Wait()

	seen := make(map[uint32]bool, seals)
	for i, header := range headers {
		require.Len(t, header, GcmStandardNonceSize, "seal %d", i)
		require.Equal(t, fixed[:], header[:fixedFieldSize])
		n := binary.BigEndian.Uint32(header[fixedFieldSize:])
		require.Less(t, n, uint32(seals))
		require.False(t, seen[n], "counter %d repeated", n)
		seen[n] = true
	}
}

// --- random-IV fallback -----------------------------------------------------
//
// These exercise the path taken under FIPS 140-3 without needing a FIPS build,
// by constructing the sealer through the injectable form.

func TestRandomFallbackProducesDistinctHeaders(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	fixed := testFixedField(t, "0011223344556677")

	sealer, err := newAESGcmSealer(key, fixed, true, maxRandomNonceSeals)
	require.NoError(t, err)

	aesGcm, err := NewAESGcm(key)
	require.NoError(t, err)

	seen := make(map[string]bool)
	for i := range 32 {
		header, ciphertext, err := sealer.Seal([]byte("payload"))
		require.NoError(t, err)

		// Same shape as the counter path: a 12-byte header the reader takes as
		// the prefix, and a ciphertext ending in the tag.
		require.Len(t, header, GcmStandardNonceSize)
		require.False(t, seen[string(header)], "random header repeated at seal %d", i)
		seen[string(header)] = true

		// The header is *not* built from the fixed field here -- that is the
		// whole difference -- but the wire bytes still round-trip.
		assert.False(t, bytes.HasPrefix(header, fixed[:]))

		plain, err := aesGcm.Decrypt(append(header, ciphertext...))
		require.NoError(t, err)
		assert.Equal(t, "payload", string(plain))
	}
}

func TestRandomFallbackBudgetIsConcurrencySafe(t *testing.T) {
	const budget = 64
	const attempts = 256
	sealer, err := newAESGcmSealer(make([]byte, 32), [fixedFieldSize]byte{}, true, budget)
	require.NoError(t, err)

	var mu sync.Mutex
	var sealed int

	var wg sync.WaitGroup
	for range attempts {
		wg.Go(func() {
			_, _, err := sealer.Seal([]byte("payload"))
			if err == nil {
				mu.Lock()
				sealed++
				mu.Unlock()
				return
			}
			assert.ErrorIs(t, err, ErrSealerExhausted)
		})
	}
	wg.Wait()

	// Exactly the budget gets through no matter how many callers race for it.
	assert.Equal(t, budget, sealed)
}
