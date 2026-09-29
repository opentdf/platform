package ocrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// sealCounterSize is the width of the invocation counter inside the AES-GCM IV.
const sealCounterSize = 4

// fixedFieldSize is whatever is left of a standard 12-byte AES-GCM IV once the
// 32-bit counter is subtracted, so the two fields exactly fill the IV.
const fixedFieldSize = GcmStandardNonceSize - sealCounterSize

// maxDeterministicSeals is the exclusive seal ceiling for the deterministic
// construction. NIST SP 800-38D permits the full 2^32 values of a 32-bit
// invocation field; we stop one short so the bound itself stays representable
// as a uint32.
const maxDeterministicSeals uint32 = 1<<32 - 1

// maxRandomNonceSeals is the exclusive seal ceiling when IVs come from an RBG
// instead. See MaxSeals for why it is so much smaller than
// maxDeterministicSeals.
const maxRandomNonceSeals uint32 = 1 << 26

// probeKeySize is an AES-256 key length, used only for the capability probe.
const probeKeySize = 32

// ErrSealerExhausted is returned by Seal once a sealer has performed MaxSeals
// encryptions. The counter never wraps: reusing an IV under one key is the
// failure this type exists to prevent, so there is nothing to do but fail.
var ErrSealerExhausted = errors.New("encryption limit for one key exhausted; start a new message with a fresh key")

// deterministicIVs reports whether this process may construct AES-GCM with a
// caller-supplied IV, which is what the deterministic construction requires.
//
// Policy first, then capability. Under GODEBUG=fips140=on cipher.NewGCM still
// succeeds, but Go's FIPS module records the resulting Seal as a non-approved
// service (crypto/internal/fips140/aes/gcm.GCM.Seal calls RecordNonApproved
// where SealWithRandomNonce calls RecordApproved), so a construction probe
// alone would silently keep deterministic IVs in a production FIPS
// deployment. fips140.Enabled reports on, only, and build-time GOFIPS140
// alike. The probe then covers GODEBUG=fips140=only, which refuses
// cipher.NewGCM outright, and any future restriction we have not anticipated;
// falling back is safe whatever the reason.
//
// fips140.Enabled is Go 1.24. fips140.Enforced, which would distinguish the
// modes, is Go 1.26 and would put that floor on a published module.
var deterministicIVs = sync.OnceValue(func() bool {
	if fips140.Enabled() {
		return false
	}
	block, err := aes.NewCipher(make([]byte, probeKeySize))
	if err != nil {
		return false
	}
	_, err = cipher.NewGCM(block)
	return err == nil
})

// MaxSeals is the number of encryptions one AesGcmSealer may perform. Seal
// enforces it, so callers only need it to size their own work -- see the SDK's
// segment-count and segment-size ceilings.
//
// It is 2^32-1 with the deterministic construction, where non-repetition is a
// property of the counter and NIST SP 800-38D 8.3's 2^32 limit on the
// invocation field is the only bound.
//
// On the random-IV fallback it drops to 2^26. Uniqueness there is
// probabilistic: over n random 96-bit IVs the chance of a collision is about
// n^2/2^97, so 2^32 invocations sit at 2^-33 while 2^26 buys 2^-45 -- a 4096x
// margin under NIST's approved ceiling, at the cost of a proportionally
// smaller payload.
func MaxSeals() uint32 {
	if deterministicIVs() {
		return maxDeterministicSeals
	}
	return maxRandomNonceSeals
}

// AesGcmSealer encrypts under one key, constructing each AES-GCM IV from a
// per-sealer random fixed field and an invocation counter (NIST SP 800-38D
// 8.2.1):
//
//	byte  0 .. 7              8  9 10 11
//	     +--------------------+---------------+
//	     | fixed field (64b)  | counter (32b) |   big-endian
//	     | RBG, per sealer    | 0,1,2,...     |
//	     +--------------------+---------------+
//
// The counter lives with the key, so every call takes a fresh IV: retried,
// repeated and out-of-order encryptions can never reuse one, and callers have
// no ordinal to get wrong. The price is that an IV says nothing about which
// segment it encrypts -- concurrent callers take counters in arrival order.
//
// Use one sealer for every encryption under a key. Two sealers over the same
// key count independently, and are kept apart only by their fixed fields
// being drawn at random: a collision needs both 64-bit values to match.
//
// A sealer is safe for concurrent use and must not be copied.
//
// There is deliberately no Unseal. Readers must keep accepting messages whose
// IVs were drawn at random, so nothing may validate the construction on the
// way back in; the IV is read off the wire as it always was.
type AesGcmSealer struct {
	aead  cipher.AEAD
	fixed [fixedFieldSize]byte
	max   uint32

	// random is set when aead draws its own IV, i.e. the FIPS fallback. next
	// then counts encryptions against max without contributing to the IV.
	random bool

	// next is the counter value the following Seal will take. 64 bits so that
	// callers racing past max cannot wrap it back into range.
	next atomic.Uint64
}

// NewAESGcmSealer returns a sealer over key with a fixed field drawn from
// crypto/rand.
//
// The IV construction is chosen once per process. Where Go refuses
// caller-supplied AES-GCM IVs, or where FIPS 140-3 is enabled and a
// caller-supplied IV would make encryption a non-approved service, the sealer
// falls back to random IVs. The fallback is total and internal -- same API,
// same wire bytes, same call sites -- and surfaces only as the smaller
// MaxSeals.
func NewAESGcmSealer(key []byte) (*AesGcmSealer, error) {
	var fixed [fixedFieldSize]byte
	if _, err := io.ReadFull(rand.Reader, fixed[:]); err != nil {
		return nil, fmt.Errorf("reading IV fixed field: %w", err)
	}
	return newAESGcmSealer(key, fixed, !deterministicIVs(), MaxSeals())
}

// newAESGcmSealer is the injectable form of NewAESGcmSealer: tests pin the
// fixed field for known-answer vectors, and pick the random path and a limit
// small enough to exhaust without touching process-global state.
func newAESGcmSealer(key []byte, fixed [fixedFieldSize]byte, random bool, maxSeals uint32) (*AesGcmSealer, error) {
	if len(key) == 0 {
		return nil, ErrInvalidKeyData
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKeyData, err)
	}

	var aead cipher.AEAD
	if random {
		aead, err = cipher.NewGCMWithRandomNonce(block)
	} else {
		aead, err = cipher.NewGCM(block)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsupportedAESGCMConfiguration, err)
	}

	return &AesGcmSealer{aead: aead, fixed: fixed, max: maxSeals, random: random}, nil
}

// Seal encrypts plaintext, returning its header followed by its
// ciphertext-with-tag. The header is the 12-byte AES-GCM IV, which every
// reader of this format expects as the prefix; the two are returned separately
// because callers hash them separately.
//
// Every call consumes one counter value, whether or not the caller goes on to
// use the result. Returns ErrSealerExhausted -- before encrypting, so an
// exhausted sealer produces nothing -- once MaxSeals values are spent.
func (s *AesGcmSealer) Seal(plaintext []byte) ([]byte, []byte, error) {
	if s == nil || s.aead == nil {
		return nil, nil, fmt.Errorf("%w: sealer was not constructed with NewAESGcmSealer", ErrInvalidKeyData)
	}
	n := s.next.Add(1) - 1
	if n >= uint64(s.max) {
		return nil, nil, fmt.Errorf("%w: limit is %d", ErrSealerExhausted, s.max)
	}

	if s.random {
		// The IV is drawn inside the AEAD and prepended; split it back off so
		// the caller sees the same two values it gets from the counter path.
		//nolint:gosec // G407 reads the nil nonce as hardcoded; NewGCMWithRandomNonce requires it and draws the IV itself.
		sealed := s.aead.Seal(nil, nil, plaintext, nil)
		return sealed[:GcmStandardNonceSize], sealed[GcmStandardNonceSize:], nil
	}

	header := make([]byte, GcmStandardNonceSize)
	copy(header, s.fixed[:])
	binary.BigEndian.PutUint32(header[fixedFieldSize:], uint32(n))

	return header, s.aead.Seal(nil, header, plaintext, nil), nil
}
