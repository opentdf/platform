package ocrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/fips140"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
)

// messagePartSize is the width of the part number inside the AES-GCM IV.
const messagePartSize = 4

// MessageIDSize is the length in bytes of a MessageID. It is whatever is left
// of a standard 12-byte AES-GCM IV once the 32-bit part number is subtracted,
// so the two fields exactly fill the IV.
const MessageIDSize = GcmStandardNonceSize - messagePartSize

// maxDeterministicParts is the exclusive part ceiling for the deterministic
// construction. NIST SP 800-38D permits the full 2^32 values of a 32-bit
// invocation field; we stop one short so the bound itself stays representable
// as a uint32 and the range check can be a plain `part >= max`.
const maxDeterministicParts uint32 = 1<<32 - 1

// maxRandomNonceParts is the exclusive part ceiling -- and, on that path, the
// encryption budget -- when IVs come from an RBG instead. See MaxMessageParts
// for why it is so much smaller than maxDeterministicParts.
const maxRandomNonceParts uint32 = 1 << 26

// probeKeySize is an AES-256 key length, used only for the capability probe.
const probeKeySize = 32

var (
	// ErrInvalidMessageID is returned when a message ID is not MessageIDSize bytes long.
	ErrInvalidMessageID = errors.New("invalid message id")

	// ErrMessagePartsExhausted is returned by Seal for a part number at or
	// above MaxMessageParts. The IV construction never wraps: reusing a part
	// number under one key is the failure this package exists to prevent, so
	// there is nothing to do but fail.
	ErrMessagePartsExhausted = errors.New("message part number exceeds the limit for one key")

	// ErrMessageInvocationsExhausted is returned by Seal when a sealer on the
	// random-IV path has spent its encryption budget. Unlike
	// ErrMessagePartsExhausted this counts *attempts*, not ordinals: on that
	// path every call draws a fresh IV, so retries and re-sealed parts consume
	// budget too.
	ErrMessageInvocationsExhausted = errors.New("message encryption limit exhausted; start a new message with a fresh key")
)

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

// MaxMessageParts is the exclusive upper bound on the part numbers one key may
// seal. Seal range-checks against it, so callers only need it to size their
// own work -- see the SDK's segment-count and segment-size ceilings.
//
// It is 2^32-1 with the deterministic construction, where non-repetition is a
// property of the construction and NIST SP 800-38D 8.3's 2^32 limit on the
// invocation field is the only bound.
//
// On the random-IV fallback it drops to 2^26, and doubles as the number of
// encryptions the key may perform. Uniqueness there is probabilistic: over n
// random 96-bit IVs the chance of a collision is about n^2/2^97, so 2^32
// invocations sit at 2^-33 while 2^26 buys 2^-45 -- a 4096x margin under
// NIST's approved ceiling, at the cost of a proportionally smaller payload.
func MaxMessageParts() uint32 {
	if deterministicIVs() {
		return maxDeterministicParts
	}
	return maxRandomNonceParts
}

// MessageID is the per-message random value shared by every part of a message,
// across every key that message is sealed under. It is the fixed field of the
// deterministic IV construction in NIST SP 800-38D 8.2.1:
//
//	byte  0 .. 7              8  9 10 11
//	     +--------------------+------------+
//	     | MessageID (64b)    | part (32b) |   big-endian
//	     | RBG, per message   | 0,1,2,...  |
//	     +--------------------+------------+
//
// Within one message the part number makes IVs non-repeating by construction.
// *Across* messages there is no such guarantee: uniqueness rests entirely on
// the fixed field being drawn fresh from a cryptographic RBG for each one. A
// MessageID must therefore never be reused for a second message, and never be
// derived from anything predictable.
//
// The bytes are copied on construction, so a caller reusing its randomness
// buffer cannot retroactively change parts that have already been sealed.
type MessageID struct {
	b [MessageIDSize]byte
}

// NewMessageID draws a message ID from r, which must be a cryptographic random
// source -- crypto/rand.Reader in production.
func NewMessageID(r io.Reader) (MessageID, error) {
	var id MessageID
	if _, err := io.ReadFull(r, id.b[:]); err != nil {
		return MessageID{}, fmt.Errorf("reading message id: %w", err)
	}
	return id, nil
}

// MessageIDFromBytes reconstructs a message ID from exactly MessageIDSize
// bytes, copying them. It exists for threading an ID across a package boundary
// and for tests; production code should draw one with NewMessageID.
func MessageIDFromBytes(b []byte) (MessageID, error) {
	if len(b) != MessageIDSize {
		return MessageID{}, fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidMessageID, len(b), MessageIDSize)
	}
	var id MessageID
	copy(id.b[:], b)
	return id, nil
}

// Bytes returns a copy of the message ID.
func (m MessageID) Bytes() []byte {
	out := make([]byte, MessageIDSize)
	copy(out, m.b[:])
	return out
}

// sealerState is the state an AesGcmSealer shares with its copies. Holding it
// behind a pointer keeps the encryption budget shared rather than duplicated
// when the sealer is passed by value.
type sealerState struct {
	aead     cipher.AEAD
	id       MessageID
	maxParts uint32

	// random is set when aead draws its own IV, i.e. the FIPS fallback. In
	// that mode used tracks encryption attempts against maxParts.
	random bool
	used   atomic.Uint32
}

// reserve claims one encryption attempt, saturating at the limit so the
// counter can never wrap back into budget it has already spent. A reserved
// attempt is never returned, even if the encryption that follows fails: the
// budget bounds IV draws, and a failed draw is still a draw.
func (s *sealerState) reserve() error {
	for {
		used := s.used.Load()
		if used >= s.maxParts {
			return ErrMessageInvocationsExhausted
		}
		if s.used.CompareAndSwap(used, used+1) {
			return nil
		}
	}
}

// AesGcmSealer encrypts the parts of one message under one key, deriving each
// part's AES-GCM IV from a message ID and a part number rather than drawing it
// at random (NIST SP 800-38D 8.2.1).
//
// The key and the message ID are fused at construction on purpose. The failure
// this guards against is a caller holding the two as independent values and
// pairing one message's ID with another message's key -- silent IV reuse,
// which under AES-GCM leaks the XOR of the two plaintexts *and* the GHASH
// subkey, and so forges tags for everything else under that key.
//
// A sealer is safe for concurrent use. Copies share one encryption budget.
//
// There is deliberately no Unseal. Readers must keep accepting messages whose
// IVs were drawn at random, so nothing may validate the construction on the
// way back in; the IV is read off the wire as it always was.
type AesGcmSealer struct {
	state *sealerState
}

// NewAESGcmSealer returns a sealer for one message under key, which must be a
// key no other message is sealed under. Reuse the returned sealer for every
// part of that message: a second sealer over the same key keeps its own
// encryption budget and would not see the first one's.
//
// The IV construction is chosen once per process. Where Go refuses
// caller-supplied AES-GCM IVs, or where FIPS 140-3 is enabled and a
// caller-supplied IV would make encryption a non-approved service, the sealer
// falls back to random IVs. The fallback is total and internal -- same API,
// same wire bytes, same call sites -- and surfaces only as the smaller
// MaxMessageParts.
func NewAESGcmSealer(key []byte, id MessageID) (AesGcmSealer, error) {
	return newAESGcmSealer(key, id, !deterministicIVs(), MaxMessageParts())
}

// newAESGcmSealer is the injectable form of NewAESGcmSealer: tests pick the
// random path and a budget small enough to exhaust without touching
// process-global state or performing millions of encryptions.
func newAESGcmSealer(key []byte, id MessageID, random bool, maxParts uint32) (AesGcmSealer, error) {
	if len(key) == 0 {
		return AesGcmSealer{}, ErrInvalidKeyData
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return AesGcmSealer{}, fmt.Errorf("%w: %w", ErrInvalidKeyData, err)
	}

	var aead cipher.AEAD
	if random {
		aead, err = cipher.NewGCMWithRandomNonce(block)
	} else {
		aead, err = cipher.NewGCM(block)
	}
	if err != nil {
		return AesGcmSealer{}, fmt.Errorf("%w: %w", ErrUnsupportedAESGCMConfiguration, err)
	}

	return AesGcmSealer{state: &sealerState{
		aead:     aead,
		id:       id,
		maxParts: maxParts,
		random:   random,
	}}, nil
}

// Seal encrypts plaintext as part `part` of the message, returning the part's
// header followed by its ciphertext-with-tag. The header is the 12-byte
// AES-GCM IV, which every reader of this format expects as the part's prefix;
// the two are returned separately because callers hash them separately.
//
// Part numbers are the caller's uniqueness guarantee and Seal cannot check
// them for you. Never expose encryptions of two different plaintexts under the
// same key, message ID and part.
//
// Returns ErrMessagePartsExhausted at or above MaxMessageParts. On the random
// fallback it also returns ErrMessageInvocationsExhausted -- before
// encrypting, so an exhausted sealer produces nothing -- once the key has made
// MaxMessageParts encryption attempts, counting retries and repeated parts.
func (s AesGcmSealer) Seal(part uint32, plaintext []byte) ([]byte, []byte, error) {
	if s.state == nil {
		return nil, nil, fmt.Errorf("%w: sealer was not constructed with NewAESGcmSealer", ErrInvalidKeyData)
	}
	if part >= s.state.maxParts {
		return nil, nil, fmt.Errorf("%w: part %d is at or above the limit of %d", ErrMessagePartsExhausted, part, s.state.maxParts)
	}

	if s.state.random {
		if err := s.state.reserve(); err != nil {
			return nil, nil, err
		}
		// The IV is drawn inside the AEAD and prepended; split it back off so
		// the caller sees the same two values it gets from the deterministic
		// path. `part` is range-checked above and then deliberately unused.
		//nolint:gosec // G407 reads the nil nonce as hardcoded; NewGCMWithRandomNonce requires it and draws the IV itself.
		sealed := s.state.aead.Seal(nil, nil, plaintext, nil)
		return sealed[:GcmStandardNonceSize], sealed[GcmStandardNonceSize:], nil
	}

	header := make([]byte, GcmStandardNonceSize)
	copy(header, s.state.id.b[:])
	binary.BigEndian.PutUint32(header[MessageIDSize:], part)

	return header, s.state.aead.Seal(nil, header, plaintext, nil), nil
}
