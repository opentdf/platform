package sdk

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
)

// KeySplitter converts attribute values plus a DEK into one or more
// key splits, each addressed to one or more KAS servers. Injected on
// the chunked Writer so tests can substitute an identity splitter
// without touching real attribute grants.
//
// Experimental: not part of the stable SDK API; may change or be removed.
type KeySplitter interface {
	// Split evaluates the ABAC policy expressed by attrs, produces N
	// splits of dek per the resulting boolean expression, and returns
	// each split alongside the KAS public keys it must be wrapped to.
	Split(ctx context.Context, attrs []*policy.Value, dek []byte, defaultKAS *policy.SimpleKasKey) (*SplitResult, error)
}

// Split is one XOR share of the DEK bound to one or more KAS
// servers.
//
// Experimental: not part of the stable SDK API; may change or be removed.
type Split struct {
	// Data is this share of the DEK: the value that, XOR'd with every
	// other share in the result, reproduces the DEK. With a single
	// split -- what DefaultKeySplitter always produces -- there is
	// nothing to XOR against, so it is the DEK verbatim.
	Data []byte

	// ID uniquely identifies this split within a SplitResult. It is
	// what the reader groups shares on, so it is required once there
	// is more than one split and must be distinct across them. With a
	// single split there is nothing to distinguish, and it is
	// conventionally left empty.
	ID string

	// KASURLs lists every KAS that can unwrap this split. Multiple
	// URLs mean any one KAS is sufficient (OR semantics).
	KASURLs []string
}

// SplitResult is what KeySplitter.Split returns: the shares plus the
// KAS wrapping keys needed to encrypt each share into a KeyAccess
// object.
//
// Experimental: not part of the stable SDK API; may change or be removed.
type SplitResult struct {
	// KASPublicKeys maps KAS URL to the wrapping key to use for that
	// URL. Populated for every URL referenced by any split.
	KASPublicKeys map[string]KASPublicKey

	// Splits are the DEK shares in emission order.
	Splits []Split
}

// Validate reports whether the result can be turned into a key access
// array that a reader can actually reconstruct the DEK from. The
// chunked writer calls it before wrapping anything, and third-party
// KeySplitter implementations can call it as a self-check.
//
// Every rule here exists because breaking it produces a TDF that is
// accepted at creation and fails later in a way that does not name the
// cause. The reader derives the set of splits it must collect from the
// key access objects present in the manifest, so a share that never
// reached the manifest is invisible to its completeness check: it XORs
// what it has, reconstructs the wrong DEK, and reports a root
// signature failure, which reads as tampering. By then the plaintext
// is gone.
//
// Validate sees only the shares, so it is half the contract: it can
// confirm they agree with each other, but not that they agree with the
// key. VerifyReconstruction is the other half.
//
// Experimental: not part of the stable SDK API; may change or be removed.
func (r *SplitResult) Validate() error {
	if r == nil || len(r.Splits) == 0 {
		return errors.New("chunked: splitter returned no splits")
	}

	ids := make(map[string]struct{}, len(r.Splits))
	shareLen := len(r.Splits[0].Data)
	for i, split := range r.Splits {
		// A share is one XOR operand. A short or empty one silently
		// leaves part of the DEK unmasked, since the reader XORs only
		// as many bytes as the share carries.
		if len(split.Data) == 0 {
			return fmt.Errorf("chunked: split %d (id %q) has no share data", i, split.ID)
		}
		if len(split.Data) != shareLen {
			return fmt.Errorf("chunked: split %d (id %q) has a %d-byte share; split 0 has %d and all shares must agree",
				i, split.ID, len(split.Data), shareLen)
		}

		// A single split carries no sid, because there is nothing to
		// distinguish it from. With more than one, sid is what the
		// reader groups on: an empty or duplicated id collapses two
		// shares into one group, and the second is never XOR'd in.
		if len(r.Splits) > 1 && split.ID == "" {
			return fmt.Errorf("chunked: split %d has an empty id; ids are required when there is more than one split", i)
		}
		if _, dup := ids[split.ID]; dup {
			return fmt.Errorf("chunked: split id %q is used by more than one split", split.ID)
		}
		ids[split.ID] = struct{}{}

		if len(split.KASURLs) == 0 {
			return fmt.Errorf("chunked: split %d (id %q) names no KAS; its share could never be unwrapped", i, split.ID)
		}
		for _, url := range split.KASURLs {
			pk, ok := r.KASPublicKeys[url]
			if !ok {
				// The same sentinel the mainline writer uses for an
				// unresolved KAS, so callers can match one error whichever
				// path produced it.
				return fmt.Errorf("chunked: splitID:[%s], kas:[%s]: no entry in KASPublicKeys: %w", split.ID, url, errKasPubKeyMissing)
			}
			if err := pk.validate(url); err != nil {
				return err
			}
		}
	}
	return nil
}

// VerifyReconstruction reports whether the shares actually rebuild
// dek. It is the half of the splitter's contract Validate cannot
// check: Validate sees only the shares, so it can confirm they agree
// with each other but not that they agree with the key.
//
// Mirrors the self-check the XOR splitter performs on its own output.
// A splitter that returns shares of the wrong length, or of the right
// length and the wrong value, produces a TDF that wraps, uploads and
// rewraps without complaint, then fails at the reader's root signature
// check -- reported as tampering, after the plaintext is gone.
//
// With a single split there is nothing to XOR against, so the share
// must equal dek verbatim; the loop below expresses that as the
// degenerate case rather than special-casing it.
//
// Experimental: not part of the stable SDK API; may change or be removed.
func (r *SplitResult) VerifyReconstruction(dek []byte) error {
	if r == nil || len(r.Splits) == 0 {
		return errors.New("chunked: splitter returned no splits")
	}
	if len(dek) == 0 {
		return errors.New("chunked: cannot verify split reconstruction against an empty DEK")
	}

	reconstructed := make([]byte, len(dek))
	for i, split := range r.Splits {
		// Length is checked against the DEK, not against Splits[0] as Validate
		// does: shares that agree with each other but are shorter than the key
		// leave its tail unmasked, and the reader XORs only as many bytes as
		// each share carries.
		if len(split.Data) != len(dek) {
			return fmt.Errorf("chunked: split %d (id %q) has a %d-byte share; every share must be %d bytes, the length of the DEK",
				i, split.ID, len(split.Data), len(dek))
		}
		subtle.XORBytes(reconstructed, reconstructed, split.Data)
	}

	// Constant-time, and deliberately silent about where the mismatch is. The
	// XOR splitter's equivalent reports the first differing byte index, which
	// is a prefix-match oracle over key material in exchange for nothing: the
	// caller cannot act on the offset.
	if subtle.ConstantTimeCompare(reconstructed, dek) != 1 {
		return errors.New("chunked: the splits do not XOR back to the DEK; a reader that collected every share would reconstruct the wrong key and report a root signature failure")
	}
	return nil
}

// KASPublicKey is the wrapping key resolved for one KAS URL.
//
// Experimental: not part of the stable SDK API; may change or be removed.
type KASPublicKey struct {
	// Algorithm identifies the wrapping scheme. It must be one of the
	// values ocrypto.ParseKeyType accepts, e.g. ocrypto.RSA2048Key or
	// ocrypto.EC256Key -- use PolicyAlgorithmToKeyType to derive it
	// from a policy.Algorithm. An unrecognized value falls through
	// createKeyAccess's RSA default, which sniffs the PEM rather than
	// honoring the declared scheme, and produces a KAO that cannot be
	// decrypted; SplitResult.Validate rejects it first.
	Algorithm ocrypto.KeyType

	// KID identifies which key at that KAS to use.
	KID string

	// PEM is the wrapping key in PEM form.
	PEM string

	// URL of the KAS.
	URL string
}

// validate checks one resolved wrapping key. mapKey is the
// KASPublicKeys key it was found under, which is reported in errors
// and must match URL: the KAO is built from URL, so the two
// disagreeing means the split names one KAS and the manifest points a
// reader at another.
func (k KASPublicKey) validate(mapKey string) error {
	if k.PEM == "" {
		return fmt.Errorf("chunked: kas:[%s]: %w", mapKey, errKasPubKeyMissing)
	}
	if k.URL == "" {
		return fmt.Errorf("chunked: kas %q has an empty URL field; every key access object built from it would name no endpoint", mapKey)
	}
	if k.URL != mapKey {
		return fmt.Errorf("chunked: kas %q is keyed under %q but carries URL %q; key access objects are built from the URL field", mapKey, mapKey, k.URL)
	}
	if _, err := ocrypto.ParseKeyType(string(k.Algorithm)); err != nil {
		return fmt.Errorf("chunked: kas %q: %w", mapKey, err)
	}
	return nil
}

// toKASInfo adapts the splitter's wrapping-key descriptor to the
// KASInfo shape consumed by createKeyAccess. Default is not carried
// over; it plays no part in building a key access object.
func (k KASPublicKey) toKASInfo() KASInfo {
	return KASInfo{
		URL:       k.URL,
		PublicKey: k.PEM,
		KID:       k.KID,
		Algorithm: string(k.Algorithm),
	}
}

// ErrSplitterRequiresDefaultKAS is returned by the default key
// splitter when no default KAS was supplied. The default splitter is
// single-KAS only; multi-attribute splits require injecting a full
// splitter via WithChunkedKeySplitter.
var ErrSplitterRequiresDefaultKAS = errors.New("chunked: default splitter requires a default KAS; supply WithChunkedDefaultKAS or WithChunkedKeySplitter")

// ErrSplitterUnsupportedAlgorithm is returned by the default key
// splitter when the default KAS advertises a key algorithm this SDK
// has no wrapping scheme for.
var ErrSplitterUnsupportedAlgorithm = errors.New("chunked: unsupported KAS key algorithm")

// DefaultKeySplitter returns a single-KAS single-split splitter.
// Attributes are ignored; the entire DEK is bound to the caller's
// default KAS. Callers with attribute-based key splits requirements
// should inject their own splitter via WithChunkedKeySplitter.
//
// Experimental: not part of the stable SDK API; may change or be removed.
func DefaultKeySplitter() KeySplitter { return &singleKASSplitter{} }

// singleKASSplitter binds the full DEK to a single KAS. Attributes
// are ignored; splitting into multi-KAS OR-of-AND shares is beyond
// this default's scope.
type singleKASSplitter struct{}

// Split returns one split covering the full DEK, addressed to
// defaultKAS. Errors when defaultKAS is nil, has no public key or
// URI, or names an algorithm this SDK cannot wrap for.
func (s *singleKASSplitter) Split(_ context.Context, _ []*policy.Value, dek []byte, defaultKAS *policy.SimpleKasKey) (*SplitResult, error) {
	if defaultKAS == nil || defaultKAS.GetPublicKey() == nil || defaultKAS.GetPublicKey().GetPem() == "" {
		return nil, ErrSplitterRequiresDefaultKAS
	}
	url := defaultKAS.GetKasUri()
	if url == "" {
		// An empty URI would still produce a PEM-valid split, but the
		// resulting KeyAccess.KasURL leaves a reader with no endpoint to
		// send a rewrap request to.
		return nil, fmt.Errorf("%w: kas uri is empty", ErrSplitterRequiresDefaultKAS)
	}

	// Reject an unmappable algorithm here rather than letting the empty
	// string formatAlg returns on failure reach createKeyAccess. There
	// it selects the RSA branch by default, and ocrypto.FromPublicPEM
	// sniffs the PEM instead of honoring that choice: an EC or ML-KEM
	// key parses successfully and wraps, but the KAO is left claiming
	// keyType "wrapped" with no ephemeral public key. That produces a
	// TDF nothing can decrypt, which is far worse to debug than a
	// failure at creation time.
	//
	// SplitResult.Validate enforces the same rule for every splitter,
	// including injected ones. Keeping the check here too lets the
	// error name ErrSplitterUnsupportedAlgorithm and the offending
	// policy.Algorithm, which the generic check cannot see.
	alg, err := PolicyAlgorithmToKeyType(defaultKAS.GetPublicKey().GetAlgorithm())
	if err != nil {
		return nil, fmt.Errorf("%w: kas %s: %w", ErrSplitterUnsupportedAlgorithm, url, err)
	}

	share := make([]byte, len(dek))
	copy(share, dek)
	return &SplitResult{
		KASPublicKeys: map[string]KASPublicKey{
			url: {
				Algorithm: alg,
				KID:       defaultKAS.GetPublicKey().GetKid(),
				PEM:       defaultKAS.GetPublicKey().GetPem(),
				URL:       url,
			},
		},
		Splits: []Split{{
			Data:    share,
			KASURLs: []string{url},
		}},
	}, nil
}
