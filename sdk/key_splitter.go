package sdk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
)

// KeySplitter converts attribute values plus a DEK into one or more
// key splits, each addressed to one or more KAS servers. Injected on
// the chunked Writer so tests can substitute an identity splitter
// without touching real attribute grants.
type KeySplitter interface {
	// Split evaluates the ABAC policy expressed by attrs, produces N
	// splits of dek per the resulting boolean expression, and returns
	// each split alongside the KAS public keys it must be wrapped to.
	Split(ctx context.Context, attrs []*policy.Value, dek []byte, defaultKAS *policy.SimpleKasKey) (*SplitResult, error)
}

// Split is one XOR share of the DEK bound to one or more KAS
// servers.
type Split struct {
	// Data is the split share (XOR of the DEK with the other shares).
	Data []byte

	// ID uniquely identifies this split within a SplitResult. Empty
	// when the result contains only one split (single-KAO TDF).
	ID string

	// KASURLs lists every KAS that can unwrap this split. Multiple
	// URLs mean any one KAS is sufficient (OR semantics).
	KASURLs []string
}

// SplitResult is what KeySplitter.Split returns: the shares plus the
// KAS wrapping keys needed to encrypt each share into a KeyAccess
// object.
type SplitResult struct {
	// KASPublicKeys maps KAS URL to the wrapping key to use for that
	// URL. Populated for every URL referenced by any split.
	KASPublicKeys map[string]KASPublicKey

	// Splits are the DEK shares in emission order.
	Splits []Split
}

// KASPublicKey is the wrapping key resolved for one KAS URL.
type KASPublicKey struct {
	// Algorithm identifies the wrapping scheme (e.g. "rsa", "ec").
	Algorithm string

	// KID identifies which key at that KAS to use.
	KID string

	// PEM is the wrapping key in PEM form.
	PEM string

	// URL of the KAS.
	URL string
}

// ErrSplitterRequiresDefaultKAS is returned by the default key
// splitter when no default KAS was supplied. The default splitter is
// single-KAS only; multi-attribute splits require injecting a full
// splitter via WithChunkedKeySplitter.
var ErrSplitterRequiresDefaultKAS = errors.New("chunked: default splitter requires a default KAS; supply WithChunkedDefaultKAS or WithChunkedKeySplitter")

// DefaultKeySplitter returns a single-KAS single-split splitter.
// Attributes are ignored; the entire DEK is bound to the caller's
// default KAS. Callers with attribute-based key splits requirements
// should inject their own splitter via WithChunkedKeySplitter.
func DefaultKeySplitter() KeySplitter { return &singleKASSplitter{} }

// singleKASSplitter binds the full DEK to a single KAS. Attributes
// are ignored; splitting into multi-KAS OR-of-AND shares is beyond
// this default's scope.
type singleKASSplitter struct{}

// Split returns one split covering the full DEK, addressed to
// defaultKAS. Errors when defaultKAS is nil or has no public key.
func (s *singleKASSplitter) Split(_ context.Context, _ []*policy.Value, dek []byte, defaultKAS *policy.SimpleKasKey) (*SplitResult, error) {
	if defaultKAS == nil || defaultKAS.GetPublicKey() == nil || defaultKAS.GetPublicKey().GetPem() == "" {
		return nil, ErrSplitterRequiresDefaultKAS
	}
	url := defaultKAS.GetKasUri()
	share := make([]byte, len(dek))
	copy(share, dek)
	return &SplitResult{
		KASPublicKeys: map[string]KASPublicKey{
			url: {
				Algorithm: algorithmPolicyToString(defaultKAS.GetPublicKey().GetAlgorithm()),
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

// keyAccessResolver turns a DEK into the two manifest fields that
// bind it to policy: the base64-encoded policy object and the key
// access objects wrapping the DEK to each KAS. The writer holds one;
// SDK.CreateTDF resolves its key access up front and supplies a
// staticKeyAccess, while the public chunked path defers to a
// KeySplitter at Finalize time.
type keyAccessResolver interface {
	resolve(ctx context.Context, dek []byte, cfg *ChunkedFinalizeConfig) (string, []KeyAccess, error)
}

// splitShare is one XOR share of the DEK together with every KAS able
// to unwrap it. Several KAS entries on one share mean any of them
// suffices (OR semantics); several shares mean all are required (AND).
type splitShare struct {
	// id names the share in the manifest ("sid"). Empty when the TDF
	// has a single share.
	id string

	// data is the share itself.
	data []byte

	// kases are the wrapping targets for this share.
	kases []KASInfo
}

// staticKeyAccess returns key access objects resolved ahead of time.
type staticKeyAccess struct {
	// kaos are the pre-built key access objects.
	kaos []KeyAccess

	// policy is the base64-encoded policy object the kaos are bound to.
	policy string
}

func (r staticKeyAccess) resolve(_ context.Context, _ []byte, _ *ChunkedFinalizeConfig) (string, []KeyAccess, error) {
	return r.policy, r.kaos, nil
}

// splitterKeyAccess adapts a public KeySplitter to keyAccessResolver.
type splitterKeyAccess struct {
	// splitter maps attributes plus the DEK onto KAS-addressed shares.
	splitter KeySplitter
}

func (r splitterKeyAccess) resolve(ctx context.Context, dek []byte, cfg *ChunkedFinalizeConfig) (string, []KeyAccess, error) {
	splits, err := r.splitter.Split(ctx, cfg.attributes, dek, cfg.defaultKAS)
	if err != nil {
		return "", nil, err
	}
	if splits == nil || len(splits.Splits) == 0 {
		return "", nil, errors.New("no splits produced")
	}

	shares := make([]splitShare, 0, len(splits.Splits))
	for _, split := range splits.Splits {
		share := splitShare{id: split.ID, data: split.Data}
		for _, url := range split.KASURLs {
			// A URL the splitter left out of KASPublicKeys yields an
			// empty PEM, which buildKeyAccessObjects rejects.
			pk := splits.KASPublicKeys[url]
			share.kases = append(share.kases, KASInfo{
				URL:       url,
				PublicKey: pk.PEM,
				KID:       pk.KID,
				Algorithm: pk.Algorithm,
			})
		}
		shares = append(shares, share)
	}

	fqns := make([]string, 0, len(cfg.attributes))
	for _, v := range cfg.attributes {
		fqns = append(fqns, v.GetFqn())
	}
	return resolvePolicyAndKeyAccess(fqns, shares, cfg.encryptedMetadata)
}

// resolvePolicyAndKeyAccess builds the policy document the DEK is bound to and wraps
// every share to its KAS targets, returning the two manifest fields that bind a DEK to
// policy. Shared by SDK.CreateTDF's KAO template path and the chunked writer's
// KeySplitter path, so both emit byte-identical policy for the same attributes.
func resolvePolicyAndKeyAccess(fqns []string, shares []splitShare, metadata string) (string, []KeyAccess, error) {
	policyObj, err := createPolicyObjectFromFQNs(fqns)
	if err != nil {
		return "", nil, fmt.Errorf("fail to create policy object:%w", err)
	}
	policyObjectAsStr, err := json.Marshal(policyObj)
	if err != nil {
		return "", nil, fmt.Errorf("json.Marshal failed:%w", err)
	}
	base64Policy := string(ocrypto.Base64Encode(policyObjectAsStr))

	kaos, err := buildKeyAccessObjects(shares, base64Policy, metadata)
	if err != nil {
		return "", nil, err
	}
	return base64Policy, kaos, nil
}

// buildKeyAccessObjects wraps every share to each of its KAS targets,
// emitting the manifest's keyAccess array in share order.
func buildKeyAccessObjects(shares []splitShare, base64Policy, metadata string) ([]KeyAccess, error) {
	var kaos []KeyAccess
	for _, share := range shares {
		policyBinding := createPolicyBinding(share.data, base64Policy)

		var encryptedMetadata string
		if metadata != "" {
			var err error
			encryptedMetadata, err = encryptMetadata(share.data, metadata)
			if err != nil {
				return nil, err
			}
		}

		for _, kasInfo := range share.kases {
			if kasInfo.PublicKey == "" {
				return nil, fmt.Errorf("splitID:[%s], kas:[%s]: %w", share.id, kasInfo.URL, errKasPubKeyMissing)
			}
			keyAccess, err := createKeyAccess(kasInfo, share.data, policyBinding, encryptedMetadata, share.id)
			if err != nil {
				return nil, err
			}
			kaos = append(kaos, keyAccess)
		}
	}
	if len(kaos) == 0 {
		return nil, errors.New("no key access objects generated")
	}
	return kaos, nil
}

// splitDEK returns count XOR shares of dek. Every share but the last
// is random; the last absorbs the parity so the shares XOR back to dek.
func splitDEK(dek []byte, count int, rand io.Reader) ([][]byte, error) {
	if count <= 0 {
		return nil, errors.New("no key splits requested")
	}
	shares := make([][]byte, count)
	parity := make([]byte, len(dek))
	copy(parity, dek)
	for i := 0; i < count-1; i++ {
		share := make([]byte, len(dek))
		if _, err := io.ReadFull(rand, share); err != nil {
			return nil, fmt.Errorf("generate key split failed: %w", err)
		}
		for j, b := range share {
			parity[j] ^= b
		}
		shares[i] = share
	}
	shares[count-1] = parity
	return shares, nil
}

// algorithmPolicyToString maps a policy.Algorithm enum to the
// ocrypto.KeyType string form used when picking a wrap scheme.
// Unknown enums (including PQ / KEM variants not yet wired through
// chunkedWrapKeyWithPublicKey) return the empty string; the caller
// treats that as "unsupported algorithm."
func algorithmPolicyToString(a policy.Algorithm) string {
	if kt, err := PolicyAlgorithmToKeyType(a); err == nil {
		return string(kt)
	}
	return ""
}
