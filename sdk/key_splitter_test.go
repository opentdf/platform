package sdk

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A PEM is required to get past the earlier nil/empty checks; these
// tests never wrap anything, so its contents only need to parse as a
// PEM block, not match the advertised algorithm.
const splitterTestPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjhRuJUUiBTLBmYuIJ6vGz1L8k+d3
0j9RGVOM3G8mUJDPuOwLZLwJqDGmvHkyTa8k3lWK8v5nOSGN3nOJ8t2gEg==
-----END PUBLIC KEY-----`

func TestSingleKASSplitterRequiresDefaultKAS(t *testing.T) {
	for _, tc := range []struct {
		name string
		kas  *policy.SimpleKasKey
	}{
		{"nil KAS", nil},
		{"nil public key", &policy.SimpleKasKey{KasUri: "https://kas.example.com"}},
		{"empty PEM", &policy.SimpleKasKey{
			KasUri:    "https://kas.example.com",
			PublicKey: &policy.SimpleKasPublicKey{Algorithm: policy.Algorithm_ALGORITHM_RSA_2048, Kid: "k1"},
		}},
		{"empty KAS URI", &policy.SimpleKasKey{
			PublicKey: &policy.SimpleKasPublicKey{Algorithm: policy.Algorithm_ALGORITHM_RSA_2048, Kid: "k1", Pem: splitterTestPEM},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			splitter := DefaultKeySplitter()
			res, err := splitter.Split(context.Background(), nil, []byte("0123456789abcdef"), tc.kas)

			require.ErrorIs(t, err, ErrSplitterRequiresDefaultKAS)
			assert.Nil(t, res)
		})
	}
}

func TestSingleKASSplitterRejectsUnmappableAlgorithm(t *testing.T) {
	// An algorithm the SDK has no wrapping scheme for used to yield the
	// empty string, which createKeyAccess reads as a request for RSA.
	// The resulting KAO claims keyType "wrapped" with no ephemeral
	// public key, so the TDF is built successfully and then cannot be
	// decrypted by anything. Fail at creation time instead.
	for _, tc := range []struct {
		name string
		alg  policy.Algorithm
	}{
		{"unspecified", policy.Algorithm_ALGORITHM_UNSPECIFIED},
		{"out of range", policy.Algorithm(9999)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			splitter := DefaultKeySplitter()
			res, err := splitter.Split(context.Background(), nil, []byte("0123456789abcdef"),
				&policy.SimpleKasKey{
					KasUri: "https://kas.example.com",
					PublicKey: &policy.SimpleKasPublicKey{
						Algorithm: tc.alg,
						Kid:       "k1",
						Pem:       splitterTestPEM,
					},
				})

			require.ErrorIs(t, err, ErrSplitterUnsupportedAlgorithm)
			assert.Nil(t, res)
			// The KAS URL is in the message so an operator can tell which
			// of several KASes is misconfigured.
			assert.Contains(t, err.Error(), "https://kas.example.com")
		})
	}
}

func TestSingleKASSplitterAcceptsKnownAlgorithms(t *testing.T) {
	for _, tc := range []struct {
		name string
		alg  policy.Algorithm
		want ocrypto.KeyType
	}{
		{"rsa 2048", policy.Algorithm_ALGORITHM_RSA_2048, ocrypto.RSA2048Key},
		{"ec p256", policy.Algorithm_ALGORITHM_EC_P256, ocrypto.EC256Key},
	} {
		t.Run(tc.name, func(t *testing.T) {
			splitter := DefaultKeySplitter()
			dek := []byte("0123456789abcdef")
			res, err := splitter.Split(context.Background(), nil, dek,
				&policy.SimpleKasKey{
					KasUri: "https://kas.example.com",
					PublicKey: &policy.SimpleKasPublicKey{
						Algorithm: tc.alg,
						Kid:       "k1",
						Pem:       splitterTestPEM,
					},
				})

			require.NoError(t, err)
			require.Len(t, res.Splits, 1)
			assert.Equal(t, dek, res.Splits[0].Data)
			assert.Equal(t, tc.want, res.KASPublicKeys["https://kas.example.com"].Algorithm)
		})
	}
}

// TestSplitResultValidate covers the contract every KeySplitter must
// meet, including the ones it is injected for. Each case below is a
// result that would be accepted at creation and fail only at decryption
// time, with an error naming nothing useful -- the reader derives the
// set of shares it needs from the key access objects present in the
// manifest, so a share that never reached the manifest is invisible to
// its completeness check and surfaces as a root signature failure.
func TestSplitResultValidate(t *testing.T) {
	const (
		urlA = "https://kas-a.example.com"
		urlB = "https://kas-b.example.com"
	)
	keyA := KASPublicKey{Algorithm: ocrypto.RSA2048Key, KID: "a", PEM: splitterTestPEM, URL: urlA}
	keyB := KASPublicKey{Algorithm: ocrypto.RSA2048Key, KID: "b", PEM: splitterTestPEM, URL: urlB}
	share := func(b byte) []byte { return []byte{b, b, b, b} }

	for _, tc := range []struct {
		name    string
		in      *SplitResult
		wantSub string
	}{
		{
			name: "single split",
			in: &SplitResult{
				KASPublicKeys: map[string]KASPublicKey{urlA: keyA},
				Splits:        []Split{{Data: share(1), KASURLs: []string{urlA}}},
			},
		},
		{
			name: "two splits, one KAS each",
			in: &SplitResult{
				KASPublicKeys: map[string]KASPublicKey{urlA: keyA, urlB: keyB},
				Splits: []Split{
					{ID: "s0", Data: share(1), KASURLs: []string{urlA}},
					{ID: "s1", Data: share(2), KASURLs: []string{urlB}},
				},
			},
		},
		{
			name: "one split, two KASes (OR group)",
			in: &SplitResult{
				KASPublicKeys: map[string]KASPublicKey{urlA: keyA, urlB: keyB},
				Splits:        []Split{{Data: share(1), KASURLs: []string{urlA, urlB}}},
			},
		},
		{
			name:    "nil result",
			in:      nil,
			wantSub: "no splits",
		},
		{
			name:    "no splits",
			in:      &SplitResult{KASPublicKeys: map[string]KASPublicKey{urlA: keyA}},
			wantSub: "no splits",
		},
		{
			name: "empty share",
			in: &SplitResult{
				KASPublicKeys: map[string]KASPublicKey{urlA: keyA},
				Splits:        []Split{{Data: nil, KASURLs: []string{urlA}}},
			},
			wantSub: "no share data",
		},
		{
			// The reader XORs only as many bytes as each share carries,
			// so a short one leaves the tail of the DEK unmasked.
			name: "shares of different lengths",
			in: &SplitResult{
				KASPublicKeys: map[string]KASPublicKey{urlA: keyA, urlB: keyB},
				Splits: []Split{
					{ID: "s0", Data: share(1), KASURLs: []string{urlA}},
					{ID: "s1", Data: []byte{2, 2}, KASURLs: []string{urlB}},
				},
			},
			wantSub: "all shares must agree",
		},
		{
			// sid is what the reader groups on; an empty one on a
			// multi-split result collapses the two into one group.
			name: "empty id with more than one split",
			in: &SplitResult{
				KASPublicKeys: map[string]KASPublicKey{urlA: keyA, urlB: keyB},
				Splits: []Split{
					{Data: share(1), KASURLs: []string{urlA}},
					{ID: "s1", Data: share(2), KASURLs: []string{urlB}},
				},
			},
			wantSub: "empty id",
		},
		{
			name: "duplicate ids",
			in: &SplitResult{
				KASPublicKeys: map[string]KASPublicKey{urlA: keyA, urlB: keyB},
				Splits: []Split{
					{ID: "same", Data: share(1), KASURLs: []string{urlA}},
					{ID: "same", Data: share(2), KASURLs: []string{urlB}},
				},
			},
			wantSub: "more than one split",
		},
		{
			name: "split names no KAS",
			in: &SplitResult{
				KASPublicKeys: map[string]KASPublicKey{urlA: keyA},
				Splits: []Split{
					{ID: "s0", Data: share(1), KASURLs: []string{urlA}},
					{ID: "s1", Data: share(2)},
				},
			},
			wantSub: "names no KAS",
		},
		{
			name: "split names an unresolved KAS",
			in: &SplitResult{
				KASPublicKeys: map[string]KASPublicKey{urlA: keyA},
				Splits:        []Split{{Data: share(1), KASURLs: []string{urlA, urlB}}},
			},
			wantSub: urlB,
		},
		{
			name: "resolved KAS has no PEM",
			in: &SplitResult{
				KASPublicKeys: map[string]KASPublicKey{urlA: {Algorithm: ocrypto.RSA2048Key, URL: urlA}},
				Splits:        []Split{{Data: share(1), KASURLs: []string{urlA}}},
			},
			wantSub: "kas public key is missing",
		},
		{
			// KeyAccess.KasURL is built from the URL field, so a blank
			// one points the reader at no endpoint at all.
			name: "resolved KAS has no URL field",
			in: &SplitResult{
				KASPublicKeys: map[string]KASPublicKey{urlA: {Algorithm: ocrypto.RSA2048Key, PEM: splitterTestPEM}},
				Splits:        []Split{{Data: share(1), KASURLs: []string{urlA}}},
			},
			wantSub: "empty URL field",
		},
		{
			name: "URL field disagrees with the map key",
			in: &SplitResult{
				KASPublicKeys: map[string]KASPublicKey{urlA: {Algorithm: ocrypto.RSA2048Key, PEM: splitterTestPEM, URL: urlB}},
				Splits:        []Split{{Data: share(1), KASURLs: []string{urlA}}},
			},
			wantSub: "key access objects are built from the URL field",
		},
		{
			// An unparseable algorithm falls through createKeyAccess's
			// RSA default, which sniffs the PEM instead of honoring the
			// declared scheme and emits a KAO nothing can decrypt.
			name: "unparseable algorithm",
			in: &SplitResult{
				KASPublicKeys: map[string]KASPublicKey{urlA: {Algorithm: "rsa:9999", PEM: splitterTestPEM, URL: urlA}},
				Splits:        []Split{{Data: share(1), KASURLs: []string{urlA}}},
			},
			wantSub: "rsa:9999",
		},
		{
			// The zero value of the field, so this is what an injected
			// splitter that simply never set Algorithm produces.
			name: "empty algorithm",
			in: &SplitResult{
				KASPublicKeys: map[string]KASPublicKey{urlA: {PEM: splitterTestPEM, URL: urlA}},
				Splits:        []Split{{Data: share(1), KASURLs: []string{urlA}}},
			},
			wantSub: "unrecognized key type",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.in.Validate()
			if tc.wantSub == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)
		})
	}
}

// TestSplitResultVerifyReconstruction covers the half of the contract
// Validate cannot reach. Every case below passes Validate -- the shares
// are non-empty, agree on length with each other, and carry distinct
// ids -- and still yields a key no reader can rebuild, which surfaces
// only as a root signature failure at decryption.
func TestSplitResultVerifyReconstruction(t *testing.T) {
	dek := []byte("0123456789abcdef")

	// xorShares splits dek into n shares that close the XOR exactly,
	// the shape a correct multi-KAS splitter produces.
	xorShares := func(n int) []Split {
		out := make([]Split, n)
		accum := make([]byte, len(dek))
		for i := range n - 1 {
			share := make([]byte, len(dek))
			for j := range share {
				share[j] = byte(i*31 + j*7 + 1)
				accum[j] ^= share[j]
			}
			out[i] = Split{ID: fmt.Sprintf("s%d", i), Data: share}
		}
		last := make([]byte, len(dek))
		for j := range last {
			last[j] = dek[j] ^ accum[j]
		}
		out[n-1] = Split{ID: fmt.Sprintf("s%d", n-1), Data: last}
		return out
	}

	// mutate flips one byte of the first share, so the shares still
	// agree on length and only the value is wrong.
	mutate := func(splits []Split) []Split {
		splits[0].Data[0] ^= 0xFF
		return splits
	}

	for _, tc := range []struct {
		name    string
		in      *SplitResult
		dek     []byte
		wantSub string
	}{
		{
			name: "single split equal to the DEK",
			in:   &SplitResult{Splits: []Split{{Data: slices.Clone(dek)}}},
			dek:  dek,
		},
		{
			name: "real multi-way XOR",
			in:   &SplitResult{Splits: xorShares(3)},
			dek:  dek,
		},
		{
			name:    "single split with the wrong value",
			in:      &SplitResult{Splits: mutate([]Split{{Data: slices.Clone(dek)}})},
			dek:     dek,
			wantSub: "do not XOR back to the DEK",
		},
		{
			name:    "multi-way XOR that does not close",
			in:      &SplitResult{Splits: mutate(xorShares(3))},
			dek:     dek,
			wantSub: "do not XOR back to the DEK",
		},
		{
			// Mutually-agreeing short shares pass Validate, which only
			// compares shares against each other, and leave the DEK's
			// tail unmasked.
			name: "short shares",
			in: &SplitResult{Splits: []Split{
				{ID: "s0", Data: slices.Clone(dek[:8])},
				{ID: "s1", Data: make([]byte, 8)},
			}},
			dek:     dek,
			wantSub: "the length of the DEK",
		},
		{
			name:    "nil receiver",
			in:      nil,
			dek:     dek,
			wantSub: "no splits",
		},
		{
			name:    "no splits",
			in:      &SplitResult{},
			dek:     dek,
			wantSub: "no splits",
		},
		{
			// Refused rather than passed: an empty DEK would make every
			// share trivially "reconstruct" nothing.
			name:    "empty DEK",
			in:      &SplitResult{Splits: []Split{{Data: slices.Clone(dek)}}},
			dek:     nil,
			wantSub: "empty DEK",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.in != nil && len(tc.in.Splits) > 0 && len(tc.dek) > 0 {
				// Every case must be one Validate would let through, or
				// it proves nothing about the gap this method closes.
				populateKASKeys(tc.in)
				require.NoError(t, tc.in.Validate(), "case must pass Validate to be interesting")
			}

			err := tc.in.VerifyReconstruction(tc.dek)
			if tc.wantSub == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)
		})
	}
}

// populateKASKeys gives every split a resolvable KAS so Validate's
// structural checks pass and only the reconstruction check is left to
// fail.
func populateKASKeys(r *SplitResult) {
	const url = "https://kas-a.example.com"
	r.KASPublicKeys = map[string]KASPublicKey{
		url: {Algorithm: ocrypto.RSA2048Key, KID: "a", PEM: splitterTestPEM, URL: url},
	}
	for i := range r.Splits {
		r.Splits[i].KASURLs = []string{url}
	}
}

// TestDefaultKeySplitterResultValidates closes the loop: whatever the
// shipped splitter produces must satisfy the contract the writer
// enforces on injected ones, or the default path fails at Finalize.
func TestDefaultKeySplitterResultValidates(t *testing.T) {
	res, err := DefaultKeySplitter().Split(context.Background(), nil, []byte("0123456789abcdef"),
		&policy.SimpleKasKey{
			KasUri: "https://kas.example.com",
			PublicKey: &policy.SimpleKasPublicKey{
				Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
				Kid:       "k1",
				Pem:       splitterTestPEM,
			},
		})
	require.NoError(t, err)
	require.NoError(t, res.Validate())
}

// TestSingleKASSplitterRejectsAttributeGrants checks that the default splitter
// refuses attributes naming a KAS of their own rather than binding the key to
// the default one anyway.
//
// This is the failure the guard exists for: the resulting TDF is well-formed
// at every layer that inspects it -- the policy names the attribute, the
// manifest names a KAS, the round trip succeeds -- while the key sits at a KAS
// the attribute never authorized. Nothing downstream compares the grant to the
// placement, so creation time is the only place it can be caught.
func TestSingleKASSplitterRejectsAttributeGrants(t *testing.T) {
	const fqn = "https://example.com/attr/classification/value/secret"
	grant := []*policy.KeyAccessServer{{Uri: "https://grants.example.com"}}
	kasKeys := []*policy.SimpleKasKey{{KasUri: "https://grants.example.com"}}

	// A default KAS good enough to succeed on, so a passing case proves the
	// grant is what was rejected rather than a missing default.
	defaultKAS := &policy.SimpleKasKey{
		KasUri: "https://kas.example.com",
		PublicKey: &policy.SimpleKasPublicKey{
			Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
			Kid:       "k1",
			Pem:       splitterTestPEM,
		},
	}

	for _, tc := range []struct {
		name  string
		value *policy.Value
		want  string
	}{
		{
			"value grant",
			&policy.Value{Fqn: fqn, Grants: grant},
			"names its own KAS",
		},
		{
			"value kas keys",
			&policy.Value{Fqn: fqn, KasKeys: kasKeys},
			"names its own KAS",
		},
		{
			// Grants are inherited, so a definition-level one reaches the
			// value even though the value itself declares nothing.
			"attribute definition grant",
			&policy.Value{Fqn: fqn, Attribute: &policy.Attribute{Grants: grant}},
			"attribute definition",
		},
		{
			"attribute definition kas keys",
			&policy.Value{Fqn: fqn, Attribute: &policy.Attribute{KasKeys: kasKeys}},
			"attribute definition",
		},
		{
			"namespace grant",
			&policy.Value{Fqn: fqn, Attribute: &policy.Attribute{
				Namespace: &policy.Namespace{Grants: grant},
			}},
			"namespace",
		},
		{
			"namespace kas keys",
			&policy.Value{Fqn: fqn, Attribute: &policy.Attribute{
				Namespace: &policy.Namespace{KasKeys: kasKeys},
			}},
			"namespace",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := DefaultKeySplitter().Split(context.Background(),
				[]*policy.Value{tc.value}, []byte("0123456789abcdef"), defaultKAS)

			require.ErrorIs(t, err, ErrSplitterIgnoresGrants)
			require.ErrorContains(t, err, tc.want, "the error must name which level carried the grant")
			require.ErrorContains(t, err, fqn)
			assert.Nil(t, res)
		})
	}

	// The control: the same attribute without any grant is exactly what this
	// splitter is for, and must still work.
	t.Run("grantless attribute is accepted", func(t *testing.T) {
		res, err := DefaultKeySplitter().Split(context.Background(),
			[]*policy.Value{{Fqn: fqn}}, []byte("0123456789abcdef"), defaultKAS)
		require.NoError(t, err)
		require.Len(t, res.Splits, 1)
		assert.Equal(t, []string{"https://kas.example.com"}, res.Splits[0].KASURLs)
	})
}
