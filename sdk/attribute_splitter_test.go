package sdk

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"testing"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// counterSplitID hands out "1", "2", ... so a test can pin split IDs
// that are UUIDs in production.
func counterSplitID() func() string {
	i := 0
	return func() string {
		i++
		return strconv.Itoa(i)
	}
}

// splitterFor builds an offline canonical splitter, optionally with a
// key fetcher and a base key, without going through SDK.
func splitterFor(fetcher KASKeyFetcher, base baseKeyProvider) *attributeSplitter {
	x, _ := NewAttributeKeySplitter().(*attributeSplitter)
	x.fetcher = fetcher
	x.base = base
	return x
}

// staticBaseKey is a baseKeyProvider returning a fixed key, or an
// error when the key is nil.
type staticBaseKey struct {
	key *policy.SimpleKasKey
}

func (b staticBaseKey) GetBaseKey(_ context.Context) (*policy.SimpleKasKey, error) {
	if b.key == nil {
		return nil, errors.New("no base key configured")
	}
	return b.key, nil
}

// kaoShape is the part of a split a test asserts on: which KAS holds
// which key, and which share it unwraps.
type kaoShape struct {
	SplitID   string
	URL       string
	KID       string
	Algorithm ocrypto.KeyType
}

// shapeOf flattens a SplitResult to the KAO shapes it will produce, in
// manifest order.
func shapeOf(t *testing.T, result *SplitResult) []kaoShape {
	t.Helper()
	var shapes []kaoShape
	for _, split := range result.Splits {
		for _, key := range split.Keys {
			assert.NotEmpty(t, key.PEM, "every wrapping key must carry a PEM")
			shapes = append(shapes, kaoShape{
				SplitID:   split.ID,
				URL:       key.URL,
				KID:       key.KID,
				Algorithm: ocrypto.KeyType(key.Algorithm),
			})
		}
	}
	return shapes
}

// assertReconstructs checks the XOR shares still recover the DEK, the
// invariant that makes a multi-split TDF decryptable at all.
func assertReconstructs(t *testing.T, result *SplitResult, dek []byte) {
	t.Helper()
	got := make([]byte, len(dek))
	for _, split := range result.Splits {
		require.Len(t, split.Data, len(dek), "every share is DEK-sized")
		for i, b := range split.Data {
			got[i] ^= b
		}
	}
	assert.Equal(t, dek, got, "shares must XOR back to the DEK")
}

func TestAttributeSplitter_Attributes(t *testing.T) {
	dek := make([]byte, kKeySize)
	for i := range dek {
		dek[i] = byte(i)
	}

	for _, tc := range []struct {
		n string
		// policy are the attribute value FQNs bound to the payload.
		policy []AttributeValueFQN
		// splits is the number of XOR shares expected.
		splits int
		// shapes are the key access objects expected, in order.
		shapes []kaoShape
	}{
		{
			// One anyOf clause spanning two KAS: either KAS can
			// unwrap, so there is a single share with two KAOs.
			n:      "anyOf across two KAS is one split",
			policy: []AttributeValueFQN{rel2aus, rel2can},
			splits: 1,
			shapes: []kaoShape{
				{"1", kasAu, "r1", ocrypto.RSA2048Key},
				{"1", kasCa, "r1", ocrypto.RSA2048Key},
			},
		},
		{
			// Two allOf values: both KAS are required, so the DEK is
			// split and each share goes to one KAS.
			n:      "allOf across two KAS is two splits",
			policy: []AttributeValueFQN{n2kHCS, n2kInt},
			splits: 2,
			shapes: []kaoShape{
				{"1", kasUsHCS, "r2", ocrypto.KeyType("rsa:4096")},
				{"2", kasUk, "r1", ocrypto.RSA2048Key},
			},
		},
		{
			// An anyOf clause ANDed with an allOf clause: three
			// shares, four KAOs. Clauses are emitted in attribute
			// order, so the anyOf pair takes the first share.
			n:      "mixed anyOf and allOf",
			policy: []AttributeValueFQN{rel2aus, rel2can, n2kHCS, n2kInt},
			splits: 3,
			shapes: []kaoShape{
				{"1", kasAu, "r1", ocrypto.RSA2048Key},
				{"1", kasCa, "r1", ocrypto.RSA2048Key},
				{"2", kasUsHCS, "r2", ocrypto.KeyType("rsa:4096")},
				{"3", kasUk, "r1", ocrypto.RSA2048Key},
			},
		},
		{
			// The case a URL-keyed map could not express: one KAS,
			// two keys, two algorithms, one share. Both KAOs must
			// survive or the TDF loses a decryption path.
			n:      "same KAS with two key IDs keeps both KAOs",
			policy: []AttributeValueFQN{mpa, mpb},
			splits: 1,
			shapes: []kaoShape{
				{"1", evenMoreSpecificKas, "e1", ocrypto.EC256Key},
				{"1", evenMoreSpecificKas, "r2", ocrypto.KeyType("rsa:4096")},
			},
		},
		{
			// Grants at the namespace, reached because neither the
			// value nor the definition carries one.
			n:      "namespace grant",
			policy: []AttributeValueFQN{spk2uns2uns},
			splits: 1,
			shapes: []kaoShape{
				{"", lessSpecificKas, "r3", ocrypto.RSA2048Key},
			},
		},
	} {
		t.Run(tc.n, func(t *testing.T) {
			x := splitterFor(&fakeKeyInfoFetcher{}, nil)
			result, err := x.Split(t.Context(), SplitRequest{
				Attributes:      valuesToPolicy(tc.policy...),
				DEK:             dek,
				GenerateSplitID: counterSplitID(),
			})
			require.NoError(t, err)
			assert.Len(t, result.Splits, tc.splits)
			assert.Equal(t, tc.shapes, shapeOf(t, result))
			assertReconstructs(t, result, dek)
		})
	}
}

func TestAttributeSplitter_DefaultKASFallback(t *testing.T) {
	dek := make([]byte, kKeySize)
	baseKey := mockSimpleKasKey(kasUs, "r1")

	t.Run("one default KAS is a single unsplit KAO", func(t *testing.T) {
		x := splitterFor(nil, nil)
		result, err := x.Split(t.Context(), SplitRequest{
			DEK:             dek,
			DefaultKAS:      []*policy.SimpleKasKey{mockSimpleKasKey(kasAu, "r1")},
			GenerateSplitID: counterSplitID(),
		})
		require.NoError(t, err)
		// A single share carries no split ID, matching what
		// CreateTDF has always emitted for a one-KAS TDF.
		assert.Equal(t, []kaoShape{{"", kasAu, "r1", ocrypto.RSA2048Key}}, shapeOf(t, result))
	})

	t.Run("several default KAS split the DEK", func(t *testing.T) {
		x := splitterFor(nil, nil)
		result, err := x.Split(t.Context(), SplitRequest{
			DEK: dek,
			DefaultKAS: []*policy.SimpleKasKey{
				mockSimpleKasKey(kasAu, "r1"),
				mockSimpleKasKey(kasCa, "r2"),
				mockSimpleKasKey(kasUk, "r3"),
			},
			GenerateSplitID: counterSplitID(),
		})
		require.NoError(t, err)
		assert.Equal(t, []kaoShape{
			{"1", kasAu, "r1", ocrypto.RSA2048Key},
			{"2", kasCa, "r2", ocrypto.KeyType("rsa:4096")},
			{"3", kasUk, "r3", ocrypto.RSA2048Key},
		}, shapeOf(t, result))
		assertReconstructs(t, result, dek)
	})

	t.Run("base key is used when no default KAS was given", func(t *testing.T) {
		x := splitterFor(nil, staticBaseKey{key: baseKey})
		result, err := x.Split(t.Context(), SplitRequest{
			DEK:             dek,
			GenerateSplitID: counterSplitID(),
		})
		require.NoError(t, err)
		assert.Equal(t, []kaoShape{{"", kasUs, "r1", ocrypto.RSA2048Key}}, shapeOf(t, result))
	})

	t.Run("explicit default KAS beats the base key", func(t *testing.T) {
		x := splitterFor(nil, staticBaseKey{key: baseKey})
		result, err := x.Split(t.Context(), SplitRequest{
			DEK:             dek,
			DefaultKAS:      []*policy.SimpleKasKey{mockSimpleKasKey(kasAu, "r1")},
			GenerateSplitID: counterSplitID(),
		})
		require.NoError(t, err)
		assert.Equal(t, []kaoShape{{"", kasAu, "r1", ocrypto.RSA2048Key}}, shapeOf(t, result))
	})

	t.Run("no default KAS and no base key is an error", func(t *testing.T) {
		x := splitterFor(nil, nil)
		_, err := x.Split(t.Context(), SplitRequest{DEK: dek})
		require.ErrorIs(t, err, ErrSplitterRequiresDefaultKAS)
	})

	t.Run("unavailable base key falls through to the error", func(t *testing.T) {
		x := splitterFor(nil, staticBaseKey{key: nil})
		_, err := x.Split(t.Context(), SplitRequest{DEK: dek})
		require.ErrorIs(t, err, ErrSplitterRequiresDefaultKAS)
	})

	t.Run("attributes that name a KAS ignore the base key", func(t *testing.T) {
		x := splitterFor(&fakeKeyInfoFetcher{}, staticBaseKey{key: baseKey})
		result, err := x.Split(t.Context(), SplitRequest{
			Attributes:      valuesToPolicy(rel2aus),
			DEK:             dek,
			GenerateSplitID: counterSplitID(),
		})
		require.NoError(t, err)
		assert.Equal(t, []kaoShape{{"", kasAu, "r1", ocrypto.RSA2048Key}}, shapeOf(t, result))
	})
}

func TestAttributeSplitter_Offline(t *testing.T) {
	dek := make([]byte, kKeySize)

	t.Run("grants carrying keys resolve without a fetcher", func(t *testing.T) {
		// Every grant in these fixtures embeds its KAS key, so an
		// offline splitter can wrap to it. This is what lets the
		// experimental Writer work with no platform connection.
		x := splitterFor(nil, nil)
		result, err := x.Split(t.Context(), SplitRequest{
			Attributes:      valuesToPolicy(rel2aus),
			DEK:             dek,
			GenerateSplitID: counterSplitID(),
		})
		require.NoError(t, err)
		assert.Equal(t, []kaoShape{{"", kasAu, "r1", ocrypto.RSA2048Key}}, shapeOf(t, result))
	})

	t.Run("a default KAS with no key errors rather than fetching", func(t *testing.T) {
		x := splitterFor(nil, nil)
		_, err := x.Split(t.Context(), SplitRequest{
			DEK:        dek,
			DefaultKAS: []*policy.SimpleKasKey{{KasUri: kasAu}},
		})
		require.ErrorIs(t, err, errKasPubKeyMissing)
	})

	t.Run("a default KAS with no key is fetched when online", func(t *testing.T) {
		x := splitterFor(&fakeKeyInfoFetcher{}, nil)
		result, err := x.Split(t.Context(), SplitRequest{
			DEK:        dek,
			DefaultKAS: []*policy.SimpleKasKey{{KasUri: kasAu}},
		})
		require.NoError(t, err)
		assert.Equal(t, []kaoShape{{"", kasAu, "r1", ocrypto.RSA2048Key}}, shapeOf(t, result))
	})
}

func TestAttributeSplitter_MissingGrantIsAnError(t *testing.T) {
	// clsA has no grant at any level. The canonical splitter refuses
	// rather than silently dropping the attribute from the policy,
	// which would produce a TDF the attribute does not actually guard.
	x := splitterFor(&fakeKeyInfoFetcher{}, nil)
	_, err := x.Split(t.Context(), SplitRequest{
		Attributes: valuesToPolicy(clsA),
		DEK:        make([]byte, kKeySize),
	})
	require.Error(t, err)
}

func TestAttributeSplitter_PreferredAlgorithmPicksTheKey(t *testing.T) {
	// mpa and mpb map the same KAS to an RSA key and an EC key. When
	// a grant-planned step has to choose one, the request's preferred
	// algorithm decides; without it the choice is still deterministic.
	reasoner, err := newGranterFromAttributes(slog.Default(), newKasKeyCache(), valuesToPolicy(mpa, mpb)...)
	require.NoError(t, err)

	for _, tc := range []struct {
		n         string
		preferred ocrypto.KeyType
		wantKID   string
	}{
		{"prefers EC when asked", ocrypto.EC256Key, "e1"},
		{"prefers RSA when asked", ocrypto.KeyType("rsa:4096"), "r2"},
		{"deterministic without a preference", "", "e1"},
	} {
		t.Run(tc.n, func(t *testing.T) {
			tpl, err := reasoner.fillTemplateFromPlan(
				t.Context(),
				[]keySplitStep{{KAS: evenMoreSpecificKas}},
				tc.preferred,
				nil,
			)
			require.NoError(t, err)
			require.Len(t, tpl, 1)
			assert.Equal(t, tc.wantKID, tpl[0].kid)
		})
	}
}

func TestSplitResultFromTemplate_GroupsBySplitID(t *testing.T) {
	dek := make([]byte, kKeySize)
	for i := range dek {
		dek[i] = byte(i * 3)
	}

	// Entries for one split ID need not be adjacent; grouping must
	// still produce one share per distinct ID, in first-seen order.
	result, err := splitResultFromTemplate([]kaoTpl{
		{kasAu, "a", "r1", mockRSAPublicKey1, ocrypto.RSA2048Key},
		{kasCa, "b", "r1", mockRSAPublicKey1, ocrypto.RSA2048Key},
		{kasUk, "a", "r3", mockRSAPublicKey3, ocrypto.RSA2048Key},
	}, dek, defaultRand)
	require.NoError(t, err)

	require.Len(t, result.Splits, 2)
	assert.Equal(t, "a", result.Splits[0].ID)
	assert.Len(t, result.Splits[0].Keys, 2)
	assert.Equal(t, "b", result.Splits[1].ID)
	assert.Len(t, result.Splits[1].Keys, 1)
	assertReconstructs(t, result, dek)
}

func TestSplitResultFromTemplate_EmptyTemplate(t *testing.T) {
	_, err := splitResultFromTemplate(nil, make([]byte, kKeySize), defaultRand)
	require.ErrorIs(t, err, errInvalidKasInfo)
}
