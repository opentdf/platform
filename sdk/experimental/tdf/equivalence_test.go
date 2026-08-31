// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"bytes"
	"sort"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// kaoShape is a key access object reduced to the parts attribute
// reasoning decides: which key at which KAS, and which share it
// unwraps. Split IDs themselves are random UUIDs, so shares are
// identified by the index of the group they fall into rather than by
// the ID printed in the manifest.
type kaoShape struct {
	Share int
	URL   string
	KID   string
}

// shapeOfManifest reduces a manifest's keyAccess array to comparable
// shapes, sorted so that the comparison is over the set of wrapping
// targets rather than over emission order.
func shapeOfManifest(t *testing.T, kaos []sdk.KeyAccess) []kaoShape {
	t.Helper()
	share := make(map[string]int)
	shapes := make([]kaoShape, 0, len(kaos))
	for _, kao := range kaos {
		if _, ok := share[kao.SplitID]; !ok {
			share[kao.SplitID] = len(share)
		}
		shapes = append(shapes, kaoShape{share[kao.SplitID], kao.KasURL, kao.KID})
	}
	sort.Slice(shapes, func(i, j int) bool {
		if shapes[i].Share != shapes[j].Share {
			return shapes[i].Share < shapes[j].Share
		}
		if shapes[i].URL != shapes[j].URL {
			return shapes[i].URL < shapes[j].URL
		}
		return shapes[i].KID < shapes[j].KID
	})
	return shapes
}

// TestWriterMatchesCreateTDF is the test the canonical-splitter work
// exists to make pass: the same attribute values must produce the same
// key access objects whether the caller reaches for SDK.CreateTDF or
// this package's streaming Writer.
//
// Both run offline -- every wrapping key is carried by the values
// themselves -- so nothing here depends on a running platform.
func TestWriterMatchesCreateTDF(t *testing.T) {
	ctx := t.Context()

	for _, tc := range []struct {
		name string
		// wantKAOs and wantShares pin what the shared reasoning is
		// expected to decide, so an agreement on nothing cannot pass
		// for an agreement.
		wantKAOs   int
		wantShares int
		values     []*policy.Value
	}{
		{
			name:       "one value, one KAS",
			wantKAOs:   1,
			wantShares: 1,
			values: []*policy.Value{
				createTestAttribute("https://test.com/attr/Classification/value/Public", testKAS1, "kid1"),
			},
		},
		{
			name:       "allOf across two KAS splits the DEK",
			wantKAOs:   2,
			wantShares: 2,
			values: []*policy.Value{
				createTestAttribute("https://test.com/attr/Classification/value/Secret", testKAS1, "kid1"),
				createTestAttribute("https://test.com/attr/Need2Know/value/HCS", testKAS2, "kid2"),
			},
		},
		{
			name:       "anyOf across two KAS shares one split",
			wantKAOs:   2,
			wantShares: 1,
			values: []*policy.Value{
				createTestAttributeWithRule("https://test.com/attr/Rel2/value/Aus", testKAS1, "kid1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
				createTestAttributeWithRule("https://test.com/attr/Rel2/value/Can", testKAS2, "kid2", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
			},
		},
		{
			name:       "anyOf clause ANDed with an allOf value",
			wantKAOs:   3,
			wantShares: 2,
			values: []*policy.Value{
				createTestAttributeWithRule("https://test.com/attr/Rel2/value/Aus", testKAS1, "kid1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
				createTestAttributeWithRule("https://test.com/attr/Rel2/value/Can", testKAS2, "kid2", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
				createTestAttribute("https://test.com/attr/Need2Know/value/HCS", testKAS3, "kid3"),
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// SDK.CreateTDF: a zero SDK suffices because the values carry
			// every key, so nothing is fetched.
			var out bytes.Buffer
			obj, err := sdk.SDK{}.CreateTDFContext(ctx, &out, strings.NewReader("hello"),
				sdk.WithDataAttributeValues(tc.values...))
			require.NoError(t, err)

			// This package's Writer, over the same values.
			writer, err := NewWriter(ctx)
			require.NoError(t, err)
			_, err = writer.WriteSegment(ctx, 0, []byte("hello"))
			require.NoError(t, err)
			fin, err := writer.Finalize(ctx, WithAttributeValues(tc.values))
			require.NoError(t, err)

			manifest := obj.Manifest()
			want := shapeOfManifest(t, manifest.KeyAccessObjs)
			require.Len(t, want, tc.wantKAOs)
			require.Equal(t, tc.wantShares, want[len(want)-1].Share+1, "number of XOR shares")

			assert.Equal(t, want, shapeOfManifest(t, fin.Manifest.KeyAccessObjs),
				"the two paths must wrap the same shares to the same keys")
		})
	}
}
