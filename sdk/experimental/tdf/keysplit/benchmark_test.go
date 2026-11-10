// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package keysplit

import (
	"crypto/rand"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
)

func BenchmarkXORSplitter_GenerateSplits(b *testing.B) {
	benchmarks := []struct {
		name       string
		numAttrs   int
		numValues  int // values per attribute
		dekSize    int
		setupAttrs func(int, int) []*policy.Value
	}{
		{
			name:      "single_attribute_single_value",
			numAttrs:  1,
			numValues: 1,
			dekSize:   32,
			setupAttrs: func(_, _ int) []*policy.Value {
				return []*policy.Value{
					createMockValue("https://test.com/attr/test/value/test", kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF),
				}
			},
		},
		{
			name:      "small_policy",
			numAttrs:  3,
			numValues: 2,
			dekSize:   32,
			setupAttrs: func(numAttrs, numValues int) []*policy.Value {
				attrs := make([]*policy.Value, 0, numAttrs*numValues)
				kasUrls := []string{kasUs, kasUk, kasCa}
				rules := []policy.AttributeRuleTypeEnum{
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
				}

				for i := 0; i < numAttrs; i++ {
					for j := 0; j < numValues; j++ {
						fqn := "https://test.com/attr/attr" + string(rune('A'+i)) + "/value/value" + string(rune('1'+j))
						kas := kasUrls[i%len(kasUrls)]
						rule := rules[i%len(rules)]
						attrs = append(attrs, createMockValue(fqn, kas, "r1", rule))
					}
				}
				return attrs
			},
		},
		{
			name:      "medium_policy",
			numAttrs:  10,
			numValues: 5,
			dekSize:   32,
			setupAttrs: func(numAttrs, numValues int) []*policy.Value {
				attrs := make([]*policy.Value, 0, numAttrs*numValues)
				kasUrls := []string{kasUs, kasUk, kasCa, kasNz, kasAu}
				rules := []policy.AttributeRuleTypeEnum{
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
				}

				for i := 0; i < numAttrs; i++ {
					for j := 0; j < numValues; j++ {
						fqn := "https://test.com/attr/attr" + string(rune('A'+i)) + "/value/value" + string(rune('1'+j))
						kas := kasUrls[(i+j)%len(kasUrls)]
						rule := rules[i%len(rules)]
						attrs = append(attrs, createMockValue(fqn, kas, "r1", rule))
					}
				}
				return attrs
			},
		},
		{
			name:      "large_policy",
			numAttrs:  25,
			numValues: 10,
			dekSize:   32,
			setupAttrs: func(numAttrs, numValues int) []*policy.Value {
				attrs := make([]*policy.Value, 0, numAttrs*numValues)
				kasUrls := []string{kasUs, kasUk, kasCa, kasNz, kasAu, kasUsHCS, kasUsSA}
				rules := []policy.AttributeRuleTypeEnum{
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
					policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
				}

				for i := 0; i < numAttrs; i++ {
					for j := 0; j < numValues; j++ {
						fqn := "https://test.com/attr/attr" + string(rune('A'+i%26)) + string(rune('0'+i/26)) + "/value/value" + string(rune('1'+j%10)) + string(rune('0'+j/10))
						kas := kasUrls[(i*numValues+j)%len(kasUrls)]
						rule := rules[i%len(rules)]
						attrs = append(attrs, createMockValue(fqn, kas, "r1", rule))
					}
				}
				return attrs
			},
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			// Setup
			splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))
			attrs := bm.setupAttrs(bm.numAttrs, bm.numValues)

			dek := make([]byte, bm.dekSize)
			_, err := rand.Read(dek)
			if err != nil {
				b.Fatal(err)
			}

			ctx := b.Context()

			// Reset timer to exclude setup time
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				result, err := splitter.GenerateSplits(ctx, attrs, dek)
				if err != nil {
					b.Fatal(err)
				}
				_ = result // Prevent optimization
			}
		})
	}
}

// BenchmarkXORSplitter_BuildKeyAccessObjects functionality moved to parent tdf package
// to avoid circular dependencies. This benchmark focused on split generation only.

func BenchmarkXORSplitter_SplitGeneration(b *testing.B) {
	// Benchmark split generation from attributes to splits
	benchmarks := []struct {
		name       string
		numAttrs   int
		dekSize    int
		policySize int
	}{
		{
			name:       "small_end_to_end",
			numAttrs:   5,
			dekSize:    32,
			policySize: 1000,
		},
		{
			name:       "medium_end_to_end",
			numAttrs:   15,
			dekSize:    32,
			policySize: 5000,
		},
		{
			name:       "large_end_to_end",
			numAttrs:   30,
			dekSize:    32,
			policySize: 15000,
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			// Setup
			splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))

			attrs := make([]*policy.Value, bm.numAttrs)
			kasUrls := []string{kasUs, kasUk, kasCa, kasNz, kasAu}
			rules := []policy.AttributeRuleTypeEnum{
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
				policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
			}

			for i := 0; i < bm.numAttrs; i++ {
				fqn := "https://bench.com/attr/attr" + string(rune('A'+i%26)) + "/value/value" + string(rune('1'+i%10))
				kas := kasUrls[i%len(kasUrls)]
				rule := rules[i%len(rules)]
				attrs[i] = createMockValue(fqn, kas, "r1", rule)
			}

			dek := make([]byte, bm.dekSize)
			_, err := rand.Read(dek)
			if err != nil {
				b.Fatal(err)
			}

			policyBytes := make([]byte, bm.policySize)
			_, err = rand.Read(policyBytes)
			if err != nil {
				b.Fatal(err)
			}

			ctx := b.Context()

			// Reset timer to exclude setup time
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				// Generate splits
				result, err := splitter.GenerateSplits(ctx, attrs, dek)
				if err != nil {
					b.Fatal(err)
				}

				// Verify split generation succeeded
				_ = result // Prevent optimization of split generation
			}
		})
	}
}

func BenchmarkAttributeResolution(b *testing.B) {
	// Benchmark the attribute resolution logic specifically
	benchmarks := []struct {
		name        string
		numAttrs    int
		grantLevels []string // "value", "attribute", "namespace", "none"
	}{
		{
			name:        "all_value_grants",
			numAttrs:    10,
			grantLevels: []string{"value"},
		},
		{
			name:        "mixed_grant_levels",
			numAttrs:    10,
			grantLevels: []string{"value", "attribute", "namespace", "none"},
		},
		{
			name:        "hierarchy_resolution",
			numAttrs:    25,
			grantLevels: []string{"value", "attribute", "namespace"},
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			// Setup attributes with different grant levels
			attrs := make([]*policy.Value, bm.numAttrs)

			for i := 0; i < bm.numAttrs; i++ {
				grantLevel := bm.grantLevels[i%len(bm.grantLevels)]
				fqn := "https://bench.com/attr/attr" + string(rune('A'+i%26)) + "/value/value" + string(rune('1'+i%10))

				var attr *policy.Value
				switch grantLevel {
				case "value":
					attr = createMockValue(fqn, kasUs, "r1", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
				case "attribute":
					attr = createMockValue(fqn, "", "", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
					attr.Attribute.Grants = []*policy.KeyAccessServer{{Uri: kasUk}}
				case "namespace":
					attr = createMockValue(fqn, "", "", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
					attr.Attribute.Namespace.Grants = []*policy.KeyAccessServer{{Uri: kasCa}}
				case "none":
					attr = createMockValue(fqn, "", "", policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF)
				}
				attrs[i] = attr
			}

			splitter := NewXORSplitter(WithDefaultKAS(&policy.SimpleKasKey{KasUri: kasUs}))
			dek := make([]byte, 32)
			_, err := rand.Read(dek)
			if err != nil {
				b.Fatal(err)
			}

			// Reset timer
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				// This will internally do attribute resolution
				result, err := splitter.GenerateSplits(b.Context(), attrs, dek)
				if err != nil {
					b.Fatal(err)
				}
				_ = result
			}
		})
	}
}
