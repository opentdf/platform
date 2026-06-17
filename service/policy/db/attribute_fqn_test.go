package db

import (
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/stretchr/testify/assert"
)

func TestDefinitionFqnFromValueFqn(t *testing.T) {
	tests := []struct {
		name     string
		valueFqn string
		want     string
	}{
		{
			name:     "https value fqn",
			valueFqn: "https://example.com/attr/foo/value/bar",
			want:     "https://example.com/attr/foo",
		},
		{
			name:     "http value fqn",
			valueFqn: "http://example.com/attr/foo/value/bar",
			want:     "http://example.com/attr/foo",
		},
		{
			name:     "definition fqn",
			valueFqn: "https://example.com/attr/foo",
			want:     "",
		},
		{
			name:     "invalid fqn",
			valueFqn: "not-a-fqn",
			want:     "",
		},
		{
			name:     "empty string",
			valueFqn: "",
			want:     "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := definitionFqnFromValueFqn(tc.valueFqn)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestResolveEffectiveKasKeys(t *testing.T) {
	valueKey := &policy.SimpleKasKey{KasUri: "https://value-kas", KasId: "value"}
	defKey := &policy.SimpleKasKey{KasUri: "https://def-kas", KasId: "def"}
	nsKey := &policy.SimpleKasKey{KasUri: "https://ns-kas", KasId: "ns"}

	def := func(defKeys, nsKeys []*policy.SimpleKasKey) *policy.Attribute {
		return &policy.Attribute{
			KasKeys:   defKeys,
			Namespace: &policy.Namespace{KasKeys: nsKeys},
		}
	}

	tests := []struct {
		name  string
		value *policy.Value
		attr  *policy.Attribute
		want  []*policy.SimpleKasKey
	}{
		{
			name:  "value keys win over definition and namespace",
			value: &policy.Value{KasKeys: []*policy.SimpleKasKey{valueKey}},
			attr:  def([]*policy.SimpleKasKey{defKey}, []*policy.SimpleKasKey{nsKey}),
			want:  []*policy.SimpleKasKey{valueKey},
		},
		{
			name:  "definition keys used when value has none",
			value: &policy.Value{},
			attr:  def([]*policy.SimpleKasKey{defKey}, []*policy.SimpleKasKey{nsKey}),
			want:  []*policy.SimpleKasKey{defKey},
		},
		{
			name:  "namespace keys used when value and definition have none",
			value: &policy.Value{},
			attr:  def(nil, []*policy.SimpleKasKey{nsKey}),
			want:  []*policy.SimpleKasKey{nsKey},
		},
		{
			name:  "nil value falls back to definition",
			value: nil,
			attr:  def([]*policy.SimpleKasKey{defKey}, nil),
			want:  []*policy.SimpleKasKey{defKey},
		},
		{
			name:  "no keys at any level returns nil",
			value: &policy.Value{},
			attr:  def(nil, nil),
			want:  nil,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := resolveEffectiveKasKeys(tc.value, tc.attr)
			assert.Equal(t, tc.want, got)
		})
	}
}
