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

	// Legacy grants with a cached public key resolve to SimpleKasKeys.
	grantKAS := func(uri, id, kid string) *policy.KeyAccessServer {
		return &policy.KeyAccessServer{
			Uri: uri,
			Id:  id,
			PublicKey: &policy.PublicKey{
				PublicKey: &policy.PublicKey_Cached{
					Cached: &policy.KasPublicKeySet{Keys: []*policy.KasPublicKey{
						{Kid: kid, Pem: "pem", Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048},
					}},
				},
			},
		}
	}
	grantKey := func(uri, id, kid string) *policy.SimpleKasKey {
		return &policy.SimpleKasKey{
			KasUri:    uri,
			KasId:     id,
			PublicKey: &policy.SimpleKasPublicKey{Algorithm: policy.Algorithm_ALGORITHM_RSA_2048, Kid: kid, Pem: "pem"},
		}
	}
	valueGrant := grantKAS("https://vg-kas", "vg", "vgk")
	defGrant := grantKAS("https://dg-kas", "dg", "dgk")
	nsGrant := grantKAS("https://ng-kas", "ng", "ngk")

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
		{
			name:  "value grant resolves when no mapped keys",
			value: &policy.Value{Grants: []*policy.KeyAccessServer{valueGrant}},
			attr:  def(nil, nil),
			want:  []*policy.SimpleKasKey{grantKey("https://vg-kas", "vg", "vgk")},
		},
		{
			name:  "value mapped key preferred over value grant",
			value: &policy.Value{KasKeys: []*policy.SimpleKasKey{valueKey}, Grants: []*policy.KeyAccessServer{valueGrant}},
			attr:  def(nil, nil),
			want:  []*policy.SimpleKasKey{valueKey},
		},
		{
			name:  "value grant preferred over definition mapped key",
			value: &policy.Value{Grants: []*policy.KeyAccessServer{valueGrant}},
			attr:  def([]*policy.SimpleKasKey{defKey}, nil),
			want:  []*policy.SimpleKasKey{grantKey("https://vg-kas", "vg", "vgk")},
		},
		{
			name:  "definition grant used when value has none",
			value: &policy.Value{},
			attr:  &policy.Attribute{Grants: []*policy.KeyAccessServer{defGrant}, Namespace: &policy.Namespace{}},
			want:  []*policy.SimpleKasKey{grantKey("https://dg-kas", "dg", "dgk")},
		},
		{
			name:  "namespace grant used when value and definition have none",
			value: &policy.Value{},
			attr:  &policy.Attribute{Namespace: &policy.Namespace{Grants: []*policy.KeyAccessServer{nsGrant}}},
			want:  []*policy.SimpleKasKey{grantKey("https://ng-kas", "ng", "ngk")},
		},
		{
			name:  "grant without a cached key is skipped",
			value: &policy.Value{Grants: []*policy.KeyAccessServer{{Uri: "https://remote-only", Id: "ro"}}},
			attr:  def(nil, nil),
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveEffectiveKasKeys(tc.value, tc.attr)
			assert.Equal(t, tc.want, got)
		})
	}
}
