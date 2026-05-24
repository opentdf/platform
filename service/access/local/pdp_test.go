package local

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	fqnSecret = "https://example.com/attr/classification/value/secret"
	fqnPublic = "https://example.com/attr/classification/value/public"
)

func TestGrant_Validate(t *testing.T) {
	cases := map[string]struct {
		g       Grant
		wantErr bool
	}{
		"ok":             {g: Grant{Type: GrantTypeAttribute, Actions: []string{"read"}, Locations: []string{fqnSecret}}, wantErr: false},
		"no type":        {g: Grant{Actions: []string{"read"}, Locations: []string{fqnSecret}}, wantErr: true},
		"no actions":     {g: Grant{Type: GrantTypeAttribute, Locations: []string{fqnSecret}}, wantErr: true},
		"no locations":   {g: Grant{Type: GrantTypeAttribute, Actions: []string{"read"}}, wantErr: true},
		"empty action":   {g: Grant{Type: GrantTypeAttribute, Actions: []string{""}, Locations: []string{fqnSecret}}, wantErr: true},
		"empty location": {g: Grant{Type: GrantTypeAttribute, Actions: []string{"read"}, Locations: []string{""}}, wantErr: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := tc.g.Validate()
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDecide_AllowsExactMatch(t *testing.T) {
	grants := []Grant{
		{Type: GrantTypeAttribute, Actions: []string{"read"}, Locations: []string{fqnSecret}},
	}
	d := Decide(grants, "read", fqnSecret)
	assert.True(t, d.Allow)
	assert.Empty(t, d.RequiredObligations)
}

func TestDecide_DeniesUnmatchedAction(t *testing.T) {
	grants := []Grant{
		{Type: GrantTypeAttribute, Actions: []string{"read"}, Locations: []string{fqnSecret}},
	}
	assert.False(t, Decide(grants, "write", fqnSecret).Allow)
}

func TestDecide_DeniesUnmatchedLocation(t *testing.T) {
	grants := []Grant{
		{Type: GrantTypeAttribute, Actions: []string{"read"}, Locations: []string{fqnSecret}},
	}
	assert.False(t, Decide(grants, "read", fqnPublic).Allow)
}

func TestDecide_CaseInsensitive(t *testing.T) {
	grants := []Grant{
		{Type: GrantTypeAttribute, Actions: []string{"READ"}, Locations: []string{fqnSecret}},
	}
	assert.True(t, Decide(grants, "read", fqnSecret).Allow)
	assert.True(t, Decide(grants, "rEaD", "HTTPS://example.com/attr/Classification/Value/Secret").Allow)
}

func TestDecide_EmptyInputsDeny(t *testing.T) {
	grants := []Grant{
		{Type: GrantTypeAttribute, Actions: []string{"read"}, Locations: []string{fqnSecret}},
	}
	assert.False(t, Decide(grants, "", fqnSecret).Allow)
	assert.False(t, Decide(grants, "read", "").Allow)
	assert.False(t, Decide(nil, "read", fqnSecret).Allow)
}

func TestDecide_IgnoresUnknownType(t *testing.T) {
	grants := []Grant{
		{Type: "future_type", Actions: []string{"read"}, Locations: []string{fqnSecret}},
	}
	assert.False(t, Decide(grants, "read", fqnSecret).Allow)
}

func TestDecide_CollectsObligationsAcrossOverlappingGrants(t *testing.T) {
	grants := []Grant{
		{
			Type: GrantTypeAttribute, Actions: []string{"read"}, Locations: []string{fqnSecret},
			Obligations: []string{"https://x/obl/a/value/1", "https://x/obl/b/value/1"},
		},
		{
			Type: GrantTypeAttribute, Actions: []string{"read", "decrypt"}, Locations: []string{fqnSecret},
			// Overlap: "https://x/obl/a/value/1" should not be duplicated.
			Obligations: []string{"https://x/obl/a/value/1", "https://x/obl/c/value/1"},
		},
	}
	d := Decide(grants, "read", fqnSecret)
	require.True(t, d.Allow)
	assert.Equal(t, []string{
		"https://x/obl/a/value/1",
		"https://x/obl/b/value/1",
		"https://x/obl/c/value/1",
	}, d.RequiredObligations)
}

func TestDecideAny_AllResourcesMustPermit(t *testing.T) {
	grants := []Grant{
		{Type: GrantTypeAttribute, Actions: []string{"read"}, Locations: []string{fqnSecret, fqnPublic}},
	}
	t.Run("all match", func(t *testing.T) {
		d := DecideAny(grants, "read", []string{fqnSecret, fqnPublic})
		assert.True(t, d.Allow)
	})
	t.Run("one missing", func(t *testing.T) {
		d := DecideAny(grants, "read", []string{fqnSecret, "https://example.com/attr/level/value/top"})
		assert.False(t, d.Allow)
	})
	t.Run("empty resource list", func(t *testing.T) {
		assert.False(t, DecideAny(grants, "read", nil).Allow)
	})
}

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	in := []Grant{
		{Type: GrantTypeAttribute, Actions: []string{"read", "decrypt"}, Locations: []string{fqnSecret}, Obligations: []string{"https://x/obl/a/value/1"}},
		{Type: GrantTypeAttribute, Actions: []string{"read"}, Locations: []string{fqnPublic}},
	}
	buf, err := MarshalGrants(in)
	require.NoError(t, err)
	out, err := UnmarshalGrants(buf)
	require.NoError(t, err)
	require.Len(t, out, 2)
	assert.Equal(t, in[0].Actions, out[0].Actions)
	assert.Equal(t, in[0].Locations, out[0].Locations)
	assert.Equal(t, in[0].Obligations, out[0].Obligations)
	assert.Equal(t, in[1].Locations, out[1].Locations)
}

func TestUnmarshalRejectsMalformedGrants(t *testing.T) {
	t.Run("invalid json", func(t *testing.T) {
		_, err := UnmarshalGrants([]byte("not json"))
		require.Error(t, err)
	})
	t.Run("structurally invalid grant", func(t *testing.T) {
		_, err := UnmarshalGrants([]byte(`[{"type":"opentdf_attribute"}]`))
		require.Error(t, err)
	})
}

func TestGrantsFromToken(t *testing.T) {
	// Sign a token with the local Grant claim, parse it, extract grants.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	privKey, err := jwk.FromRaw(priv)
	require.NoError(t, err)
	require.NoError(t, privKey.Set(jwk.AlgorithmKey, jwa.EdDSA))
	require.NoError(t, privKey.Set(jwk.KeyIDKey, "test-kid"))
	pubKey, err := jwk.FromRaw(pub)
	require.NoError(t, err)
	require.NoError(t, pubKey.Set(jwk.AlgorithmKey, jwa.EdDSA))
	require.NoError(t, pubKey.Set(jwk.KeyIDKey, "test-kid"))
	set := jwk.NewSet()
	require.NoError(t, set.AddKey(pubKey))

	tok := jwt.New()
	require.NoError(t, tok.Set(jwt.SubjectKey, "user-1"))
	require.NoError(t, tok.Set(jwt.IssuerKey, "test"))
	require.NoError(t, tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	grants := []Grant{
		{Type: GrantTypeAttribute, Actions: []string{"read"}, Locations: []string{fqnSecret}, Obligations: []string{"https://x/obl/a/value/1"}},
	}
	buf, err := json.Marshal(grants)
	require.NoError(t, err)
	var generic []map[string]any
	require.NoError(t, json.Unmarshal(buf, &generic))
	require.NoError(t, tok.Set(AuthorizationDetailsClaim, generic))

	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.KeyIDKey, "test-kid"))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA, privKey, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)

	parsed, err := jwt.Parse(signed, jwt.WithKeySet(set), jwt.WithValidate(true), jwt.WithIssuer("test"))
	require.NoError(t, err)

	got, err := GrantsFromToken(parsed)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, []string{"read"}, got[0].Actions)
	assert.Equal(t, []string{fqnSecret}, got[0].Locations)
	assert.Equal(t, []string{"https://x/obl/a/value/1"}, got[0].Obligations)
}

func TestGrantsFromToken_MissingClaim(t *testing.T) {
	tok := jwt.New()
	require.NoError(t, tok.Set(jwt.SubjectKey, "user-1"))
	_, err := GrantsFromToken(tok)
	require.ErrorIs(t, err, ErrClaimMissing)
}
