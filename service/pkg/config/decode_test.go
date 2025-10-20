package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type inlineCfg struct {
	A Secret `mapstructure:"a"`
	B Secret `mapstructure:"b"`
	C Secret `mapstructure:"c"`
}

func TestDecodeHook_InlineForms(t *testing.T) {
	// Prepare a temp file for file: form
	dir := t.TempDir()
	f := filepath.Join(dir, "secret.txt")
	require.NoError(t, os.WriteFile(f, []byte("from-file"), 0o600))
	t.Setenv("OPENTDF_TEST_INLINE", "from-env")

	in := ServiceConfig{
		"a": "literal:abc",
		"b": "env:OPENTDF_TEST_INLINE",
		"c": "file:" + f,
	}

	var out inlineCfg
	require.NoError(t, BindServiceConfig(t.Context(), in, &out))

	a, err := out.A.Resolve(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "abc", a)
	b, err := out.B.Resolve(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "from-env", b)
	c, err := out.C.Resolve(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "from-file", c)
}

func TestDecodeHook_MalformedDirectives(t *testing.T) {
	cases := []ServiceConfig{
		{"x": "env:"},
		{"x": "file:"},
		{"x": map[string]any{"fromEnv": ""}},
		{"x": map[string]any{"fromFile": ""}},
	}
	for _, in := range cases {
		var out struct {
			X Secret `mapstructure:"x"`
		}
		err := BindServiceConfig(t.Context(), in, &out)
		require.Error(t, err)
	}
}

// A nested service configuration with multiple tenants and lists of credentials.
type tenantCfg struct {
	Credential Secret   `mapstructure:"credential"`
	Passwords  []Secret `mapstructure:"passwords"`
}

type svcCfgComplex struct {
	ClientSecret Secret               `mapstructure:"client_secret"`
	Tenants      map[string]tenantCfg `mapstructure:"tenants"`
}

func TestBindServiceConfig_NestedTenants_SecretsAndLists(t *testing.T) {
	// Prepare env vars and a temp file for fromFile
	t.Setenv("OPENTDF_TEST_CLIENT_SECRET", "client-secret")
	t.Setenv("OPENTDF_TENANT_A_CRED", "tenant-a-cred")
	t.Setenv("OPENTDF_PASS1", "p1")

	dir := t.TempDir()
	filePath := filepath.Join(dir, "pass.txt")
	require.NoError(t, os.WriteFile(filePath, []byte("from-file\n"), 0o600))

	in := ServiceConfig{
		"client_secret": "env:OPENTDF_TEST_CLIENT_SECRET",
		"tenants": map[string]any{
			"tenantA": map[string]any{
				"credential": "env:OPENTDF_TENANT_A_CRED",
				"passwords": []any{
					"env:OPENTDF_PASS1",
					"literal:abc",
					map[string]any{"fromFile": filePath},
				},
			},
			"tenantB": map[string]any{
				"credential": "literal:credB",
			},
		},
	}

	var out svcCfgComplex
	// Eagerly resolve to validate that nested secrets are materialized
	require.NoError(t, BindServiceConfig(t.Context(), in, &out, WithEagerSecretResolution()))

	// Assert top-level secret
	v, err := out.ClientSecret.Resolve(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "client-secret", v)

	// Assert tenant map
	tenantA, ok := out.Tenants["tenantA"]
	require.True(t, ok, "expected tenant 'tenantA' present")
	credA, err := tenantA.Credential.Resolve(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "tenant-a-cred", credA)
	require.Len(t, tenantA.Passwords, 3)
	p0, _ := tenantA.Passwords[0].Resolve(t.Context())
	p1, _ := tenantA.Passwords[1].Resolve(t.Context())
	p2, _ := tenantA.Passwords[2].Resolve(t.Context())
	assert.Equal(t, "p1", p0)
	assert.Equal(t, "abc", p1)
	assert.Equal(t, "from-file", p2)

	// Second tenant literal credential
	tenantB, ok := out.Tenants["tenantB"]
	require.True(t, ok, "expected tenant 'tenantB' present")
	credB, err := tenantB.Credential.Resolve(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "credB", credB)
}

func TestBindServiceConfig_NestedTenants_EagerFailureOnMissingEnv(t *testing.T) {
	in := ServiceConfig{
		"tenants": map[string]any{
			"tenantA": map[string]any{
				// Missing env value should cause eager resolution to fail
				"credential": "env:OPENTDF_TEST_MISSING_ENV_ABC123",
			},
		},
	}
	var out svcCfgComplex
	err := BindServiceConfig(t.Context(), in, &out, WithEagerSecretResolution())
	require.Error(t, err)
}
