package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

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
	if err := os.WriteFile(filePath, []byte("from-file\n"), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

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
	if err := BindServiceConfig(context.Background(), in, &out, WithEagerSecretResolution()); err != nil {
		t.Fatalf("bind: %v", err)
	}

	// Assert top-level secret
	v, err := out.ClientSecret.Resolve(context.Background())
	if err != nil || v != "client-secret" {
		t.Fatalf("client_secret resolve: %v %q", err, v)
	}

	// Assert tenant map
	tenantA, ok := out.Tenants["tenantA"]
	if !ok {
		t.Fatalf("expected tenant 'tenantA' present")
	}
	credA, err := tenantA.Credential.Resolve(context.Background())
	if err != nil || credA != "tenant-a-cred" {
		t.Fatalf("credential resolve: %v %q", err, credA)
	}
	if len(tenantA.Passwords) != 3 {
		t.Fatalf("expected 3 passwords, got %d", len(tenantA.Passwords))
	}
	p0, _ := tenantA.Passwords[0].Resolve(context.Background())
	p1, _ := tenantA.Passwords[1].Resolve(context.Background())
	p2, _ := tenantA.Passwords[2].Resolve(context.Background())
	if p0 != "p1" || p1 != "abc" || p2 != "from-file" {
		t.Fatalf("passwords mismatch: %q, %q, %q", p0, p1, p2)
	}

	// Second tenant literal credential
	tenantB, ok := out.Tenants["tenantB"]
	if !ok {
		t.Fatalf("expected tenant 'tenantB' present")
	}
	credB, err := tenantB.Credential.Resolve(context.Background())
	if err != nil || credB != "credB" {
		t.Fatalf("credential resolve (tenantB): %v %q", err, credB)
	}
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
	if err := BindServiceConfig(context.Background(), in, &out, WithEagerSecretResolution()); err == nil {
		t.Fatalf("expected bind failure on missing env in eager resolution")
	}
}
