package config

import (
	"testing"
)

type demoCfg struct {
	User   string `mapstructure:"user" validate:"required"`
	Pass   Secret `mapstructure:"pass"`
	Nested struct {
		Token Secret `mapstructure:"token"`
	} `mapstructure:"nested"`
}

func TestBindServiceConfig_LiteralAndEnv(t *testing.T) {
	t.Setenv("OPENTDF_DEMO_TOKEN", "tok")

	in := ServiceConfig{
		"user": "alice",
		"pass": "p@ss",
		"nested": map[string]any{
			"token": map[string]any{"fromEnv": "OPENTDF_DEMO_TOKEN"},
		},
	}

	var out demoCfg
	if err := BindServiceConfig(t.Context(), in, &out, WithEagerSecretResolution()); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if out.User != "alice" {
		t.Fatalf("user mismatch: %q", out.User)
	}
	pass, err := out.Pass.Resolve(t.Context())
	if err != nil || pass != "p@ss" {
		t.Fatalf("pass resolve: %v %q", err, pass)
	}
	tok, err := out.Nested.Token.Resolve(t.Context())
	if err != nil || tok != "tok" {
		t.Fatalf("token resolve: %v %q", err, tok)
	}
}
