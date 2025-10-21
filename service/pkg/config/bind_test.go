package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	err := BindServiceConfig(t.Context(), in, &out, WithEagerSecretResolution())
	require.NoError(t, err)

	assert.Equal(t, "alice", out.User)

	pass, err := out.Pass.Resolve(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "p@ss", pass)

	tok, err := out.Nested.Token.Resolve(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "tok", tok)
}
