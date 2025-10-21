package config

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type arrayCfg struct {
	Secrets []Secret `mapstructure:"secrets"`
}

type provider struct {
	Name     string `mapstructure:"name"`
	Password Secret `mapstructure:"password"`
}

type providersCfg struct {
	Providers []provider `mapstructure:"providers"`
}

func TestBind_FromYAMLArray_SecretsSlice(t *testing.T) {
	t.Setenv("OPENTDF_YAML_ARR", "arr-env")
	dir := t.TempDir()
	fp := filepath.Join(dir, "s.txt")
	require.NoError(t, os.WriteFile(fp, []byte("from-file\n"), 0o600))

	yaml := "" +
		"secrets:\n" +
		"  - \"env:OPENTDF_YAML_ARR\"\n" +
		"  - { fromFile: \"" + fp + "\" }\n" +
		"  - \"literal:abc\"\n"

	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewBufferString(yaml)))

	in := ServiceConfig{
		"secrets": v.Get("secrets"),
	}
	var out arrayCfg
	require.NoError(t, BindServiceConfig(t.Context(), in, &out, WithEagerSecretResolution()))
	require.Len(t, out.Secrets, 3)
	s0, _ := out.Secrets[0].Resolve(t.Context())
	s1, _ := out.Secrets[1].Resolve(t.Context())
	s2, _ := out.Secrets[2].Resolve(t.Context())
	assert.Equal(t, "arr-env", s0)
	assert.Equal(t, "from-file", s1)
	assert.Equal(t, "abc", s2)
}

func TestBind_FromYAMLArray_StructsWithSecretFields(t *testing.T) {
	t.Setenv("OPENTDF_PROVIDER_B_PASS", "b-pass")

	yaml := "" +
		"providers:\n" +
		"  - name: a\n" +
		"    password: \"literal:alpha\"\n" +
		"  - name: b\n" +
		"    password: \"env:OPENTDF_PROVIDER_B_PASS\"\n"

	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewBufferString(yaml)))

	in := ServiceConfig{
		"providers": v.Get("providers"),
	}
	var out providersCfg
	require.NoError(t, BindServiceConfig(t.Context(), in, &out, WithEagerSecretResolution()))
	require.Len(t, out.Providers, 2)
	assert.Equal(t, "a", out.Providers[0].Name)
	assert.Equal(t, "b", out.Providers[1].Name)
	p0, _ := out.Providers[0].Password.Resolve(t.Context())
	p1, _ := out.Providers[1].Password.Resolve(t.Context())
	assert.Equal(t, "alpha", p0)
	assert.Equal(t, "b-pass", p1)
}
