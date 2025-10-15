package config

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
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
	if err := os.WriteFile(fp, []byte("from-file\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	yaml := "" +
		"secrets:\n" +
		"  - \"env:OPENTDF_YAML_ARR\"\n" +
		"  - { fromFile: \"" + fp + "\" }\n" +
		"  - \"literal:abc\"\n"

	v := viper.New()
	v.SetConfigType("yaml")
	if err := v.ReadConfig(bytes.NewBufferString(yaml)); err != nil {
		t.Fatalf("read yaml: %v", err)
	}

	in := ServiceConfig{
		"secrets": v.Get("secrets"),
	}
	var out arrayCfg
	if err := BindServiceConfig(context.Background(), in, &out, WithEagerSecretResolution()); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if len(out.Secrets) != 3 {
		t.Fatalf("expected 3 secrets, got %d", len(out.Secrets))
	}
	s0, _ := out.Secrets[0].Resolve(context.Background())
	s1, _ := out.Secrets[1].Resolve(context.Background())
	s2, _ := out.Secrets[2].Resolve(context.Background())
	if s0 != "arr-env" || s1 != "from-file" || s2 != "abc" {
		t.Fatalf("values mismatch: %q %q %q", s0, s1, s2)
	}
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
	if err := v.ReadConfig(bytes.NewBufferString(yaml)); err != nil {
		t.Fatalf("read yaml: %v", err)
	}

	in := ServiceConfig{
		"providers": v.Get("providers"),
	}
	var out providersCfg
	if err := BindServiceConfig(context.Background(), in, &out, WithEagerSecretResolution()); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if len(out.Providers) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(out.Providers))
	}
	if out.Providers[0].Name != "a" || out.Providers[1].Name != "b" {
		t.Fatalf("names mismatch: %q %q", out.Providers[0].Name, out.Providers[1].Name)
	}
	p0, _ := out.Providers[0].Password.Resolve(context.Background())
	p1, _ := out.Providers[1].Password.Resolve(context.Background())
	if p0 != "alpha" || p1 != "b-pass" {
		t.Fatalf("passwords mismatch: %q %q", p0, p1)
	}
}
