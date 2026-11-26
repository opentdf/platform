package profilestore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zalando/go-keyring"
)

// Captured by the pinned go-osprofiles module with synthetic, nonsecret values.
const fixtureEncryptionKey = "0123456789abcdef0123456789abcdef"

type fixtureProfile struct {
	Name            string `json:"profile"`
	Endpoint        string `json:"endpoint"`
	TLSNoVerify     bool   `json:"tlsNoVerify"`
	OutputFormat    string `json:"outputFormat,omitempty"`
	AuthCredentials struct {
		AuthType     string   `json:"authType"`
		ClientID     string   `json:"clientId"`
		ClientSecret string   `json:"clientSecret,omitempty"`
		Scopes       []string `json:"scopes,omitempty"`
	} `json:"authCredentials"`
}

func (p *fixtureProfile) GetName() string { return p.Name }

func assertOriginalProfile(t *testing.T, p *fixtureProfile) {
	t.Helper()
	if p.Name != "alpha" || p.Endpoint != "https://example.invalid" || p.OutputFormat != "json" || p.AuthCredentials.AuthType != "client-credentials" || p.AuthCredentials.ClientID != "synthetic-id" || p.AuthCredentials.ClientSecret != "synthetic-not-a-secret" || len(p.AuthCredentials.Scopes) != 1 || p.AuthCredentials.Scopes[0] != "test:read" {
		t.Fatalf("original profile was not decoded intact: %+v", p)
	}
}

func prepareOriginalFileFixtures(t *testing.T) string {
	t.Helper()
	keyring.MockInit()
	dir := t.TempDir()
	files, err := os.ReadDir("testdata/original-files")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 6 {
		t.Fatalf("expected three encrypted and three metadata files, got %d", len(files))
	}
	for _, file := range files {
		if !strings.HasPrefix(file.Name(), "urn.goosprofiles.otdfctl_fixture.profile.v1.") {
			t.Fatalf("unexpected original filename: %s", file.Name())
		}
		data, err := os.ReadFile(filepath.Join("testdata/original-files", file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, file.Name()), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, key := range []string{"global", "profile-alpha", "profile-beta"} {
		if err := keyring.Set("urn.goosprofiles.otdfctl_fixture.profile.v1", key, fixtureEncryptionKey); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}
