package profilestore

import (
	"encoding/json"
	"errors"
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

func TestPinnedOriginalFileFixtures(t *testing.T) {
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
	p, err := New("otdfctl_fixture", WithFileStore(dir))
	if err != nil {
		t.Fatal(err)
	}
	if got := GetGlobalConfig(p).GetDefaultProfile(); got != "alpha" {
		t.Fatalf("original default: %q", got)
	}
	if got := ListProfiles(p); len(got) != 2 || got[0] != "alpha" || got[1] != "beta" {
		t.Fatalf("original profiles: %v", got)
	}
	alpha, err := GetProfile[*fixtureProfile](p, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	alphaProfile, ok := alpha.Profile.(*fixtureProfile)
	if !ok {
		t.Fatalf("unexpected profile type: %T", alpha.Profile)
	}
	assertOriginalProfile(t, alphaProfile)
	if err := SetDefaultProfile(p, "beta"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteProfile[*fixtureProfile](p, "alpha"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteProfile[*fixtureProfile](p, "beta"); !errors.Is(err, ErrCannotDeleteDefaultProfile) {
		t.Fatalf("expected default protection, got %v", err)
	}
	if err := SetDefaultProfile(p, "alpha"); err == nil {
		t.Fatal("deleted profile can be selected")
	}
}

func TestPinnedOriginalKeyringFixtures(t *testing.T) {
	keyring.MockInit()
	const ns = "otdfctl_keyring_fixture"
	// Captured directly from original keyring mock Get(ns, key) after New/AddProfile.
	for key, value := range map[string]string{
		"global":        `{"version":"1.0","profiles":["alpha"],"defaultProfile":"alpha"}` + "\n",
		"profile-alpha": `{"profile":"alpha","endpoint":"https://example.invalid","tlsNoVerify":false,"outputFormat":"json","authCredentials":{"authType":"client-credentials","clientId":"synthetic-id","clientSecret":"synthetic-not-a-secret","scopes":["test:read"]}}` + "\n",
	} {
		if err := keyring.Set(ns, key, value); err != nil {
			t.Fatal(err)
		}
	}
	p, err := New(ns, WithKeyringStore())
	if err != nil {
		t.Fatal(err)
	}
	if got := GetGlobalConfig(p).GetDefaultProfile(); got != "alpha" {
		t.Fatalf("original default: %q", got)
	}
	stored, err := GetProfile[*fixtureProfile](p, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	storedProfile, ok := stored.Profile.(*fixtureProfile)
	if !ok {
		t.Fatalf("unexpected profile type: %T", stored.Profile)
	}
	assertOriginalProfile(t, storedProfile)
	storedProfile.TLSNoVerify = true
	if err := stored.Save(); err != nil {
		t.Fatal(err)
	}
	raw, err := keyring.Get(ns, "profile-alpha")
	if err != nil {
		t.Fatal(err)
	}
	var updated fixtureProfile
	if err := json.Unmarshal([]byte(raw), &updated); err != nil {
		t.Fatal(err)
	}
	if !updated.TLSNoVerify {
		t.Fatal("update did not preserve keyring identity")
	}
}

func TestProfileLifecycleInMemory(t *testing.T) {
	p, err := New("memory_fixture", WithInMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AddProfile(&fixtureProfile{Name: "first"}, true); err != nil {
		t.Fatal(err)
	}
	if err := p.AddProfile(&fixtureProfile{Name: "second"}, false); err != nil {
		t.Fatal(err)
	}
	if err := SetDefaultProfile(p, "second"); err != nil {
		t.Fatal(err)
	}
	// The original in-memory driver creates a new map per key and cannot reload
	// profiles by name; deletion is exercised with the file fixture above.
	if got := GetGlobalConfig(p).GetDefaultProfile(); got != "second" {
		t.Fatalf("default changed: %q", got)
	}
}

func assertOriginalProfile(t *testing.T, p *fixtureProfile) {
	t.Helper()
	if p.Name != "alpha" || p.Endpoint != "https://example.invalid" || p.OutputFormat != "json" || p.AuthCredentials.AuthType != "client-credentials" || p.AuthCredentials.ClientID != "synthetic-id" || p.AuthCredentials.ClientSecret != "synthetic-not-a-secret" || len(p.AuthCredentials.Scopes) != 1 || p.AuthCredentials.Scopes[0] != "test:read" {
		t.Fatalf("original profile was not decoded intact: %+v", p)
	}
}
