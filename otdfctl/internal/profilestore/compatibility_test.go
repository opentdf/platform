package profilestore

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestPinnedOriginalFileFixtures(t *testing.T) {
	dir := prepareOriginalFileFixtures(t)
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

func TestPinnedOriginalFileFixtureExtensionSave(t *testing.T) {
	dir := prepareOriginalFileFixtures(t)
	p, err := New("otdfctl_fixture", WithFileStore(dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := GetGlobalConfig(p).SetExtension("future", json.RawMessage(`{"x":1}`)); err != nil {
		t.Fatal(err)
	}
	alpha, err := GetProfile[*fixtureProfile](p, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	original, ok := alpha.Profile.(*fixtureProfile)
	if !ok {
		t.Fatal("incorrect profile type")
	}
	assertOriginalProfile(t, original)
	if err := alpha.SetExtension("future", json.RawMessage(`{"x":2}`)); err != nil {
		t.Fatal(err)
	}
	original.TLSNoVerify = true
	if err := alpha.Save(); err != nil {
		t.Fatal(err)
	}
	p, err = New("otdfctl_fixture", WithFileStore(dir))
	if err != nil {
		t.Fatal(err)
	}
	alpha, err = GetProfile[*fixtureProfile](p, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	updated, ok := alpha.Profile.(*fixtureProfile)
	if !ok || !updated.TLSNoVerify {
		t.Fatal("core update missing")
	}
	assertExtension(t, alpha.Extension, "future", `{"x":2}`)
	assertExtension(t, GetGlobalConfig(p).Extension, "future", `{"x":1}`)
}
