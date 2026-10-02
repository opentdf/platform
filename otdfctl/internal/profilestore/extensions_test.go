package profilestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/store"
	"github.com/zalando/go-keyring"
)

func TestOpaqueExtensionsRoundTrip(t *testing.T) {
	for _, driver := range []string{"memory", "file", "keyring"} {
		t.Run(driver, func(t *testing.T) {
			keyring.MockInit()
			ns := "extension_test"
			var option profileConfigVariadicFunc
			switch driver {
			case "memory":
				option = WithInMemoryStore()
			case "file":
				option = WithFileStore(t.TempDir())
			default:
				option = WithKeyringStore()
			}
			p, err := New(ns, option)
			if err != nil {
				t.Fatal(err)
			}
			if got, ok, err := GetGlobalConfig(p).Extension("owner"); err != nil || ok || got != nil {
				t.Fatalf("absent global: %s %v %v", got, ok, err)
			}
			if err := GetGlobalConfig(p).SetExtension("owner", json.RawMessage(`{"unknown":{"a":1}}`)); err != nil {
				t.Fatal(err)
			}
			if err := GetGlobalConfig(p).SetExtension("other", json.RawMessage(`null`)); err != nil {
				t.Fatal(err)
			}
			if err := p.AddProfile(&fixtureProfile{Name: "alpha"}, true); err != nil {
				t.Fatal(err)
			}
			current, err := GetCurrentProfile(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := current.SetExtension("owner", json.RawMessage(`{"future":[1,{"x":true}]}`)); err != nil {
				t.Fatal(err)
			}
			if err := current.SetExtension("other", json.RawMessage(`false`)); err != nil {
				t.Fatal(err)
			}
			currentProfile, ok := current.Profile.(*fixtureProfile)
			if !ok {
				t.Fatal("incorrect profile type")
			}
			currentProfile.Endpoint = "https://example.invalid"
			if err := current.Save(); err != nil {
				t.Fatal(err)
			}
			if err := SetDefaultProfile(p, "alpha"); err != nil {
				t.Fatal(err)
			}
			if err := GetGlobalConfig(p).SetExtension("owner", nil); !errors.Is(err, store.ErrInvalidExtensions) {
				t.Fatalf("nil accepted: %v", err)
			}
			if driver != "memory" {
				p, err = New(ns, option)
				if err != nil {
					t.Fatal(err)
				}
				current, err = GetProfile[*fixtureProfile](p, "alpha")
				if err != nil {
					t.Fatal(err)
				}
			}
			assertExtension(t, GetGlobalConfig(p).Extension, "owner", `{"unknown":{"a":1}}`)
			assertExtension(t, GetGlobalConfig(p).Extension, "other", `null`)
			assertExtension(t, current.Extension, "owner", `{"future":[1,{"x":true}]}`)
			assertExtension(t, current.Extension, "other", `false`)
			if currentProfile, ok = current.Profile.(*fixtureProfile); !ok || currentProfile.Endpoint != "https://example.invalid" {
				t.Fatal("core update lost")
			}
		})
	}
}

func assertExtension(t *testing.T, get func(string) (json.RawMessage, bool, error), name, want string) {
	t.Helper()
	got, ok, err := get(name)
	if err != nil || !ok || !bytes.Equal(got, []byte(want)) {
		t.Fatalf("extension %q: %s, present %v, err %v; want %s", name, got, ok, err, want)
	}
}

func TestMalformedExtensionsDoNotOverwrite(t *testing.T) {
	keyring.MockInit()
	const ns = "malformed_extension"
	original := `{"version":"1.0","profiles":[],"defaultProfile":"","extensions":[]}` + "\n"
	if err := keyring.Set(ns, "global", original); err != nil {
		t.Fatal(err)
	}
	if _, err := New(ns, WithKeyringStore()); !errors.Is(err, store.ErrInvalidExtensions) {
		t.Fatalf("malformed global accepted: %v", err)
	}
	got, err := keyring.Get(ns, "global")
	if err != nil || got != original {
		t.Fatalf("global overwritten: %q %v", got, err)
	}
	if err := keyring.Set(ns, "global", `{"version":"1.0","profiles":["alpha"],"defaultProfile":"alpha"}`); err != nil {
		t.Fatal(err)
	}
	profile := `{"profile":"alpha","extensions":"bad"}` + "\n"
	if err := keyring.Set(ns, "profile-alpha", profile); err != nil {
		t.Fatal(err)
	}
	p, err := New(ns, WithKeyringStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GetProfile[*fixtureProfile](p, "alpha"); !errors.Is(err, store.ErrInvalidExtensions) {
		t.Fatalf("malformed profile accepted: %v", err)
	}
	got, err = keyring.Get(ns, "profile-alpha")
	if err != nil || got != profile {
		t.Fatalf("profile overwritten: %q %v", got, err)
	}
}

func TestStaleHandleRejectsMalformedLatestWithoutOverwrite(t *testing.T) {
	keyring.MockInit()
	const ns = "stale_malformed_test"
	p, err := New(ns, WithKeyringStore())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AddProfile(&fixtureProfile{Name: "alpha"}, true); err != nil {
		t.Fatal(err)
	}
	profile, err := GetProfile[*fixtureProfile](p, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	const malformed = `{"profile":"alpha","extensions":[]}`
	if err := keyring.Set(ns, "profile-alpha", malformed); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetExtension("owner", json.RawMessage(`1`)); !errors.Is(err, store.ErrInvalidExtensions) {
		t.Fatalf("malformed latest configuration accepted: %v", err)
	}
	got, err := keyring.Get(ns, "profile-alpha")
	if err != nil || got != malformed {
		t.Fatalf("malformed data overwritten: %s %v", got, err)
	}
}

func TestPinnedOriginalFileFixtureExtensionSave(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	for _, key := range []string{"global", "profile-alpha", "profile-beta"} {
		if err := keyring.Set("urn.goosprofiles.otdfctl_fixture.profile.v1", key, fixtureEncryptionKey); err != nil {
			t.Fatal(err)
		}
	}
	files, err := os.ReadDir("testdata/original-files")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join("testdata/original-files", file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, file.Name()), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
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

func TestCoreSavePreservesUnknownNestedAndClearsOmitted(t *testing.T) {
	keyring.MockInit()
	const ns = "nested_core_test"
	if err := keyring.Set(ns, "global", `{"version":"1.0","profiles":["alpha"],"defaultProfile":"alpha"}`); err != nil {
		t.Fatal(err)
	}
	original := `{"profile":"alpha","endpoint":"old","outputFormat":"json","authCredentials":{"authType":"client-credentials","clientId":"old","clientSecret":"old","future":{"inner":7},"accessToken":{"clientId":"old","accessToken":"old","refreshToken":"old","expiration":1,"futureToken":true}},"futureTop":[1,2]}`
	if err := keyring.Set(ns, "profile-alpha", original); err != nil {
		t.Fatal(err)
	}
	p, err := New(ns, WithKeyringStore())
	if err != nil {
		t.Fatal(err)
	}
	profile, err := GetProfile[*fixtureProfile](p, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	core, ok := profile.Profile.(*fixtureProfile)
	if !ok {
		t.Fatal("incorrect profile type")
	}
	core.Endpoint = "new"
	core.OutputFormat = ""
	core.AuthCredentials.ClientID = "new"
	core.AuthCredentials.ClientSecret = ""
	if err := profile.Save(); err != nil {
		t.Fatal(err)
	}
	data, err := keyring.Get(ns, "profile-alpha")
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]json.RawMessage
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		t.Fatal(err)
	}
	if _, present := result["outputFormat"]; present {
		t.Fatal("omitted output format retained")
	}
	if string(result["futureTop"]) != `[1,2]` || string(result["endpoint"]) != `"new"` {
		t.Fatalf("top-level fields changed: %s", data)
	}
	var auth map[string]json.RawMessage
	if err := json.Unmarshal(result["authCredentials"], &auth); err != nil {
		t.Fatal(err)
	}
	if _, present := auth["clientSecret"]; present {
		t.Fatal("omitted client secret retained")
	}
	if string(auth["future"]) != `{"inner":7}` || string(auth["clientId"]) != `"new"` {
		t.Fatalf("auth fields changed: %s", data)
	}
}

func TestSequentialStaleCoreSavesPreserveOpaqueFields(t *testing.T) {
	for _, driver := range []string{"file", "keyring"} {
		t.Run(driver, func(t *testing.T) {
			keyring.MockInit()
			option := WithKeyringStore()
			if driver == "file" {
				option = WithFileStore(t.TempDir())
			}
			const ns = "stale_core_save_test"
			first, err := New(ns, option)
			if err != nil {
				t.Fatal(err)
			}
			if err := first.AddProfile(&fixtureProfile{Name: "alpha"}, true); err != nil {
				t.Fatal(err)
			}
			second, err := New(ns, option)
			if err != nil {
				t.Fatal(err)
			}
			firstProfile, err := GetProfile[*fixtureProfile](first, "alpha")
			if err != nil {
				t.Fatal(err)
			}
			secondProfile, err := GetProfile[*fixtureProfile](second, "alpha")
			if err != nil {
				t.Fatal(err)
			}
			if err := secondProfile.SetExtension("owner", json.RawMessage(`{"value":1}`)); err != nil {
				t.Fatal(err)
			}
			if err := GetGlobalConfig(second).SetExtension("owner", json.RawMessage(`{"value":2}`)); err != nil {
				t.Fatal(err)
			}
			core, ok := firstProfile.Profile.(*fixtureProfile)
			if !ok {
				t.Fatal("incorrect profile type")
			}
			core.Endpoint = "https://new.invalid"
			if err := firstProfile.Save(); err != nil {
				t.Fatal(err)
			}
			if err := GetGlobalConfig(first).SetDefaultProfile("alpha"); err != nil {
				t.Fatal(err)
			}
			loaded, err := New(ns, option)
			if err != nil {
				t.Fatal(err)
			}
			loadedProfile, err := GetProfile[*fixtureProfile](loaded, "alpha")
			if err != nil {
				t.Fatal(err)
			}
			assertExtension(t, loadedProfile.Extension, "owner", `{"value":1}`)
			assertExtension(t, GetGlobalConfig(loaded).Extension, "owner", `{"value":2}`)
			loadedCore, ok := loadedProfile.Profile.(*fixtureProfile)
			if !ok || loadedCore.Endpoint != "https://new.invalid" {
				t.Fatal("core save lost")
			}
		})
	}
}

func TestStaleCoreSavePreservesLatestUnknownFields(t *testing.T) {
	keyring.MockInit()
	const ns = "stale_core_unknown_test"
	p, err := New(ns, WithKeyringStore())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AddProfile(&fixtureProfile{Name: "alpha"}, true); err != nil {
		t.Fatal(err)
	}
	profile, err := GetProfile[*fixtureProfile](p, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	const latestProfile = `{"profile":"alpha","futureTop":1,"authCredentials":{"futureAuth":2,"accessToken":{"futureToken":3}}}`
	const latestGlobal = `{"version":"1.0","profiles":["alpha"],"defaultProfile":"alpha","futureGlobal":4}`
	if err := keyring.Set(ns, "profile-alpha", latestProfile); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Set(ns, "global", latestGlobal); err != nil {
		t.Fatal(err)
	}
	core, ok := profile.Profile.(*fixtureProfile)
	if !ok {
		t.Fatal("incorrect profile type")
	}
	core.Endpoint = "updated"
	if err := profile.Save(); err != nil {
		t.Fatal(err)
	}
	if err := GetGlobalConfig(p).SetDefaultProfile("alpha"); err != nil {
		t.Fatal(err)
	}
	got, err := keyring.Get(ns, "profile-alpha")
	if err != nil || !bytes.Contains([]byte(got), []byte(`"futureTop":1`)) ||
		!bytes.Contains([]byte(got), []byte(`"futureAuth":2`)) ||
		!bytes.Contains([]byte(got), []byte(`"futureToken":3`)) ||
		!bytes.Contains([]byte(got), []byte(`"endpoint":"updated"`)) {
		t.Fatalf("latest profile fields lost: %s %v", got, err)
	}
	got, err = keyring.Get(ns, "global")
	if err != nil || !bytes.Contains([]byte(got), []byte(`"futureGlobal":4`)) {
		t.Fatalf("latest global field lost: %s %v", got, err)
	}
}

func TestStaleCoreSaveRejectsMalformedLatest(t *testing.T) {
	keyring.MockInit()
	const ns = "stale_core_malformed_test"
	p, err := New(ns, WithKeyringStore())
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AddProfile(&fixtureProfile{Name: "alpha"}, true); err != nil {
		t.Fatal(err)
	}
	profile, err := GetProfile[*fixtureProfile](p, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	const malformed = `{"profile":"alpha","extensions":[]}`
	if err := keyring.Set(ns, "profile-alpha", malformed); err != nil {
		t.Fatal(err)
	}
	if err := profile.Save(); !errors.Is(err, store.ErrInvalidExtensions) {
		t.Fatalf("profile core save accepted malformed latest: %v", err)
	}
	got, err := keyring.Get(ns, "profile-alpha")
	if err != nil || got != malformed {
		t.Fatalf("profile overwritten: %s %v", got, err)
	}
	if err := keyring.Set(ns, "global", malformed); err != nil {
		t.Fatal(err)
	}
	if err := GetGlobalConfig(p).SetDefaultProfile("alpha"); !errors.Is(err, store.ErrInvalidExtensions) {
		t.Fatalf("global core save accepted malformed latest: %v", err)
	}
	got, err = keyring.Get(ns, "global")
	if err != nil || got != malformed {
		t.Fatalf("global overwritten: %s %v", got, err)
	}
}

func TestSequentialStaleHandlesRebaseExtensions(t *testing.T) {
	for _, driver := range []string{"file", "keyring"} {
		t.Run(driver, func(t *testing.T) {
			keyring.MockInit()
			option := WithKeyringStore()
			if driver == "file" {
				option = WithFileStore(t.TempDir())
			}
			const ns = "stale_handles_test"
			first, err := New(ns, option)
			if err != nil {
				t.Fatal(err)
			}
			if err := first.AddProfile(&fixtureProfile{Name: "alpha"}, true); err != nil {
				t.Fatal(err)
			}
			second, err := New(ns, option)
			if err != nil {
				t.Fatal(err)
			}
			firstProfile, err := GetProfile[*fixtureProfile](first, "alpha")
			if err != nil {
				t.Fatal(err)
			}
			secondProfile, err := GetProfile[*fixtureProfile](second, "alpha")
			if err != nil {
				t.Fatal(err)
			}
			if err := firstProfile.SetExtension("a", json.RawMessage(`1`)); err != nil {
				t.Fatal(err)
			}
			if err := secondProfile.SetExtension("b", json.RawMessage(`2`)); err != nil {
				t.Fatal(err)
			}
			if err := GetGlobalConfig(first).SetExtension("a", json.RawMessage(`1`)); err != nil {
				t.Fatal(err)
			}
			if err := GetGlobalConfig(second).SetExtension("b", json.RawMessage(`2`)); err != nil {
				t.Fatal(err)
			}
			loaded, err := New(ns, option)
			if err != nil {
				t.Fatal(err)
			}
			loadedProfile, err := GetProfile[*fixtureProfile](loaded, "alpha")
			if err != nil {
				t.Fatal(err)
			}
			for _, get := range []func(string) (json.RawMessage, bool, error){loadedProfile.Extension, GetGlobalConfig(loaded).Extension} {
				assertExtension(t, get, "a", `1`)
				assertExtension(t, get, "b", `2`)
			}
		})
	}
}
