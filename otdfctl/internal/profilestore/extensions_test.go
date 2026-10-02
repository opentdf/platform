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
