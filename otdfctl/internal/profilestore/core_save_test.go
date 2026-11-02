package profilestore

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/store"
	"github.com/zalando/go-keyring"
)

func TestSequentialStaleCoreSavesPreserveExtensions(t *testing.T) {
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
