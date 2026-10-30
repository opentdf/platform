package profilestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/store"
	"github.com/zalando/go-keyring"
)

type aliasProfile struct {
	Name            string `json:"profile"`
	AuthCredentials struct {
		AuthType     string `json:"authType"`
		ClientID     string `json:"clientId"`
		ClientSecret string `json:"clientSecret,omitempty"`
		AccessToken  struct {
			ClientID    string `json:"clientId"`
			AccessToken string `json:"accessToken"`
		} `json:"accessToken"`
	} `json:"authCredentials"`
}

func (p *aliasProfile) GetName() string { return p.Name }

func TestCoreSaveClearsCredentialAliasesAcrossDrivers(t *testing.T) {
	for _, driver := range []string{"file", "keyring"} {
		t.Run(driver, func(t *testing.T) {
			keyring.MockInit()
			const namespace = "core_alias_test"
			option := WithKeyringStore()
			newStore := store.NewKeyringStore
			if driver == "file" {
				option = WithFileStore(t.TempDir())
				newStore = store.NewFileStore
			}
			profiler, err := New(namespace, option)
			if err != nil {
				t.Fatal(err)
			}
			if err := profiler.AddProfile(&aliasProfile{Name: "alpha"}, true); err != nil {
				t.Fatal(err)
			}
			rawStore, err := newStore(namespace, "profile-alpha")
			if err != nil {
				t.Fatal(err)
			}
			original := json.RawMessage(`{"PROFILE":"alpha","AUTHCREDENTIALS":{"AUTHTYPE":"client-credentials","clientid":"old-id","ClientSecret":"synthetic-secret","futureAuth":1,"ACCESSTOKEN":{"CLIENTID":"old-token-id","ACCESSTOKEN":"synthetic-token","futureToken":2}},"futureTop":3}`)
			if err := rawStore.Set(original); err != nil {
				t.Fatal(err)
			}
			profile, err := GetProfile[*aliasProfile](profiler, "alpha")
			if err != nil {
				t.Fatal(err)
			}
			core, ok := profile.Profile.(*aliasProfile)
			if !ok || core.AuthCredentials.ClientSecret != "synthetic-secret" {
				t.Fatal("fixture aliases did not decode")
			}
			core.AuthCredentials.ClientID = "new-id"
			core.AuthCredentials.ClientSecret = ""
			core.AuthCredentials.AccessToken.AccessToken = ""
			if err := profile.Save(); err != nil {
				t.Fatal(err)
			}
			reloaded, err := GetProfile[*aliasProfile](profiler, "alpha")
			if err != nil {
				t.Fatal(err)
			}
			updated, ok := reloaded.Profile.(*aliasProfile)
			if !ok || updated.AuthCredentials.ClientID != "new-id" || updated.AuthCredentials.ClientSecret != "" || updated.AuthCredentials.AccessToken.AccessToken != "" {
				t.Fatal("credential aliases defeated core update or clearing")
			}
			data, err := rawStore.Get()
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"futureAuth":1`, `"futureToken":2`, `"futureTop":3`} {
				if !bytes.Contains(data, []byte(want)) {
					t.Fatalf("unknown %s lost", want)
				}
			}
			if bytes.Contains(data, []byte("synthetic-secret")) || bytes.Contains(data, []byte("synthetic-token")) {
				t.Fatal("cleared credential persisted")
			}
		})
	}
}

func TestCoreSaveRejectsConflictingParentAliasesWithoutWrite(t *testing.T) {
	keyring.MockInit()
	const namespace = "conflicting_alias_test"
	profiler, err := New(namespace, WithKeyringStore())
	if err != nil {
		t.Fatal(err)
	}
	if err := profiler.AddProfile(&fixtureProfile{Name: "alpha"}, true); err != nil {
		t.Fatal(err)
	}
	const original = `{"profile":"alpha","authCredentials":{"future":1},"AUTHCREDENTIALS":{"future":2}}`
	if err := keyring.Set(namespace, "profile-alpha", original); err != nil {
		t.Fatal(err)
	}
	profile, err := GetProfile[*fixtureProfile](profiler, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.Save(); !errors.Is(err, store.ErrOpaqueConflict) {
		t.Fatalf("conflicting aliases accepted: %v", err)
	}
	got, err := keyring.Get(namespace, "profile-alpha")
	if err != nil || got != original {
		t.Fatal("persisted profile changed after rejected save")
	}
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
