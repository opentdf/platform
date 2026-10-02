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
