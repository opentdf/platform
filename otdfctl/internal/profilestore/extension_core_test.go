package profilestore

import (
	"encoding/json"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestProfileExtensionPreservesLatestCoreAcrossEscapedDuplicateKeys(t *testing.T) {
	for _, driver := range []string{"memory", "file", "keyring"} {
		t.Run(driver, func(t *testing.T) {
			keyring.MockInit()
			option := WithInMemoryStore()
			switch driver {
			case "file":
				option = WithFileStore(t.TempDir())
			case "keyring":
				option = WithKeyringStore()
			}
			p, err := New("extension_core_test", option)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.AddProfile(&fixtureProfile{Name: "alpha", Endpoint: "https://stale.invalid"}, true); err != nil {
				t.Fatal(err)
			}
			profile, err := GetCurrentProfile(p)
			if err != nil {
				t.Fatal(err)
			}
			// Both spellings decode to authCredentials. encoding/json merges
			// their typed struct fields, while a RawMessage map keeps only the last.
			const latest = `{"profile":"alpha","endpoint":"https://latest.invalid","authCredentials":{"clientId":"latest-id"},"\u0061uthCredentials":{"clientSecret":"latest-secret","futureAuth":true},"futureTop":42,"extensions":{"other":false}}`
			if err := profile.store.Set(json.RawMessage(latest)); err != nil {
				t.Fatal(err)
			}
			if err := profile.SetExtension("owner", json.RawMessage(`1`)); err != nil {
				t.Fatal(err)
			}
			data, err := profile.store.Get()
			if err != nil {
				t.Fatal(err)
			}
			var core fixtureProfile
			if err := json.Unmarshal(data, &core); err != nil {
				t.Fatal(err)
			}
			if core.Endpoint != "https://latest.invalid" || core.AuthCredentials.ClientID != "latest-id" || core.AuthCredentials.ClientSecret != "latest-secret" {
				t.Fatalf("extension write lost or replaced latest core: %+v", core)
			}
			var fields struct {
				FutureTop int `json:"futureTop"`
				Auth      struct {
					Future bool `json:"futureAuth"`
				} `json:"authCredentials"`
			}
			if err := json.Unmarshal(data, &fields); err != nil || fields.FutureTop != 42 || !fields.Auth.Future {
				t.Fatalf("extension write lost opaque data: %s %v", data, err)
			}
			assertExtension(t, profile.Extension, "other", `false`)
			assertExtension(t, profile.Extension, "owner", `1`)
		})
	}
}
