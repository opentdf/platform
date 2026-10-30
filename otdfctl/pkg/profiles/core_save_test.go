package profiles

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/opentdf/platform/otdfctl/pkg/config"
	"github.com/zalando/go-keyring"
)

func TestSetAuthCredentialsClearsAliasesOnReload(t *testing.T) {
	keyring.MockInit()
	if err := keyring.Set(config.AppName, "global", `{"version":"1.0","profiles":["alpha"],"defaultProfile":"alpha"}`); err != nil {
		t.Fatal(err)
	}
	const original = `{"profile":"alpha","authCredentials":{"authtype":"client-credentials","clientid":"old-id","clientsecret":"synthetic-secret","futureAuth":true}}`
	if err := keyring.Set(config.AppName, "profile-alpha", original); err != nil {
		t.Fatal(err)
	}
	profile, err := LoadOtdfctlProfileStore(ProfileDriverKeyring, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	credentials := profile.GetAuthCredentials()
	credentials.ClientID = "new-id"
	if err := profile.SetAuthCredentials(credentials); err != nil {
		t.Fatal(err)
	}
	profile, err = LoadOtdfctlProfileStore(ProfileDriverKeyring, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if profile.GetAuthCredentials().ClientID != "new-id" {
		t.Fatal("aliased client ID defeated setter")
	}
	// This is the same clearing call used by logout.
	if err := profile.SetAuthCredentials(AuthCredentials{}); err != nil {
		t.Fatal(err)
	}
	profile, err = LoadOtdfctlProfileStore(ProfileDriverKeyring, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	credentials = profile.GetAuthCredentials()
	if credentials.AuthType != "" || credentials.ClientID != "" || credentials.ClientSecret != "" {
		t.Fatal("logout credentials restored from core aliases")
	}
	data, err := keyring.Get(config.AppName, "profile-alpha")
	if err != nil || !strings.Contains(data, `"futureAuth":true`) || strings.Contains(data, "synthetic-secret") {
		t.Fatal("clearing lost opaque fields or retained secret")
	}
}

func TestProfileCoreSettersPreserveUnknownNestedCredentials(t *testing.T) {
	keyring.MockInit()
	const global = `{"version":"1.0","profiles":["alpha"],"defaultProfile":"alpha"}`
	const profile = `{"profile":"alpha","endpoint":"https://old.invalid","outputFormat":"json","authCredentials":{"authType":"access-token","clientId":"old","futureAuth":{"flag":true},"accessToken":{"clientId":"id","accessToken":"token","refreshToken":"refresh","expiration":10,"futureToken":42}}}`
	if err := keyring.Set(config.AppName, "global", global); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Set(config.AppName, "profile-alpha", profile); err != nil {
		t.Fatal(err)
	}
	stored, err := LoadOtdfctlProfileStore(ProfileDriverKeyring, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if err := stored.SetEndpoint("https://new.invalid"); err != nil {
		t.Fatal(err)
	}
	credentials := stored.GetAuthCredentials()
	credentials.ClientID = "new"
	credentials.AccessToken.Expiration = 11
	if err := stored.SetAuthCredentials(credentials); err != nil {
		t.Fatal(err)
	}
	data, err := keyring.Get(config.AppName, "profile-alpha")
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Endpoint        string `json:"endpoint"`
		AuthCredentials struct {
			ClientID    string          `json:"clientId"`
			FutureAuth  json.RawMessage `json:"futureAuth"`
			AccessToken struct {
				Expiration  int64           `json:"expiration"`
				FutureToken json.RawMessage `json:"futureToken"`
			} `json:"accessToken"`
		} `json:"authCredentials"`
	}
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		t.Fatal(err)
	}
	if result.Endpoint != "https://new.invalid:443" || result.AuthCredentials.ClientID != "new" || result.AuthCredentials.AccessToken.Expiration != 11 || string(result.AuthCredentials.FutureAuth) != `{"flag":true}` || string(result.AuthCredentials.AccessToken.FutureToken) != `42` {
		t.Fatalf("core update erased unknown nested fields: %s", data)
	}
}
