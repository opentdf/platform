package profiles

import (
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
