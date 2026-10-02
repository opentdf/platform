package profiles

import (
	"encoding/json"
	"errors"
	"runtime"
	"testing"

	osprofiles "github.com/opentdf/platform/otdfctl/internal/profilestore"
	osplatform "github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/platform"
	"github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/store"
	"github.com/opentdf/platform/otdfctl/pkg/config"
	"github.com/zalando/go-keyring"
)

func TestMigrateSourceAliasConflictBeforeAnyDestinationWrite(t *testing.T) {
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("LOCALAPPDATA", t.TempDir())
	target, err := CreateProfiler(ProfileDriverFileSystem)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.AddProfile(&ProfileConfig{Name: "existing", Endpoint: "https://existing.invalid"}, true); err != nil {
		t.Fatal(err)
	}
	platform, err := osplatform.NewPlatform(config.ServicePublisher, config.AppName, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	destinationGlobal, err := store.NewFileStore(config.AppName, "global", store.WithStoreDirectory(platform.UserAppConfigDirectory()))
	if err != nil {
		t.Fatal(err)
	}
	beforeGlobal, err := destinationGlobal.Get()
	if err != nil {
		t.Fatal(err)
	}
	destinationExisting, err := store.NewFileStore(config.AppName, "profile-existing", store.WithStoreDirectory(platform.UserAppConfigDirectory()))
	if err != nil {
		t.Fatal(err)
	}
	beforeExisting, err := destinationExisting.Get()
	if err != nil {
		t.Fatal(err)
	}
	const sourceGlobal = `{"version":"1.0","profiles":["alpha","beta"],"defaultProfile":"beta"}`
	const sourceAlpha = `{"profile":"alpha","authCredentials":{"future":1}}`
	const sourceBeta = `{"profile":"beta","authCredentials":{"future":1},"AUTHCREDENTIALS":{"future":2}}`
	for key, value := range map[string]string{"global": sourceGlobal, "profile-alpha": sourceAlpha, "profile-beta": sourceBeta} {
		if err := keyring.Set(config.AppName, key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); !errors.Is(err, store.ErrOpaqueConflict) {
		t.Fatalf("source aliases did not fail preflight: %v", err)
	}
	for key, want := range map[string]string{"global": sourceGlobal, "profile-alpha": sourceAlpha, "profile-beta": sourceBeta} {
		got, err := keyring.Get(config.AppName, key)
		if err != nil || got != want {
			t.Fatalf("source %q changed after alias conflict", key)
		}
	}
	for _, test := range []struct {
		name string
		raw  store.Interface
		want []byte
	}{{"global index/default", destinationGlobal, beforeGlobal}, {"existing profile", destinationExisting, beforeExisting}} {
		got, err := test.raw.Get()
		if err != nil || string(got) != string(test.want) {
			t.Fatalf("destination %s changed after alias conflict", test.name)
		}
	}
	for _, name := range []string{"alpha", "beta"} {
		raw, err := store.NewFileStore(config.AppName, "profile-"+name, store.WithStoreDirectory(platform.UserAppConfigDirectory()))
		if err != nil {
			t.Fatal(err)
		}
		if raw.Exists() {
			t.Fatalf("destination profile %q written before source alias validation", name)
		}
	}
}

func TestMigrateNonconflictingSourceAliasesPreservesUnknown(t *testing.T) {
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("LOCALAPPDATA", t.TempDir())
	if err := keyring.Set(config.AppName, "global", `{"version":"1.0","profiles":["alpha"],"defaultProfile":"alpha"}`); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Set(config.AppName, "profile-alpha", `{"profile":"alpha","authCredentials":{"future":1,"accessToken":{"futureToken":3}},"AUTHCREDENTIALS":{"otherFuture":2,"ACCESSTOKEN":{"otherToken":4}}}`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); err != nil {
		t.Fatal(err)
	}
	target, err := CreateProfiler(ProfileDriverFileSystem)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := osprofiles.GetProfile[*ProfileConfig](target, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	// A subsequent save must retain both aliases' opaque members as well.
	if err := profile.Save(); err != nil {
		t.Fatal(err)
	}
	platform, err := osplatform.NewPlatform(config.ServicePublisher, config.AppName, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := store.NewFileStore(config.AppName, "profile-alpha", store.WithStoreDirectory(platform.UserAppConfigDirectory()))
	if err != nil {
		t.Fatal(err)
	}
	data, err := raw.Get()
	if err != nil {
		t.Fatal(err)
	}
	var fields struct {
		Auth struct {
			Future      int `json:"future"`
			OtherFuture int `json:"otherFuture"`
			Token       struct {
				FutureToken int `json:"futureToken"`
				OtherToken  int `json:"otherToken"`
			} `json:"accessToken"`
		} `json:"authCredentials"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if fields.Auth.Future != 1 || fields.Auth.OtherFuture != 2 || fields.Auth.Token.FutureToken != 3 || fields.Auth.Token.OtherToken != 4 {
		t.Fatal("migration lost nonconflicting alias unknowns")
	}
	if osprofiles.GetGlobalConfig(target).GetDefaultProfile() != "alpha" {
		t.Fatal("migration changed default profile")
	}
}
