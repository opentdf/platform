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

func TestMigrateGlobalOnlySameDriverPreservesSource(t *testing.T) {
	keyring.MockInit()
	const original = `{"version":"1.0","profiles":[],"defaultProfile":"","futureGlobal":1,"extensions":{"alpha":{"enabled":true}}}`
	if err := keyring.Set(config.AppName, "global", original); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ProfileDriverKeyring, ProfileDriverKeyring); err != nil {
		t.Fatal(err)
	}
	got, err := keyring.Get(config.AppName, "global")
	if err != nil || got != original {
		t.Fatal("same-driver migration changed or deleted the global-only source")
	}
}

func TestMigrateGlobalOnlyConflictBeforeCleanup(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("filesystem location not asserted on this OS")
	}
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	const sourceGlobal = `{"version":"1.0","profiles":[],"defaultProfile":"","futureGlobal":1}`
	if err := keyring.Set(config.AppName, "global", sourceGlobal); err != nil {
		t.Fatal(err)
	}
	// First copy the opaque global field into the filesystem, then change the
	// keyring copy to create a conflicting source without manufacturing a profile.
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Set(config.AppName, "global", `{"version":"1.0","profiles":[],"defaultProfile":"","futureGlobal":2}`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); !errors.Is(err, store.ErrOpaqueConflict) {
		t.Fatalf("global conflict not reported: %v", err)
	}
	got, err := keyring.Get(config.AppName, "global")
	if err != nil || got != `{"version":"1.0","profiles":[],"defaultProfile":"","futureGlobal":2}` {
		t.Fatalf("source changed on conflict: %s %v", got, err)
	}
	target, err := CreateProfiler(ProfileDriverFileSystem)
	if err != nil {
		t.Fatal(err)
	}
	if string(osprofiles.GetGlobalConfig(target).UnknownFields()["futureGlobal"]) != `1` || len(osprofiles.ListProfiles(target)) != 0 {
		t.Fatal("destination mutated or profile manufactured")
	}
}

func TestMigrateNestedUnknownConflictBeforeWriting(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("filesystem location not asserted on this OS")
	}
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	const global = `{"version":"1.0","profiles":["alpha"],"defaultProfile":"alpha"}`
	const destinationProfile = `{"profile":"alpha","endpoint":"https://example.invalid","authCredentials":{"futureAuth":1,"accessToken":{"futureToken":1}}}`
	if err := keyring.Set(config.AppName, "global", global); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Set(config.AppName, "profile-alpha", destinationProfile); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); err != nil {
		t.Fatal(err)
	}
	for _, change := range []string{
		`{"profile":"alpha","endpoint":"https://example.invalid","authCredentials":{"futureAuth":2,"accessToken":{"futureToken":1}}}`,
		`{"profile":"alpha","endpoint":"https://example.invalid","authCredentials":{"futureAuth":1,"accessToken":{"futureToken":2}}}`,
	} {
		if err := keyring.Set(config.AppName, "global", global); err != nil {
			t.Fatal(err)
		}
		if err := keyring.Set(config.AppName, "profile-alpha", change); err != nil {
			t.Fatal(err)
		}
		if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); !errors.Is(err, store.ErrOpaqueConflict) {
			t.Fatalf("nested unknown conflict not reported: %v", err)
		}
		got, err := keyring.Get(config.AppName, "profile-alpha")
		if err != nil || got != change {
			t.Fatalf("source changed on conflict: %s %v", got, err)
		}
	}
}

func TestMigrateProfileNamespaceConflictBeforeWriting(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("filesystem location not asserted on this OS")
	}
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	source, err := CreateProfiler(ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.AddProfile(&ProfileConfig{Name: "alpha", Endpoint: "https://source.invalid"}, true); err != nil {
		t.Fatal(err)
	}
	profile, err := osprofiles.GetCurrentProfile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.SetExtension("owner", json.RawMessage(`1`)); err != nil {
		t.Fatal(err)
	}
	original, err := keyring.Get(config.AppName, "profile-alpha")
	if err != nil {
		t.Fatal(err)
	}
	target, err := CreateProfiler(ProfileDriverFileSystem)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.AddProfile(&ProfileConfig{Name: "alpha", Endpoint: "https://target.invalid"}, true); err != nil {
		t.Fatal(err)
	}
	destination, err := osprofiles.GetCurrentProfile(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := destination.SetExtension("owner", json.RawMessage(`2`)); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); !errors.Is(err, store.ErrOpaqueConflict) {
		t.Fatalf("profile conflict not reported: %v", err)
	}
	got, err := keyring.Get(config.AppName, "profile-alpha")
	if err != nil || got != original {
		t.Fatalf("source changed: %s %v", got, err)
	}
	reloaded, err := osprofiles.GetProfile[*ProfileConfig](target, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	core, ok := reloaded.Profile.(*ProfileConfig)
	if !ok || core.Endpoint != "https://target.invalid" {
		t.Fatal("destination core overwritten")
	}
	value, ok, err := reloaded.Extension("owner")
	if err != nil || !ok || string(value) != `2` {
		t.Fatalf("destination extension overwritten: %s %v %v", value, ok, err)
	}
}

func TestMigrateRejectsMalformedProfileWithoutOverwritingSource(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("filesystem location not asserted on this OS")
	}
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	if err := keyring.Set(config.AppName, "global", `{"version":"1.0","profiles":["alpha"],"defaultProfile":"alpha"}`); err != nil {
		t.Fatal(err)
	}
	original := `{"profile":"alpha","extensions":42}`
	if err := keyring.Set(config.AppName, "profile-alpha", original); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); err == nil {
		t.Fatal("malformed extensions migrated")
	}
	got, err := keyring.Get(config.AppName, "profile-alpha")
	if err != nil || got != original {
		t.Fatalf("source overwritten: %s %v", got, err)
	}
	target, err := CreateProfiler(ProfileDriverFileSystem)
	if err != nil {
		t.Fatal(err)
	}
	if len(osprofiles.ListProfiles(target)) != 0 {
		t.Fatal("destination profile created")
	}
}

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
