package profiles

import (
	"encoding/json"
	"errors"
	"runtime"
	"testing"

	osprofiles "github.com/opentdf/platform/otdfctl/internal/profilestore"
	"github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/store"
	"github.com/opentdf/platform/otdfctl/pkg/config"
	"github.com/zalando/go-keyring"
)

func TestMigrateGlobalOnlySameDriverPreservesSource(t *testing.T) {
	keyring.MockInit()
	const original = `{"version":"1.0","profiles":[],"defaultProfile":"","extensions":{"alpha":{"enabled":true}}}`
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
	const sourceGlobal = `{"version":"1.0","profiles":[],"defaultProfile":"","extensions":{"owner":1}}`
	if err := keyring.Set(config.AppName, "global", sourceGlobal); err != nil {
		t.Fatal(err)
	}
	// Copy the global extension, then seed a conflicting source payload.
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); err != nil {
		t.Fatal(err)
	}
	const conflicting = `{"version":"1.0","profiles":[],"defaultProfile":"","extensions":{"owner":2}}`
	if err := keyring.Set(config.AppName, "global", conflicting); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); !errors.Is(err, store.ErrExtensionConflict) {
		t.Fatalf("global conflict not reported: %v", err)
	}
	got, err := keyring.Get(config.AppName, "global")
	if err != nil || got != conflicting {
		t.Fatalf("source changed on conflict: %s %v", got, err)
	}
	target, err := CreateProfiler(ProfileDriverFileSystem)
	if err != nil {
		t.Fatal(err)
	}
	value, present, err := osprofiles.GetGlobalConfig(target).Extension("owner")
	if err != nil || !present || string(value) != `1` || len(osprofiles.ListProfiles(target)) != 0 {
		t.Fatal("destination mutated or profile manufactured")
	}
}

func TestMigrateIndexedProfileConflictBeforeWriting(t *testing.T) {
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
	sourceGlobal, err := keyring.Get(config.AppName, "global")
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
	destinationGlobal, err := migrationFileStore(t, "global").Get()
	if err != nil {
		t.Fatal(err)
	}
	destinationProfile, err := migrationFileStore(t, "profile-alpha").Get()
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); !errors.Is(err, osprofiles.ErrProfileNameConflict) {
		t.Fatalf("profile conflict not reported: %v", err)
	}
	if got, err := keyring.Get(config.AppName, "profile-alpha"); err != nil || got != original {
		t.Fatalf("source changed: %s %v", got, err)
	}
	if got, err := keyring.Get(config.AppName, "global"); err != nil || got != sourceGlobal {
		t.Fatalf("source global changed: %s %v", got, err)
	}
	if got, err := migrationFileStore(t, "global").Get(); err != nil || string(got) != string(destinationGlobal) {
		t.Fatalf("destination global changed: %s %v", got, err)
	}
	if got, err := migrationFileStore(t, "profile-alpha").Get(); err != nil || string(got) != string(destinationProfile) {
		t.Fatalf("destination profile changed: %s %v", got, err)
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
	if migrationFileStore(t, "global").Exists() || migrationFileStore(t, "profile-alpha").Exists() {
		t.Fatal("destination initialized before source validation")
	}
}
