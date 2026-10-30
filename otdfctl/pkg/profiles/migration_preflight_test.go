package profiles

import (
	"errors"
	"runtime"
	"testing"

	osprofiles "github.com/opentdf/platform/otdfctl/internal/profilestore"
	osplatform "github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/platform"
	"github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/store"
	"github.com/opentdf/platform/otdfctl/pkg/config"
	"github.com/zalando/go-keyring"
)

func migrationFileStore(t *testing.T, key string) store.Interface {
	t.Helper()
	platform, err := osplatform.NewPlatform(config.ServicePublisher, config.AppName, runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := store.NewFileStore(config.AppName, key, store.WithStoreDirectory(platform.UserAppConfigDirectory()))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func isolateMigrationStores(t *testing.T) {
	t.Helper()
	keyring.MockInit()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", t.TempDir())
}

func TestMigrateEmptySourceDoesNotInitializeEitherStore(t *testing.T) {
	isolateMigrationStores(t)
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); err != nil {
		t.Fatal(err)
	}
	if _, err := keyring.Get(config.AppName, "global"); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("source global initialized: %v", err)
	}
	if migrationFileStore(t, "global").Exists() {
		t.Fatal("empty migration initialized destination")
	}
	if err := Migrate(ProfileDriverUnknown, ProfileDriverKeyring); !errors.Is(err, ErrUnknownProfileDriverType) {
		t.Fatalf("invalid destination accepted for empty source: %v", err)
	}
}

func TestMigrateRejectsMemoryWithoutDeletingPersistentSource(t *testing.T) {
	for _, data := range []string{
		`{"version":"1.0","profiles":[],"defaultProfile":"","futureGlobal":1}`,
		`{"version":"1.0","profiles":[],"defaultProfile":"","extensions":{"owner":true}}`,
		`{"version":"1.0","profiles":["alpha"],"defaultProfile":"alpha"}`,
	} {
		t.Run(data, func(t *testing.T) {
			isolateMigrationStores(t)
			if err := keyring.Set(config.AppName, "global", data); err != nil {
				t.Fatal(err)
			}
			const profile = `{"profile":"alpha","endpoint":"https://example.invalid"}`
			if err := keyring.Set(config.AppName, "profile-alpha", profile); err != nil {
				t.Fatal(err)
			}
			if err := Migrate(ProfileDriverMemory, ProfileDriverKeyring); !errors.Is(err, ErrMigrationDestinationNotPersistent) {
				t.Fatalf("migration to a discarded in-memory destination not rejected: %v", err)
			}
			if got, err := keyring.Get(config.AppName, "global"); err != nil || got != data {
				t.Fatalf("persistent source changed: %q %v", got, err)
			}
			if got, err := keyring.Get(config.AppName, "profile-alpha"); err != nil || got != profile {
				t.Fatalf("persistent profile changed: %q %v", got, err)
			}
		})
	}
}

func TestMigrateSourceConflictLeavesAbsentDestinationAbsent(t *testing.T) {
	isolateMigrationStores(t)
	const global = `{"version":"1.0","profiles":["alpha"],"defaultProfile":"alpha"}`
	const profile = `{"profile":"alpha","authCredentials":{"future":1},"AUTHCREDENTIALS":{"future":2}}`
	if err := keyring.Set(config.AppName, "global", global); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Set(config.AppName, "profile-alpha", profile); err != nil {
		t.Fatal(err)
	}
	destinationGlobal := migrationFileStore(t, "global")
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); !errors.Is(err, store.ErrOpaqueConflict) {
		t.Fatalf("source conflict not reported: %v", err)
	}
	if destinationGlobal.Exists() || migrationFileStore(t, "profile-alpha").Exists() {
		t.Fatal("destination initialized before source validation")
	}
	if got, err := keyring.Get(config.AppName, "global"); err != nil || got != global {
		t.Fatalf("source global changed: %q %v", got, err)
	}
	if got, err := keyring.Get(config.AppName, "profile-alpha"); err != nil || got != profile {
		t.Fatalf("source profile changed: %q %v", got, err)
	}
}

func TestMigrateRejectsOrphanDestinationBeforeAnyWrite(t *testing.T) {
	for _, withGlobal := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent global", true: "existing global"}[withGlobal], func(t *testing.T) {
			isolateMigrationStores(t)
			const global = `{"version":"1.0","profiles":["alpha","beta"],"defaultProfile":"alpha"}`
			if err := keyring.Set(config.AppName, "global", global); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"alpha", "beta"} {
				if err := keyring.Set(config.AppName, "profile-"+name, `{"profile":"`+name+`","future":1}`); err != nil {
					t.Fatal(err)
				}
			}
			if withGlobal {
				if _, err := CreateProfiler(ProfileDriverFileSystem); err != nil {
					t.Fatal(err)
				}
			}
			destinationGlobal := migrationFileStore(t, "global")
			var beforeGlobal []byte
			if withGlobal {
				var err error
				beforeGlobal, err = destinationGlobal.Get()
				if err != nil {
					t.Fatal(err)
				}
			}
			orphan := migrationFileStore(t, "profile-beta")
			if err := orphan.Set(map[string]any{"profile": "beta", "endpoint": "https://destination.invalid", "future": 2}); err != nil {
				t.Fatal(err)
			}
			beforeOrphan, err := orphan.Get()
			if err != nil {
				t.Fatal(err)
			}
			if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); err == nil {
				t.Fatal("orphan destination overwritten")
			}
			if got, err := orphan.Get(); err != nil || string(got) != string(beforeOrphan) {
				t.Fatalf("orphan mutated before rejection: %s %v", got, err)
			}
			if migrationFileStore(t, "profile-alpha").Exists() {
				t.Fatal("earlier profile written before all destination collisions checked")
			}
			if withGlobal {
				if got, err := destinationGlobal.Get(); err != nil || string(got) != string(beforeGlobal) {
					t.Fatalf("destination global mutated: %s %v", got, err)
				}
			} else if destinationGlobal.Exists() {
				t.Fatal("destination global initialized on collision")
			}
			if got, err := keyring.Get(config.AppName, "global"); err != nil || got != global {
				t.Fatalf("source changed on collision: %s %v", got, err)
			}
		})
	}
}

func TestMigrateGlobalConflictDoesNotUpgradeDestination(t *testing.T) {
	isolateMigrationStores(t)
	const source = `{"version":"1.0","profiles":[],"defaultProfile":"","future":1}`
	if err := keyring.Set(config.AppName, "global", source); err != nil {
		t.Fatal(err)
	}
	destination := migrationFileStore(t, "global")
	if err := destination.Set(map[string]any{"version": "old", "profiles": []string{}, "defaultProfile": "", "future": 2}); err != nil {
		t.Fatal(err)
	}
	before, err := destination.Get()
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); !errors.Is(err, store.ErrOpaqueConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
	if got, err := destination.Get(); err != nil || string(got) != string(before) {
		t.Fatalf("destination version changed before conflict preflight: %s %v", got, err)
	}
}

func TestMigrateRejectsExistingProfileBeforeEarlierWrites(t *testing.T) {
	isolateMigrationStores(t)
	if err := keyring.Set(config.AppName, "global", `{"version":"1.0","profiles":["alpha","beta"],"defaultProfile":"beta"}`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alpha", "beta"} {
		if err := keyring.Set(config.AppName, "profile-"+name, `{"profile":"`+name+`"}`); err != nil {
			t.Fatal(err)
		}
	}
	target, err := CreateProfiler(ProfileDriverFileSystem)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.AddProfile(&ProfileConfig{Name: "beta"}, true); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); !errors.Is(err, osprofiles.ErrProfileNameConflict) {
		t.Fatalf("expected name conflict: %v", err)
	}
	if migrationFileStore(t, "profile-alpha").Exists() {
		t.Fatal("earlier profile written before existing-profile rejection")
	}
}
