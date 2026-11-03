package profiles

import (
	"testing"

	osprofiles "github.com/opentdf/platform/otdfctl/internal/profilestore"
)

func TestMigratePreservesIntentionalEmptyDefault(t *testing.T) {
	isolateMigrationStores(t)
	source, err := CreateProfiler(ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RegisterProfile(source, &ProfileConfig{Name: "alpha", Endpoint: "https://example.invalid"}); err != nil {
		t.Fatal(err)
	}
	if got := osprofiles.GetGlobalConfig(source).GetDefaultProfile(); got != "" {
		t.Fatalf("fixture default = %q, want empty", got)
	}
	for _, migration := range []struct{ to, from ProfileDriver }{
		{ProfileDriverFileSystem, ProfileDriverKeyring},
		{ProfileDriverKeyring, ProfileDriverFileSystem},
	} {
		if err := Migrate(migration.to, migration.from); err != nil {
			t.Fatal(err)
		}
		target, err := CreateProfiler(migration.to)
		if err != nil {
			t.Fatal(err)
		}
		if got := osprofiles.GetGlobalConfig(target).GetDefaultProfile(); got != "" {
			t.Fatalf("migration %s -> %s selected default %q", migration.from, migration.to, got)
		}
		if names := osprofiles.ListProfiles(target); len(names) != 1 || names[0] != "alpha" {
			t.Fatalf("migration lost inventory: %v", names)
		}
		if _, err := osprofiles.GetProfile[*ProfileConfig](target, "alpha"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMigrateEmptySourceDefaultPreservesExistingDestinationDefault(t *testing.T) {
	isolateMigrationStores(t)
	source, err := CreateProfiler(ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RegisterProfile(source, &ProfileConfig{Name: "alpha", Endpoint: "https://source.invalid"}); err != nil {
		t.Fatal(err)
	}
	target, err := CreateProfiler(ProfileDriverFileSystem)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.AddProfile(&ProfileConfig{Name: "existing", Endpoint: "https://destination.invalid"}, true); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); err != nil {
		t.Fatal(err)
	}
	target, err = CreateProfiler(ProfileDriverFileSystem)
	if err != nil {
		t.Fatal(err)
	}
	if got := osprofiles.GetGlobalConfig(target).GetDefaultProfile(); got != "existing" {
		t.Fatalf("existing destination default changed: %q", got)
	}
}
