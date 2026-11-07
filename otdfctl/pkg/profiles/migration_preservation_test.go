package profiles

import (
	"bytes"
	"encoding/json"
	"runtime"
	"testing"

	osprofiles "github.com/opentdf/platform/otdfctl/pkg/profilestore"
	"github.com/zalando/go-keyring"
)

func TestMigrateGlobalOnlyExtensionsWithoutProfiles(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("filesystem location not asserted on this OS")
	}
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	source, err := CreateProfiler(ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	if err := osprofiles.GetGlobalConfig(source).SetExtension("owner", json.RawMessage(`{"future":{"value":1}}`)); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); err != nil {
		t.Fatal(err)
	}
	target, err := CreateProfiler(ProfileDriverFileSystem)
	if err != nil {
		t.Fatal(err)
	}
	if len(osprofiles.ListProfiles(target)) != 0 || osprofiles.GetGlobalConfig(target).GetDefaultProfile() != "" {
		t.Fatal("migration manufactured a profile")
	}
	assertMigratedExtension(t, osprofiles.GetGlobalConfig(target).Extension, `{"future":{"value":1}}`)
	if err := Migrate(ProfileDriverKeyring, ProfileDriverFileSystem); err != nil {
		t.Fatal(err)
	}
	source, err = CreateProfiler(ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	assertMigratedExtension(t, osprofiles.GetGlobalConfig(source).Extension, `{"future":{"value":1}}`)
}

func TestMigrateProfileExtensions(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("filesystem location not asserted on this OS")
	}
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	source, err := CreateProfiler(ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.AddProfile(&ProfileConfig{Name: "alpha", Endpoint: "https://example.invalid"}, true); err != nil {
		t.Fatal(err)
	}
	current, err := osprofiles.GetCurrentProfile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := current.SetExtension("owner", json.RawMessage(`{"unknown":42}`)); err != nil {
		t.Fatal(err)
	}
	if err := osprofiles.GetGlobalConfig(source).SetExtension("owner", json.RawMessage(`null`)); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); err != nil {
		t.Fatal(err)
	}
	target, err := CreateProfiler(ProfileDriverFileSystem)
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := osprofiles.GetProfile[*ProfileConfig](target, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	pc, ok := migrated.Profile.(*ProfileConfig)
	if !ok || pc.Endpoint != "https://example.invalid" || osprofiles.GetGlobalConfig(target).GetDefaultProfile() != "alpha" {
		t.Fatal("core profile lost")
	}
	assertMigratedExtension(t, migrated.Extension, `{"unknown":42}`)
	assertMigratedExtension(t, osprofiles.GetGlobalConfig(target).Extension, `null`)
}

func assertMigratedExtension(t *testing.T, get func(string) (json.RawMessage, bool, error), want string) {
	t.Helper()
	got, ok, err := get("owner")
	if err != nil || !ok || !bytes.Equal(got, []byte(want)) {
		t.Fatalf("extension: %s present %v err %v; want %s", got, ok, err, want)
	}
}
