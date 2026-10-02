package profiles

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	osprofiles "github.com/opentdf/platform/otdfctl/internal/profilestore"
	"github.com/opentdf/platform/otdfctl/pkg/config"
	"github.com/zalando/go-keyring"
)

func TestProfileCreateAuthAndMigrateFileToKeyring(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("filesystem location not asserted on this OS")
	}
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	original, err := NewOtdfctlProfileStore(ProfileDriverFileSystem, &ProfileConfig{Name: "synthetic", Endpoint: "https://example.invalid", OutputFormat: OutputJSON}, true)
	if err != nil {
		t.Fatal(err)
	}
	credentials := AuthCredentials{AuthType: AuthTypeClientCredentials, ClientID: "fixture-id", ClientSecret: "synthetic-not-a-secret"}
	if err := original.SetAuthCredentials(credentials); err != nil {
		t.Fatal(err)
	}
	if err := original.SetTLSNoVerify(true); err != nil {
		t.Fatal(err)
	}
	if !original.IsDefault() {
		t.Fatal("new profile not default")
	}
	var dir string
	switch runtime.GOOS {
	case "darwin":
		dir = filepath.Join(os.Getenv("HOME"), "Library", "Application Support", config.ServicePublisher, config.AppName)
	case "linux":
		dir = filepath.Join(os.Getenv("HOME"), ".config", config.ServicePublisher, config.AppName)
	}
	for _, key := range []string{"global", "profile-synthetic"} {
		name := "urn.goosprofiles.otdfctl.profile.v1." + key
		for _, ext := range []string{".enc", ".nfo"} {
			if _, err := os.Stat(filepath.Join(dir, name+ext)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := keyring.Get("urn.goosprofiles.otdfctl.profile.v1", key); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(ProfileDriverKeyring, ProfileDriverFileSystem); err != nil {
		t.Fatal(err)
	}
	migrated, err := LoadOtdfctlProfileStore(ProfileDriverKeyring, "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	if !migrated.IsDefault() || migrated.GetEndpoint() != original.GetEndpoint() || migrated.GetOutputFormat() != OutputJSON || !migrated.GetTLSNoVerify() || !reflect.DeepEqual(migrated.GetAuthCredentials(), credentials) {
		t.Fatalf("migrated profile differs: default=%v endpoint=%q output=%q tls=%v credentials=%+v expected=%+v", migrated.IsDefault(), migrated.GetEndpoint(), migrated.GetOutputFormat(), migrated.GetTLSNoVerify(), migrated.GetAuthCredentials(), credentials)
	}
	for _, key := range []string{"global", "profile-synthetic"} {
		if _, err := keyring.Get(config.AppName, key); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); err != nil {
		t.Fatal(err)
	}
	restored, err := LoadOtdfctlProfileStore(ProfileDriverFileSystem, "synthetic")
	if err != nil || !restored.IsDefault() || !reflect.DeepEqual(restored.GetAuthCredentials(), credentials) {
		t.Fatalf("reverse migration differs: %v %+v", err, restored)
	}
}

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
