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

func TestMigratePreservesUnknownTopLevelFields(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("filesystem location not asserted on this OS")
	}
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	const global = `{"version":"1.0","profiles":["alpha"],"defaultProfile":"alpha","futureGlobal":{"nested":1}}`
	const profile = `{"profile":"alpha","endpoint":"https://example.invalid","authCredentials":{"authType":"client-credentials","clientId":"id"},"futureProfile":[null,{"x":true}]}`
	if err := keyring.Set(config.AppName, "global", global); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Set(config.AppName, "profile-alpha", profile); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); err != nil {
		t.Fatal(err)
	}
	assertUnknownMigratedFields(t, true)
	if err := Migrate(ProfileDriverKeyring, ProfileDriverFileSystem); err != nil {
		t.Fatal(err)
	}
	data, err := keyring.Get(config.AppName, "global")
	if err != nil || !bytes.Contains([]byte(data), []byte(`"futureGlobal":{"nested":1}`)) {
		t.Fatalf("unknown global field lost on reverse migration: %s %v", data, err)
	}
	assertUnknownMigratedFields(t, false)
}

func TestMigratePreservesUnknownNestedCredentials(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("filesystem location not asserted on this OS")
	}
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	const global = `{"version":"1.0","profiles":["alpha"],"defaultProfile":"alpha"}`
	const profile = `{"profile":"alpha","endpoint":"https://example.invalid","authCredentials":{"authType":"access-token","clientId":"id","futureAuth":{"flag":true},"accessToken":{"clientId":"id","accessToken":"token","refreshToken":"refresh","expiration":10,"futureToken":[1,2]}}}`
	if err := keyring.Set(config.AppName, "global", global); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Set(config.AppName, "profile-alpha", profile); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ProfileDriverKeyring, ProfileDriverFileSystem); err != nil {
		t.Fatal(err)
	}
	data, err := keyring.Get(config.AppName, "profile-alpha")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains([]byte(data), []byte(`"futureAuth":{"flag":true}`)) || !bytes.Contains([]byte(data), []byte(`"futureToken":[1,2]`)) {
		t.Fatalf("nested unknown lost across file/keyring migration: %s", data)
	}
	profiler, err := CreateProfiler(ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := osprofiles.GetProfile[*ProfileConfig](profiler, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	core, ok := stored.Profile.(*ProfileConfig)
	if !ok || core.Endpoint != "https://example.invalid" || core.AuthCredentials.ClientID != "id" {
		t.Fatalf("known core changed: %+v", stored.Profile)
	}
}

func TestMigrateGlobalOnlyUnknownWithoutExtensions(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("filesystem location not asserted on this OS")
	}
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	if err := keyring.Set(config.AppName, "global", `{"version":"1.0","profiles":[],"defaultProfile":"","futureGlobal":{"nested":1}}`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ProfileDriverFileSystem, ProfileDriverKeyring); err != nil {
		t.Fatal(err)
	}
	assertUnknownMigratedFields(t, true)
}

func assertUnknownMigratedFields(t *testing.T, withFile bool) {
	t.Helper()
	driver := ProfileDriverKeyring
	if withFile {
		driver = ProfileDriverFileSystem
	}
	profiler, err := CreateProfiler(driver)
	if err != nil {
		t.Fatal(err)
	}
	globalFields := osprofiles.GetGlobalConfig(profiler).UnknownFields()
	if string(globalFields["futureGlobal"]) != `{"nested":1}` {
		t.Fatalf("global unknown field lost: %s", globalFields["futureGlobal"])
	}
	if len(osprofiles.ListProfiles(profiler)) == 0 {
		return
	}
	stored, err := osprofiles.GetProfile[*ProfileConfig](profiler, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	fields := stored.UnknownFields()
	if string(fields["futureProfile"]) != `[null,{"x":true}]` {
		t.Fatalf("profile unknown field lost: %s", fields["futureProfile"])
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
