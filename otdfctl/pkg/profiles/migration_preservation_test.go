package profiles

import (
	"bytes"
	"encoding/json"
	"runtime"
	"testing"

	osprofiles "github.com/opentdf/platform/otdfctl/internal/profilestore"
	osplatform "github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/platform"
	"github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/store"
	"github.com/opentdf/platform/otdfctl/pkg/config"
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
