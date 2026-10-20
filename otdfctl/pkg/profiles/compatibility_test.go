package profiles

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

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
