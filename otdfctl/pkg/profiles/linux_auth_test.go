package profiles_test

import (
	"os"
	"path/filepath"
	"testing"

	osprofiles "github.com/opentdf/platform/otdfctl/internal/profilestore"
	"github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/platform"
	"github.com/opentdf/platform/otdfctl/pkg/config"
	"github.com/opentdf/platform/otdfctl/pkg/profiles"
	"github.com/opentdf/platform/otdfctl/pkg/profiles/extensions"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

// Exercise the Linux path on every host, without requiring a real Secret Service
// session. The CLI's Linux/D-Bus authentication check remains in e2e/auth.bats.
func TestLinuxFilesystemProfileAuthenticationLifecycle(t *testing.T) {
	keyring.MockInit()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	linux, err := platform.NewPlatform(config.ServicePublisher, config.AppName, "linux")
	require.NoError(t, err)
	dir := linux.UserAppConfigDirectory()
	require.Equal(t, filepath.Join(home, ".config", config.ServicePublisher, config.AppName), dir)

	open := func() *profiles.Profiler {
		t.Helper()
		p, err := osprofiles.New(config.AppName, osprofiles.WithFileStore(dir))
		require.NoError(t, err)
		return p
	}
	p := open()
	creds := profiles.AuthCredentials{
		AuthType: profiles.AuthTypeClientCredentials, ClientID: "linux-client", ClientSecret: "synthetic-linux-secret",
	}
	_, err = profiles.RegisterProfile(p, &profiles.ProfileConfig{
		Name: "linux-auth", Endpoint: "https://example.invalid", AuthCredentials: creds,
	})
	require.NoError(t, err)
	requireDefault(t, p, "")
	require.NoError(t, profiles.SetDefault(p, "linux-auth"))

	type consent struct {
		Allowed bool `json:"allowed"`
	}
	x, err := extensions.NewConfig(p, extensions.WithProfile[consent]("linux-test"))
	require.NoError(t, err)
	require.NoError(t, extensions.WriteProfile(x, "linux-auth", "linux-test", consent{Allowed: true}))

	p = open()
	loaded, err := profiles.LoadProfile(p, "linux-auth")
	require.NoError(t, err)
	require.Equal(t, creds, loaded.GetAuthCredentials())
	requireDefault(t, p, "linux-auth")

	files, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.NotEmpty(t, files)
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(dir, file.Name()))
		require.NoError(t, err)
		require.NotContains(t, string(data), creds.ClientSecret, "credentials must remain encrypted on disk")
	}

	// Logout uses this setter, and must leave the default and extension intact.
	require.NoError(t, loaded.SetAuthCredentials(profiles.AuthCredentials{}))
	p = open()
	loaded, err = profiles.LoadProfile(p, "linux-auth")
	require.NoError(t, err)
	require.Equal(t, profiles.AuthCredentials{}, loaded.GetAuthCredentials())
	requireDefault(t, p, "linux-auth")
	x, err = extensions.NewConfig(p, extensions.WithProfile[consent]("linux-test"))
	require.NoError(t, err)
	value, present, err := extensions.ReadProfile[consent](x, "linux-auth", "linux-test")
	require.NoError(t, err)
	require.True(t, present)
	require.True(t, value.Allowed)
}
