package common

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/profiles"
	"github.com/spf13/cobra"
	"github.com/zalando/go-keyring"
)

func runProfileSelection(t *testing.T) {
	t.Helper()
	keyring.MockInit()
	p, err := profiles.CreateProfiler(profiles.ProfileDriverFileSystem)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := profiles.RegisterProfile(p, &profiles.ProfileConfig{Name: "alpha", Endpoint: "https://example.invalid"}); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("OTDFCTL_TEST_DEFAULT") == "alpha" {
		if err := profiles.SetDefault(p, "alpha"); err != nil {
			t.Fatal(err)
		}
	}
	cmd := &cobra.Command{Use: "profile-selection"}
	cmd.Flags().String("profile", os.Getenv("OTDFCTL_TEST_PROFILE"), "profile")
	loaded := InitProfile(cli.New(cmd, nil))
	if _, err := fmt.Fprintln(os.Stdout, "selected endpoint:", loaded.GetEndpoint()); err != nil {
		t.Fatal(err)
	}
}

// InitProfile exits the process on selection errors, so exercise its real CLI
// boundary in an isolated subprocess rather than replacing the exit behavior.
func TestInitProfileSelection(t *testing.T) {
	if os.Getenv("OTDFCTL_TEST_PROFILE_SELECTION") == "1" {
		runProfileSelection(t)
		return
	}

	for _, test := range []struct {
		name        string
		profile     string
		defaultName string
		want        string
		wantError   bool
	}{
		{name: "explicit-without-default", profile: "alpha", want: "selected endpoint: https://example.invalid:443"},
		{name: "missing-explicit-without-default", profile: "missing", want: "Failed to load profile: missing", wantError: true},
		{name: "explicit-does-not-fall-back-to-default", profile: "missing", defaultName: "alpha", want: "Failed to load profile: missing", wantError: true},
		{name: "no-profile-or-default", want: "No default profile set", wantError: true},
		{name: "default-without-explicit", defaultName: "alpha", want: "selected endpoint: https://example.invalid:443"},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("LOCALAPPDATA", home)
			t.Setenv("OTDFCTL_TEST_PROFILE_SELECTION", "1")
			t.Setenv("OTDFCTL_TEST_PROFILE", test.profile)
			t.Setenv("OTDFCTL_TEST_DEFAULT", test.defaultName)
			cmd := exec.Command(os.Args[0], "-test.run=^TestInitProfileSelection$")
			output, err := cmd.CombinedOutput()
			if (err != nil) != test.wantError || !strings.Contains(string(output), test.want) {
				t.Fatalf("selection error=%v, wantError=%v; want %q in output:\n%s", err, test.wantError, test.want, output)
			}
		})
	}
}
