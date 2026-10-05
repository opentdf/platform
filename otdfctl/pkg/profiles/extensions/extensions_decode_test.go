package extensions_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	osprofiles "github.com/opentdf/platform/otdfctl/internal/profilestore"
	"github.com/opentdf/platform/otdfctl/pkg/profiles"
	"github.com/opentdf/platform/otdfctl/pkg/profiles/extensions"
	"github.com/zalando/go-keyring"
)

func TestTypedExtensionDecodeErrorReturnsZeroWithoutMutation(t *testing.T) {
	type settings struct {
		Token   string `json:"token"`
		Enabled bool   `json:"enabled"`
	}
	keyring.MockInit()
	profiler, err := profiles.CreateProfiler(profiles.ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := extensions.NewConfig(profiler, extensions.WithGlobal[settings]("alpha"), extensions.WithProfile[settings]("alpha"))
	if err != nil {
		t.Fatal(err)
	}
	if err := profiler.AddProfile(&profiles.ProfileConfig{Name: "fixture"}, false); err != nil {
		t.Fatal(err)
	}
	profile, err := osprofiles.GetProfile[*profiles.ProfileConfig](profiler, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	global := osprofiles.GetGlobalConfig(profiler)
	const original = `{"token":"synthetic-token","enabled":"wrong-type"}`
	for _, test := range []struct {
		name string
		set  func(string, json.RawMessage) error
		read func() (settings, bool, error)
		get  func(string) (json.RawMessage, bool, error)
	}{
		{"global", global.SetExtension, func() (settings, bool, error) { return extensions.ReadGlobal[settings](cfg, "alpha") }, global.Extension},
		{"profile", profile.SetExtension, func() (settings, bool, error) { return extensions.ReadProfile[settings](cfg, "fixture", "alpha") }, profile.Extension},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.set("alpha", json.RawMessage(original)); err != nil {
				t.Fatal(err)
			}
			value, present, err := test.read()
			if value != (settings{}) || !present || !errors.Is(err, extensions.ErrExtensionDecode) || strings.Contains(err.Error(), "synthetic-token") {
				t.Fatal("failed read returned a partial value, absence, or unsanitized error")
			}
			got, present, err := test.get("alpha")
			if err != nil || !present || string(got) != original {
				t.Fatal("failed read mutated storage")
			}
		})
	}
}
