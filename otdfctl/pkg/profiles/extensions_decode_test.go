package profiles

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	osprofiles "github.com/opentdf/platform/otdfctl/internal/profilestore"
	"github.com/zalando/go-keyring"
)

func TestTypedExtensionDecodeErrorReturnsZeroWithoutMutation(t *testing.T) {
	type settings struct {
		Token   string `json:"token"`
		Enabled bool   `json:"enabled"`
	}
	keyring.MockInit()
	profiler, err := CreateProfiler(ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := NewExtensionConfig(profiler, WithGlobalExtension[settings]("alpha"), WithProfileExtension[settings]("alpha"))
	if err != nil {
		t.Fatal(err)
	}
	if err := profiler.AddProfile(&ProfileConfig{Name: "fixture"}, false); err != nil {
		t.Fatal(err)
	}
	profile, err := osprofiles.GetProfile[*ProfileConfig](profiler, "fixture")
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
		{"global", global.SetExtension, func() (settings, bool, error) { return ReadGlobalExtension[settings](cfg, "alpha") }, global.Extension},
		{"profile", profile.SetExtension, func() (settings, bool, error) { return ReadProfileExtension[settings](cfg, "fixture", "alpha") }, profile.Extension},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.set("alpha", json.RawMessage(original)); err != nil {
				t.Fatal(err)
			}
			value, present, err := test.read()
			if value != (settings{}) || !present || !errors.Is(err, ErrExtensionDecode) || strings.Contains(err.Error(), "synthetic-token") {
				t.Fatal("failed read returned a partial value, absence, or unsanitized error")
			}
			got, present, err := test.get("alpha")
			if err != nil || !present || string(got) != original {
				t.Fatal("failed read mutated storage")
			}
		})
	}
}
