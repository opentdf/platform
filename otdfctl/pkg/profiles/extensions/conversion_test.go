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

type secretMarshalValue struct{}

var errSecretMarshal = errors.New("private-token from MarshalJSON")

func (secretMarshalValue) MarshalJSON() ([]byte, error) {
	return nil, errSecretMarshal
}

func TestTypedExtensionSanitizesMarshalError(t *testing.T) {
	profiler, err := profiles.CreateProfiler(profiles.ProfileDriverMemory)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := extensions.NewConfig(profiler, extensions.WithGlobal[secretMarshalValue]("alpha"))
	if err != nil {
		t.Fatal(err)
	}
	if err := osprofiles.GetGlobalConfig(profiler).SetExtension("alpha", json.RawMessage(`{"existing":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := extensions.WriteGlobal(cfg, "alpha", secretMarshalValue{}); !errors.Is(err, extensions.ErrExtensionEncode) || errors.Is(err, errSecretMarshal) || strings.Contains(err.Error(), "private-token") {
		t.Fatalf("unsafe marshal error: %v", err)
	}
	got, present, err := osprofiles.GetGlobalConfig(profiler).Extension("alpha")
	if err != nil || !present || string(got) != `{"existing":true}` {
		t.Fatalf("changed after failed marshal: %s %v %v", got, present, err)
	}
}

func TestTypedExtensionWriteReplacesNamespaceWithoutMerging(t *testing.T) {
	type settings struct {
		Enabled bool   `json:"enabled"`
		Note    string `json:"note,omitempty"`
	}
	profiler, err := profiles.CreateProfiler(profiles.ProfileDriverMemory)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := extensions.NewConfig(profiler, extensions.WithGlobal[settings]("alpha"))
	if err != nil {
		t.Fatal(err)
	}
	if err := extensions.WriteGlobal(cfg, "alpha", settings{Note: "old"}); err != nil {
		t.Fatal(err)
	}
	if err := extensions.WriteGlobal(cfg, "alpha", settings{Enabled: true}); err != nil {
		t.Fatal(err)
	}
	got, present, err := osprofiles.GetGlobalConfig(profiler).Extension("alpha")
	if err != nil || !present || string(got) != `{"enabled":true}` {
		t.Fatalf("typed write merged omitted field: %s %v %v", got, present, err)
	}
}

func TestTypedExtensionReplacesStoredNull(t *testing.T) {
	keyring.MockInit()
	profiler, err := profiles.CreateProfiler(profiles.ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := extensions.NewConfig(profiler, extensions.WithGlobal[consumerGlobal]("alpha"), extensions.WithProfile[consumerProfile]("alpha"))
	if err != nil {
		t.Fatal(err)
	}
	if err := profiler.AddProfile(&profiles.ProfileConfig{Name: "fixture"}, false); err != nil {
		t.Fatal(err)
	}
	global := osprofiles.GetGlobalConfig(profiler)
	profile, err := osprofiles.GetProfile[*profiles.ProfileConfig](profiler, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := global.SetExtension("alpha", json.RawMessage("null")); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetExtension("alpha", json.RawMessage("null")); err != nil {
		t.Fatal(err)
	}
	if err := extensions.WriteGlobal(cfg, "alpha", consumerGlobal{true}); err != nil {
		t.Fatal(err)
	}
	if err := extensions.WriteProfile(cfg, "fixture", "alpha", consumerProfile{"new"}); err != nil {
		t.Fatal(err)
	}
	if got, present, err := extensions.ReadGlobal[consumerGlobal](cfg, "alpha"); err != nil || !present || !got.Enabled {
		t.Fatalf("global replacement: %+v %v %v", got, present, err)
	}
	if got, present, err := extensions.ReadProfile[consumerProfile](cfg, "fixture", "alpha"); err != nil || !present || got.Label != "new" {
		t.Fatalf("profile replacement: %+v %v %v", got, present, err)
	}
}

func TestTypedExtensionReplacesExistingPayload(t *testing.T) {
	keyring.MockInit()
	profiler, err := profiles.CreateProfiler(profiles.ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := extensions.NewConfig(profiler, extensions.WithGlobal[consumerGlobal]("alpha"), extensions.WithProfile[consumerProfile]("alpha"))
	if err != nil {
		t.Fatal(err)
	}
	if err := profiler.AddProfile(&profiles.ProfileConfig{Name: "first", Endpoint: "https://example.invalid"}, true); err != nil {
		t.Fatal(err)
	}
	profile, err := osprofiles.GetProfile[*profiles.ProfileConfig](profiler, "first")
	if err != nil {
		t.Fatal(err)
	}
	global := osprofiles.GetGlobalConfig(profiler)
	getProfileExtension := func(namespace string) (json.RawMessage, bool, error) {
		latest, err := osprofiles.GetProfile[*profiles.ProfileConfig](profiler, "first")
		if err != nil {
			return nil, false, err
		}
		return latest.Extension(namespace)
	}
	if err := global.SetExtension("beta", json.RawMessage(`{"other":true}`)); err != nil {
		t.Fatal(err)
	}
	if err := profile.SetExtension("beta", json.RawMessage(`{"other":true}`)); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, before, after string
		set                 func(json.RawMessage) error
		read                func() (bool, error)
		write               func() error
		get                 func(string) (json.RawMessage, bool, error)
		decodeError         bool
	}{
		{"global unknown", `{"enabled":true,"future":{"nested":99}}`, `{"enabled":false}`, func(raw json.RawMessage) error { return global.SetExtension("alpha", raw) }, func() (bool, error) {
			_, ok, err := extensions.ReadGlobal[consumerGlobal](cfg, "alpha")
			return ok, err
		}, func() error { return extensions.WriteGlobal(cfg, "alpha", consumerGlobal{false}) }, global.Extension, false},
		{"profile unknown", `{"label":"old","future":42}`, `{"label":"new"}`, func(raw json.RawMessage) error { return profile.SetExtension("alpha", raw) }, func() (bool, error) {
			_, ok, err := extensions.ReadProfile[consumerProfile](cfg, "first", "alpha")
			return ok, err
		}, func() error { return extensions.WriteProfile(cfg, "first", "alpha", consumerProfile{"new"}) }, getProfileExtension, false},
		{"global duplicate key", `{"enabled":true,"enabled":false}`, `{"enabled":false}`, func(raw json.RawMessage) error { return global.SetExtension("alpha", raw) }, func() (bool, error) {
			_, ok, err := extensions.ReadGlobal[consumerGlobal](cfg, "alpha")
			return ok, err
		}, func() error { return extensions.WriteGlobal(cfg, "alpha", consumerGlobal{false}) }, global.Extension, false},
		{"global incompatible", `{"enabled":"private-token"}`, `{"enabled":false}`, func(raw json.RawMessage) error { return global.SetExtension("alpha", raw) }, func() (bool, error) {
			_, ok, err := extensions.ReadGlobal[consumerGlobal](cfg, "alpha")
			return ok, err
		}, func() error { return extensions.WriteGlobal(cfg, "alpha", consumerGlobal{false}) }, global.Extension, true},
		{"profile incompatible", `{"label":42}`, `{"label":"new"}`, func(raw json.RawMessage) error { return profile.SetExtension("alpha", raw) }, func() (bool, error) {
			_, ok, err := extensions.ReadProfile[consumerProfile](cfg, "first", "alpha")
			return ok, err
		}, func() error { return extensions.WriteProfile(cfg, "first", "alpha", consumerProfile{"new"}) }, getProfileExtension, true},
		{"global null", `null`, `{"enabled":false}`, func(raw json.RawMessage) error { return global.SetExtension("alpha", raw) }, func() (bool, error) {
			_, ok, err := extensions.ReadGlobal[consumerGlobal](cfg, "alpha")
			return ok, err
		}, func() error { return extensions.WriteGlobal(cfg, "alpha", consumerGlobal{false}) }, global.Extension, false},
		{"profile null", `null`, `{"label":"new"}`, func(raw json.RawMessage) error { return profile.SetExtension("alpha", raw) }, func() (bool, error) {
			_, ok, err := extensions.ReadProfile[consumerProfile](cfg, "first", "alpha")
			return ok, err
		}, func() error { return extensions.WriteProfile(cfg, "first", "alpha", consumerProfile{"new"}) }, getProfileExtension, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.set(json.RawMessage(test.before)); err != nil {
				t.Fatal(err)
			}
			present, err := test.read()
			if !present || (test.decodeError && !errors.Is(err, extensions.ErrExtensionDecode)) || (!test.decodeError && err != nil) || (err != nil && strings.Contains(err.Error(), "private-token")) {
				t.Fatalf("read: %v %v", present, err)
			}
			if err := test.write(); err != nil {
				t.Fatalf("write: %v", err)
			}
			got, present, err := test.get("alpha")
			if err != nil || !present || string(got) != test.after {
				t.Fatalf("replacement: %s %v %v", got, present, err)
			}
			other, present, err := test.get("beta")
			if err != nil || !present || string(other) != `{"other":true}` {
				t.Fatalf("other namespace: %s %v %v", other, present, err)
			}
		})
	}
	if got := global.GetDefaultProfile(); got != "first" {
		t.Fatalf("default changed: %q", got)
	}
	latest, err := osprofiles.GetProfile[*profiles.ProfileConfig](profiler, "first")
	if err != nil {
		t.Fatal(err)
	}
	core, ok := latest.Profile.(*profiles.ProfileConfig)
	if !ok || core.Endpoint != "https://example.invalid" {
		t.Fatalf("core changed: %+v", latest.Profile)
	}
}

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
