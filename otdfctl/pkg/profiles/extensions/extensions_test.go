package extensions_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	osprofiles "github.com/opentdf/platform/otdfctl/internal/profilestore"
	"github.com/opentdf/platform/otdfctl/pkg/config"
	"github.com/opentdf/platform/otdfctl/pkg/profiles"
	"github.com/opentdf/platform/otdfctl/pkg/profiles/extensions"
	"github.com/zalando/go-keyring"
)

type consumerGlobal struct {
	Enabled bool `json:"enabled"`
}

type consumerProfile struct {
	Label string `json:"label"`
}

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

func TestTypedExtensionIndependentConsumersAndScopes(t *testing.T) {
	profiler, err := profiles.CreateProfiler(profiles.ProfileDriverMemory)
	if err != nil {
		t.Fatal(err)
	}
	alpha, err := extensions.NewConfig(profiler, extensions.WithGlobal[consumerGlobal]("alpha"), extensions.WithProfile[consumerProfile]("alpha"))
	if err != nil {
		t.Fatal(err)
	}
	beta, err := extensions.NewConfig(profiler, extensions.WithGlobal[int]("beta"))
	if err != nil {
		t.Fatal(err)
	}
	if _, present, err := extensions.ReadGlobal[consumerGlobal](alpha, "alpha"); err != nil || present {
		t.Fatalf("absent global: %v %v", present, err)
	}
	if err := extensions.WriteGlobal(alpha, "alpha", consumerGlobal{true}); err != nil {
		t.Fatal(err)
	}
	if err := extensions.WriteGlobal(beta, "beta", 42); err != nil {
		t.Fatal(err)
	}
	if got, present, err := extensions.ReadGlobal[int](beta, "beta"); err != nil || !present || got != 42 {
		t.Fatalf("beta: %d %v %v", got, present, err)
	}
	if got, present, err := extensions.ReadGlobal[consumerGlobal](alpha, "alpha"); err != nil || !present || !got.Enabled {
		t.Fatalf("alpha: %+v %v %v", got, present, err)
	}
	if len(osprofiles.ListProfiles(profiler)) != 0 || osprofiles.GetGlobalConfig(profiler).GetDefaultProfile() != "" {
		t.Fatal("global write created a profile")
	}
	if _, _, err := extensions.ReadGlobal[int](alpha, "beta"); !errors.Is(err, extensions.ErrExtensionNotRegistered) {
		t.Fatalf("unregistered consumer: %v", err)
	}
	if err := extensions.WriteGlobal(alpha, "alpha", 1); !errors.Is(err, extensions.ErrExtensionTypeMismatch) {
		t.Fatalf("wrong type: %v", err)
	}
	if _, _, err := extensions.ReadProfile[consumerGlobal](alpha, "second", "alpha"); !errors.Is(err, extensions.ErrExtensionTypeMismatch) {
		t.Fatalf("wrong scope shape: %v", err)
	}
}

func TestTypedExtensionRegistrationErrors(t *testing.T) {
	profiler, err := profiles.CreateProfiler(profiles.ProfileDriverMemory)
	if err != nil {
		t.Fatal(err)
	}
	for _, namespace := range []string{"", "Bad", "a/b", "a..b", ".a", "a_"} {
		if _, err := extensions.NewConfig(profiler, extensions.WithGlobal[int](namespace)); !errors.Is(err, extensions.ErrInvalidExtensionNamespace) {
			t.Errorf("%q: %v", namespace, err)
		}
	}
	if _, err := extensions.NewConfig(profiler, extensions.WithGlobal[int]("alpha"), extensions.WithGlobal[string]("alpha")); !errors.Is(err, extensions.ErrDuplicateExtension) {
		t.Fatal(err)
	}
	if _, err := extensions.NewConfig(profiler, extensions.WithGlobal[int]("alpha"), extensions.WithProfile[string]("alpha")); err != nil {
		t.Fatal(err)
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

func TestTypedExtensionUsesLatestStoredConfiguration(t *testing.T) {
	keyring.MockInit()
	first, err := profiles.CreateProfiler(profiles.ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := extensions.NewConfig(first, extensions.WithGlobal[consumerGlobal]("alpha"), extensions.WithProfile[consumerProfile]("alpha"))
	if err != nil {
		t.Fatal(err)
	}
	if err := first.AddProfile(&profiles.ProfileConfig{Name: "fixture"}, true); err != nil {
		t.Fatal(err)
	}
	other, err := profiles.CreateProfiler(profiles.ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	if err := osprofiles.GetGlobalConfig(other).SetExtension("beta", json.RawMessage(`{"keep":1}`)); err != nil {
		t.Fatal(err)
	}
	profile, err := osprofiles.GetProfile[*profiles.ProfileConfig](other, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.SetExtension("beta", json.RawMessage(`{"keep":2}`)); err != nil {
		t.Fatal(err)
	}
	if err := extensions.WriteGlobal(stale, "alpha", consumerGlobal{true}); err != nil {
		t.Fatal(err)
	}
	if err := extensions.WriteProfile(stale, "fixture", "alpha", consumerProfile{"new"}); err != nil {
		t.Fatal(err)
	}
	fresh, err := profiles.CreateProfiler(profiles.ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok, err := osprofiles.GetGlobalConfig(fresh).Extension("alpha"); err != nil || !ok || string(got) != `{"enabled":true}` {
		t.Fatalf("global replacement: %s %v %v", got, ok, err)
	}
	if got, ok, err := osprofiles.GetGlobalConfig(fresh).Extension("beta"); err != nil || !ok || string(got) != `{"keep":1}` {
		t.Fatalf("global other namespace: %s %v %v", got, ok, err)
	}
	loaded, err := osprofiles.GetProfile[*profiles.ProfileConfig](fresh, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if got, ok, err := loaded.Extension("alpha"); err != nil || !ok || string(got) != `{"label":"new"}` {
		t.Fatalf("profile replacement: %s %v %v", got, ok, err)
	}
	if got, ok, err := loaded.Extension("beta"); err != nil || !ok || string(got) != `{"keep":2}` {
		t.Fatalf("profile other namespace: %s %v %v", got, ok, err)
	}
}

func TestTypedExtensionAcrossDriversAndNoCredentialDisclosure(t *testing.T) {
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("LOCALAPPDATA", t.TempDir())
	for _, driver := range []profiles.ProfileDriver{profiles.ProfileDriverFileSystem, profiles.ProfileDriverKeyring} {
		t.Run(string(driver), func(t *testing.T) {
			profiler, err := profiles.CreateProfiler(driver)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := extensions.NewConfig(profiler, extensions.WithGlobal[consumerGlobal]("alpha"), extensions.WithProfile[consumerProfile]("alpha"))
			if err != nil {
				t.Fatal(err)
			}
			if err := extensions.WriteGlobal(cfg, "alpha", consumerGlobal{true}); err != nil {
				t.Fatal(err)
			}
			if err := profiler.AddProfile(&profiles.ProfileConfig{Name: "fixture", Endpoint: "https://example.invalid"}, true); err != nil {
				t.Fatal(err)
			}
			if err := profiler.AddProfile(&profiles.ProfileConfig{Name: "other", Endpoint: "https://example.invalid"}, false); err != nil {
				t.Fatal(err)
			}
			if err := extensions.WriteProfile(cfg, "fixture", "alpha", consumerProfile{"stored"}); err != nil {
				t.Fatal(err)
			}
			if err := extensions.WriteProfile(cfg, "fixture", "alpha", consumerProfile{"updated"}); err != nil {
				t.Fatal(err)
			}
			profileStore, err := profiles.LoadOtdfctlProfileStore(driver, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			credentials := profiles.AuthCredentials{AuthType: profiles.AuthTypeClientCredentials, ClientID: "id", ClientSecret: "private-token"}
			if err := profileStore.SetAuthCredentials(credentials); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(fmt.Sprint(cfg), "private-token") {
				t.Fatal("extension config printed credentials")
			}
			loaded, err := profiles.CreateProfiler(driver)
			if err != nil {
				t.Fatal(err)
			}
			loadedCfg, err := extensions.NewConfig(loaded, extensions.WithGlobal[consumerGlobal]("alpha"), extensions.WithProfile[consumerProfile]("alpha"))
			if err != nil {
				t.Fatal(err)
			}
			if value, ok, err := extensions.ReadGlobal[consumerGlobal](loadedCfg, "alpha"); err != nil || !ok || !value.Enabled {
				t.Fatalf("global reload: %+v %v %v", value, ok, err)
			}
			if value, ok, err := extensions.ReadProfile[consumerProfile](loadedCfg, "fixture", "alpha"); err != nil || !ok || value.Label != "updated" {
				t.Fatalf("profile reload: %+v %v %v", value, ok, err)
			}
			if _, ok, err := extensions.ReadProfile[consumerProfile](loadedCfg, "other", "alpha"); err != nil || ok {
				t.Fatalf("other profile: %v %v", ok, err)
			}
			if osprofiles.GetGlobalConfig(loaded).GetDefaultProfile() != "fixture" {
				t.Fatal("extension changed the default")
			}
			if raw, err := keyring.Get(config.AppName, "profile-fixture"); driver == profiles.ProfileDriverKeyring && (err != nil || !strings.Contains(raw, "private-token")) {
				t.Fatalf("existing credentials were not retained: %v", err)
			}
		})
	}
}
