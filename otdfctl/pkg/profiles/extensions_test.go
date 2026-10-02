package profiles

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	osprofiles "github.com/opentdf/platform/otdfctl/internal/profilestore"
	"github.com/opentdf/platform/otdfctl/pkg/config"
	"github.com/zalando/go-keyring"
)

type consumerGlobal struct {
	Enabled bool `json:"enabled"`
}

type consumerProfile struct {
	Label string `json:"label"`
}

func TestTypedExtensionIndependentConsumersAndScopes(t *testing.T) {
	profiler, err := CreateProfiler(ProfileDriverMemory)
	if err != nil {
		t.Fatal(err)
	}
	alpha, err := NewExtensionConfig(profiler, WithGlobalExtension[consumerGlobal]("alpha"), WithProfileExtension[consumerProfile]("alpha"))
	if err != nil {
		t.Fatal(err)
	}
	beta, err := NewExtensionConfig(profiler, WithGlobalExtension[int]("beta"))
	if err != nil {
		t.Fatal(err)
	}
	if _, present, err := ReadGlobalExtension[consumerGlobal](alpha, "alpha"); err != nil || present {
		t.Fatalf("absent global: %v %v", present, err)
	}
	if err := WriteGlobalExtension(alpha, "alpha", consumerGlobal{true}); err != nil {
		t.Fatal(err)
	}
	if err := WriteGlobalExtension(beta, "beta", 42); err != nil {
		t.Fatal(err)
	}
	if got, present, err := ReadGlobalExtension[int](beta, "beta"); err != nil || !present || got != 42 {
		t.Fatalf("beta: %d %v %v", got, present, err)
	}
	if got, present, err := ReadGlobalExtension[consumerGlobal](alpha, "alpha"); err != nil || !present || !got.Enabled {
		t.Fatalf("alpha: %+v %v %v", got, present, err)
	}
	if len(osprofiles.ListProfiles(profiler)) != 0 || osprofiles.GetGlobalConfig(profiler).GetDefaultProfile() != "" {
		t.Fatal("global write created a profile")
	}
	if _, _, err := ReadGlobalExtension[int](alpha, "beta"); !errors.Is(err, ErrExtensionNotRegistered) {
		t.Fatalf("unregistered consumer: %v", err)
	}
	if err := WriteGlobalExtension(alpha, "alpha", 1); !errors.Is(err, ErrExtensionTypeMismatch) {
		t.Fatalf("wrong type: %v", err)
	}
	if _, _, err := ReadProfileExtension[consumerGlobal](alpha, "second", "alpha"); !errors.Is(err, ErrExtensionTypeMismatch) {
		t.Fatalf("wrong scope shape: %v", err)
	}
}

func TestTypedExtensionRegistrationErrors(t *testing.T) {
	profiler, err := CreateProfiler(ProfileDriverMemory)
	if err != nil {
		t.Fatal(err)
	}
	for _, namespace := range []string{"", "Bad", "a/b", "a..b", ".a", "a_"} {
		if _, err := NewExtensionConfig(profiler, WithGlobalExtension[int](namespace)); !errors.Is(err, ErrInvalidExtensionNamespace) {
			t.Errorf("%q: %v", namespace, err)
		}
	}
	if _, err := NewExtensionConfig(profiler, WithGlobalExtension[int]("alpha"), WithGlobalExtension[string]("alpha")); !errors.Is(err, ErrDuplicateExtension) {
		t.Fatal(err)
	}
	if _, err := NewExtensionConfig(profiler, WithGlobalExtension[int]("alpha"), WithProfileExtension[string]("alpha")); err != nil {
		t.Fatal(err)
	}
}

func TestTypedExtensionRejectsMalformedAndUnknownWithoutMutation(t *testing.T) {
	keyring.MockInit()
	profiler, err := CreateProfiler(ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := NewExtensionConfig(profiler, WithGlobalExtension[consumerGlobal]("alpha"), WithProfileExtension[consumerProfile]("alpha"))
	if err != nil {
		t.Fatal(err)
	}
	if err := profiler.AddProfile(&ProfileConfig{Name: "first"}, true); err != nil {
		t.Fatal(err)
	}
	profile, err := osprofiles.GetProfile[*ProfileConfig](profiler, "first")
	if err != nil {
		t.Fatal(err)
	}
	global := osprofiles.GetGlobalConfig(profiler)
	for _, test := range []struct {
		name  string
		raw   string
		err   error
		set   func(json.RawMessage) error
		read  func() (bool, error)
		write func() error
		get   func(string) (json.RawMessage, bool, error)
	}{
		{"global unknown", `{"enabled":true,"future":{"nested":99}}`, ErrExtensionUnsafeUpdate, func(raw json.RawMessage) error { return global.SetExtension("alpha", raw) }, func() (bool, error) {
			_, ok, err := ReadGlobalExtension[consumerGlobal](settings, "alpha")
			return ok, err
		}, func() error { return WriteGlobalExtension(settings, "alpha", consumerGlobal{false}) }, global.Extension},
		{"profile unknown", `{"label":"old","future":42}`, ErrExtensionUnsafeUpdate, func(raw json.RawMessage) error { return profile.SetExtension("alpha", raw) }, func() (bool, error) {
			_, ok, err := ReadProfileExtension[consumerProfile](settings, "first", "alpha")
			return ok, err
		}, func() error { return WriteProfileExtension(settings, "first", "alpha", consumerProfile{"new"}) }, profile.Extension},
		{"global duplicate key", `{"enabled":true,"enabled":false}`, ErrExtensionUnsafeUpdate, func(raw json.RawMessage) error { return global.SetExtension("alpha", raw) }, func() (bool, error) {
			_, ok, err := ReadGlobalExtension[consumerGlobal](settings, "alpha")
			return ok, err
		}, func() error { return WriteGlobalExtension(settings, "alpha", consumerGlobal{false}) }, global.Extension},
		{"global malformed", `{"enabled":"private-token"}`, ErrExtensionDecode, func(raw json.RawMessage) error { return global.SetExtension("alpha", raw) }, func() (bool, error) {
			_, ok, err := ReadGlobalExtension[consumerGlobal](settings, "alpha")
			return ok, err
		}, func() error { return WriteGlobalExtension(settings, "alpha", consumerGlobal{false}) }, global.Extension},
		{"profile malformed", `{"label":42}`, ErrExtensionDecode, func(raw json.RawMessage) error { return profile.SetExtension("alpha", raw) }, func() (bool, error) {
			_, ok, err := ReadProfileExtension[consumerProfile](settings, "first", "alpha")
			return ok, err
		}, func() error { return WriteProfileExtension(settings, "first", "alpha", consumerProfile{"new"}) }, profile.Extension},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.set(json.RawMessage(test.raw)); err != nil {
				t.Fatal(err)
			}
			present, err := test.read()
			if !present || (errors.Is(test.err, ErrExtensionDecode) && !errors.Is(err, test.err)) || (errors.Is(test.err, ErrExtensionUnsafeUpdate) && err != nil) {
				t.Fatalf("read: %v %v", present, err)
			}
			if err := test.write(); !errors.Is(err, test.err) || strings.Contains(err.Error(), "private-token") {
				t.Fatalf("write: %v", err)
			}
			got, present, err := test.get("alpha")
			if err != nil || !present || !reflect.DeepEqual(got, json.RawMessage(test.raw)) {
				t.Fatalf("changed after failed write: %s %v %v", got, present, err)
			}
		})
	}
}

func TestTypedExtensionChecksLatestStoredPayload(t *testing.T) {
	keyring.MockInit()
	first, err := CreateProfiler(ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := NewExtensionConfig(first, WithGlobalExtension[consumerGlobal]("alpha"), WithProfileExtension[consumerProfile]("alpha"))
	if err != nil {
		t.Fatal(err)
	}
	if err := first.AddProfile(&ProfileConfig{Name: "fixture"}, true); err != nil {
		t.Fatal(err)
	}
	other, err := CreateProfiler(ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	if err := osprofiles.GetGlobalConfig(other).SetExtension("alpha", json.RawMessage(`{"enabled":true,"newField":1}`)); err != nil {
		t.Fatal(err)
	}
	profile, err := osprofiles.GetProfile[*ProfileConfig](other, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.SetExtension("alpha", json.RawMessage(`{"label":"old","newField":2}`)); err != nil {
		t.Fatal(err)
	}
	if err := WriteGlobalExtension(stale, "alpha", consumerGlobal{false}); !errors.Is(err, ErrExtensionUnsafeUpdate) {
		t.Fatalf("stale global: %v", err)
	}
	if err := WriteProfileExtension(stale, "fixture", "alpha", consumerProfile{"new"}); !errors.Is(err, ErrExtensionUnsafeUpdate) {
		t.Fatalf("stale profile: %v", err)
	}
	fresh, err := CreateProfiler(ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := osprofiles.GetGlobalConfig(fresh).Extension("alpha"); err != nil || string(got) != `{"enabled":true,"newField":1}` {
		t.Fatalf("global changed: %s %v", got, err)
	}
	loaded, err := osprofiles.GetProfile[*ProfileConfig](fresh, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	if got, _, err := loaded.Extension("alpha"); err != nil || string(got) != `{"label":"old","newField":2}` {
		t.Fatalf("profile changed: %s %v", got, err)
	}
}

func TestTypedExtensionAcrossDriversAndNoCredentialDisclosure(t *testing.T) {
	keyring.MockInit()
	t.Setenv("HOME", t.TempDir())
	for _, driver := range []ProfileDriver{ProfileDriverFileSystem, ProfileDriverKeyring} {
		t.Run(string(driver), func(t *testing.T) {
			profiler, err := CreateProfiler(driver)
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := NewExtensionConfig(profiler, WithGlobalExtension[consumerGlobal]("alpha"), WithProfileExtension[consumerProfile]("alpha"))
			if err != nil {
				t.Fatal(err)
			}
			if err := WriteGlobalExtension(cfg, "alpha", consumerGlobal{true}); err != nil {
				t.Fatal(err)
			}
			if err := profiler.AddProfile(&ProfileConfig{Name: "fixture", Endpoint: "https://example.invalid"}, true); err != nil {
				t.Fatal(err)
			}
			if err := profiler.AddProfile(&ProfileConfig{Name: "other", Endpoint: "https://example.invalid"}, false); err != nil {
				t.Fatal(err)
			}
			if err := WriteProfileExtension(cfg, "fixture", "alpha", consumerProfile{"stored"}); err != nil {
				t.Fatal(err)
			}
			if err := WriteProfileExtension(cfg, "fixture", "alpha", consumerProfile{"updated"}); err != nil {
				t.Fatal(err)
			}
			profileStore, err := LoadOtdfctlProfileStore(driver, "fixture")
			if err != nil {
				t.Fatal(err)
			}
			credentials := AuthCredentials{AuthType: AuthTypeClientCredentials, ClientID: "id", ClientSecret: "private-token"}
			if err := profileStore.SetAuthCredentials(credentials); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(fmt.Sprint(cfg), "private-token") {
				t.Fatal("extension config printed credentials")
			}
			loaded, err := CreateProfiler(driver)
			if err != nil {
				t.Fatal(err)
			}
			loadedCfg, err := NewExtensionConfig(loaded, WithGlobalExtension[consumerGlobal]("alpha"), WithProfileExtension[consumerProfile]("alpha"))
			if err != nil {
				t.Fatal(err)
			}
			if value, ok, err := ReadGlobalExtension[consumerGlobal](loadedCfg, "alpha"); err != nil || !ok || !value.Enabled {
				t.Fatalf("global reload: %+v %v %v", value, ok, err)
			}
			if value, ok, err := ReadProfileExtension[consumerProfile](loadedCfg, "fixture", "alpha"); err != nil || !ok || value.Label != "updated" {
				t.Fatalf("profile reload: %+v %v %v", value, ok, err)
			}
			if _, ok, err := ReadProfileExtension[consumerProfile](loadedCfg, "other", "alpha"); err != nil || ok {
				t.Fatalf("other profile: %v %v", ok, err)
			}
			if osprofiles.GetGlobalConfig(loaded).GetDefaultProfile() != "fixture" {
				t.Fatal("extension changed the default")
			}
			if raw, err := keyring.Get(config.AppName, "profile-fixture"); driver == ProfileDriverKeyring && (err != nil || !strings.Contains(raw, "private-token")) {
				t.Fatalf("existing credentials were not retained: %v", err)
			}
		})
	}
}
