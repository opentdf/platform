package profiles_test

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/opentdf/platform/otdfctl/pkg/config"
	"github.com/opentdf/platform/otdfctl/pkg/profiles"
	"github.com/opentdf/platform/otdfctl/pkg/profiles/extensions"
	"github.com/zalando/go-keyring"
)

// A consumer can name the engine in its own interface without internal imports.
type profileConsumer interface {
	Inventory(*profiles.Profiler) ([]string, error)
}

type consumer struct{}

func (consumer) Inventory(p *profiles.Profiler) ([]string, error) { return profiles.ListProfiles(p) }

var _ profileConsumer = consumer{}

func requireDefault(t *testing.T, p *profiles.Profiler, want string) {
	t.Helper()
	got, err := profiles.GetDefault(p)
	if err != nil || got != want {
		t.Fatalf("default = %q, %v; want %q", got, err, want)
	}
}

func TestProfileFacadeRegistrationAndExplicitDefault(t *testing.T) {
	keyring.MockInit()
	for _, driver := range []profiles.ProfileDriver{profiles.ProfileDriverKeyring, profiles.ProfileDriverFileSystem} {
		t.Run(string(driver), func(t *testing.T) {
			keyring.MockInit()
			t.Setenv("HOME", t.TempDir())
			t.Setenv("LOCALAPPDATA", t.TempDir())
			p, err := profiles.CreateProfiler(driver)
			if err != nil {
				t.Fatal(err)
			}
			requireDefault(t, p, "")
			for _, name := range []string{"first", "second"} {
				input := &profiles.ProfileConfig{Name: name, Endpoint: "https://example.invalid", AuthCredentials: profiles.AuthCredentials{AuthType: profiles.AuthTypeClientCredentials, ClientID: "synthetic-id", ClientSecret: "synthetic-not-secret"}}
				stored, err := profiles.RegisterProfile(p, input)
				if err != nil {
					t.Fatal(err)
				}
				if stored.Name() != name || stored.GetEndpoint() != "https://example.invalid:443" || stored.IsDefault() || stored.GetAuthCredentials().ClientID != "synthetic-id" {
					t.Fatal("unexpected created profile")
				}
				if input.Endpoint != "https://example.invalid" {
					t.Fatal("registration mutated caller configuration")
				}
				requireDefault(t, p, "")
			}
			inventory, err := (consumer{}).Inventory(p)
			if err != nil || len(inventory) != 2 {
				t.Fatalf("inventory: %v %v", inventory, err)
			}
			inventory[0] = "mutated"
			inventory, err = profiles.ListProfiles(p)
			if err != nil || inventory[0] != "first" {
				t.Fatal("inventory aliases engine")
			}
			if err := profiles.SetDefault(p, "missing"); !errors.Is(err, profiles.ErrMissingProfileName) {
				t.Fatal(err)
			}
			requireDefault(t, p, "")
			if err := profiles.SetDefault(p, "second"); err != nil {
				t.Fatal(err)
			}
			if _, err := profiles.RegisterProfile(p, &profiles.ProfileConfig{Name: "third", Endpoint: "https://example.invalid"}); err != nil {
				t.Fatal(err)
			}
			requireDefault(t, p, "second")
			if _, err := profiles.RegisterProfile(p, &profiles.ProfileConfig{Name: "first", Endpoint: "https://example.invalid"}); !errors.Is(err, profiles.ErrProfileNameConflict) {
				t.Fatal(err)
			}
			if _, err := profiles.RegisterProfile(p, &profiles.ProfileConfig{Name: "Bad/Name", Endpoint: "https://example.invalid"}); err == nil {
				t.Fatal("invalid name accepted")
			}
			if _, err := profiles.RegisterProfile(p, &profiles.ProfileConfig{Name: "bad-endpoint", Endpoint: "://"}); err == nil {
				t.Fatal("invalid endpoint accepted")
			}
			requireDefault(t, p, "second")
			fresh, err := profiles.CreateProfiler(driver)
			if err != nil {
				t.Fatal(err)
			}
			requireDefault(t, fresh, "second")
			loaded, err := profiles.LoadProfile(fresh, "first")
			if err != nil || loaded.GetEndpoint() != "https://example.invalid:443" || loaded.GetAuthCredentials().ClientSecret != "synthetic-not-secret" {
				t.Fatalf("reload: %v", err)
			}
			requireDefault(t, fresh, "second")
		})
	}
}

func TestProfileFacadeOpaquePersistenceAndNoImplicitDefault(t *testing.T) {
	keyring.MockInit()
	const global = `{"version":"1.0","profiles":["existing"],"defaultProfile":"","futureGlobal":{"keep":1},"extensions":{"other":{"global":true}}}`
	const profile = `{"profile":"existing","endpoint":"https://old.invalid","futureProfile":[1,2],"authCredentials":{"futureAuth":42},"extensions":{"other":{"profile":true}}}`
	if err := keyring.Set(config.AppName, "global", global); err != nil {
		t.Fatal(err)
	}
	if err := keyring.Set(config.AppName, "profile-existing", profile); err != nil {
		t.Fatal(err)
	}
	p, err := profiles.CreateProfiler(profiles.ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	before, err := keyring.Get(config.AppName, "global")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := profiles.ListProfiles(p); err != nil {
		t.Fatal(err)
	}
	requireDefault(t, p, "")
	loaded, err := profiles.LoadProfile(p, "existing")
	if err != nil {
		t.Fatal(err)
	}
	after, err := keyring.Get(config.AppName, "global")
	if err != nil || before != after {
		t.Fatal("inventory/default/load wrote global data")
	}
	if err := loaded.SetEndpoint("https://new.invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := profiles.RegisterProfile(p, &profiles.ProfileConfig{Name: "new", Endpoint: "https://example.invalid"}); err != nil {
		t.Fatal(err)
	}
	requireDefault(t, p, "")
	cfg, err := extensions.NewConfig(p, extensions.WithGlobal[bool]("consumer"), extensions.WithProfile[bool]("consumer"))
	if err != nil {
		t.Fatal(err)
	}
	if err := extensions.WriteGlobal(cfg, "consumer", false); err != nil {
		t.Fatal(err)
	}
	if err := extensions.WriteProfile(cfg, "existing", "consumer", false); err != nil {
		t.Fatal(err)
	}
	if err := profiles.SetDefault(p, "new"); err != nil {
		t.Fatal(err)
	}
	for key, expected := range map[string]map[string]json.RawMessage{
		"global":           {"futureGlobal": json.RawMessage(`{"keep":1}`)},
		"profile-existing": {"futureProfile": json.RawMessage(`[1,2]`)},
	} {
		raw, err := keyring.Get(config.AppName, key)
		if err != nil {
			t.Fatal(err)
		}
		var object map[string]json.RawMessage
		if err := json.Unmarshal([]byte(raw), &object); err != nil {
			t.Fatal(err)
		}
		for field, want := range expected {
			if string(object[field]) != string(want) {
				t.Fatalf("lost %s in %s", field, raw)
			}
		}
		var namespaces map[string]json.RawMessage
		if err := json.Unmarshal(object["extensions"], &namespaces); err != nil {
			t.Fatal(err)
		}
		if string(namespaces["consumer"]) != "false" || namespaces["other"] == nil {
			t.Fatal("lost extension namespace")
		}
		if key == "profile-existing" {
			var auth map[string]json.RawMessage
			if err := json.Unmarshal(object["authCredentials"], &auth); err != nil || string(auth["futureAuth"]) != "42" {
				t.Fatal("lost nested opaque field")
			}
		}
	}
	fresh, err := profiles.CreateProfiler(profiles.ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	requireDefault(t, fresh, "new")
	freshConfig, err := extensions.NewConfig(fresh, extensions.WithProfile[bool]("consumer"))
	if err != nil {
		t.Fatal(err)
	}
	if got, present, err := extensions.ReadProfile[bool](freshConfig, "existing", "consumer"); err != nil || !present || got {
		t.Fatalf("stored No: %v %v %v", got, present, err)
	}
	if _, present, err := extensions.ReadProfile[bool](freshConfig, "new", "consumer"); err != nil || present {
		t.Fatalf("absent: %v %v", present, err)
	}
}

func TestProfileFacadeInvalidEngineAndOrphanCollision(t *testing.T) {
	for _, p := range []*profiles.Profiler{nil, {}} {
		if _, err := profiles.ListProfiles(p); !errors.Is(err, profiles.ErrInvalidProfiler) {
			t.Fatal(err)
		}
		if _, err := profiles.GetDefault(p); !errors.Is(err, profiles.ErrInvalidProfiler) {
			t.Fatal(err)
		}
		if err := profiles.SetDefault(p, "name"); !errors.Is(err, profiles.ErrInvalidProfiler) {
			t.Fatal(err)
		}
		if _, err := profiles.LoadProfile(p, "name"); !errors.Is(err, profiles.ErrInvalidProfiler) {
			t.Fatal(err)
		}
		if _, err := profiles.RegisterProfile(p, &profiles.ProfileConfig{}); !errors.Is(err, profiles.ErrInvalidProfiler) {
			t.Fatal(err)
		}
	}
	keyring.MockInit()
	p, err := profiles.CreateProfiler(profiles.ProfileDriverKeyring)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := profiles.RegisterProfile(p, nil); !errors.Is(err, profiles.ErrProfileConfigEmpty) {
		t.Fatal(err)
	}
	const orphan = `{"profile":"orphan","future":true}`
	if err := keyring.Set(config.AppName, "profile-orphan", orphan); err != nil {
		t.Fatal(err)
	}
	if _, err := profiles.RegisterProfile(p, &profiles.ProfileConfig{Name: "orphan", Endpoint: "https://example.invalid"}); !errors.Is(err, profiles.ErrProfileNameConflict) {
		t.Fatal(err)
	}
	raw, err := keyring.Get(config.AppName, "profile-orphan")
	if err != nil || raw != orphan {
		t.Fatal("overwrote orphan")
	}
	requireDefault(t, p, "")
	if err := p.Cleanup(false); err != nil {
		t.Fatal(err)
	}
	if _, err := profiles.GetDefault(p); !errors.Is(err, profiles.ErrInvalidProfiler) {
		t.Fatal(err)
	}
}

func TestProfileRegistrationSanitizesEndpointErrors(t *testing.T) {
	p, err := profiles.CreateProfiler(profiles.ProfileDriverMemory)
	if err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []string{
		"https://user:synthetic-password@example.invalid:bad",
		"https://example.invalid:bad?token=synthetic-query-token",
		"https://user:synthetic-password@example.invalid:bad?token=synthetic-query-token",
		"", "ftp://example.invalid",
	} {
		// Do not use a secret-bearing endpoint as a subtest name/log message.
		_, err := profiles.RegisterProfile(p, &profiles.ProfileConfig{Name: "invalid", Endpoint: endpoint})
		if !errors.Is(err, profiles.ErrProfileEndpointInvalid) {
			t.Fatal("registration did not return the sanitized public sentinel")
		}
		if strings.Contains(err.Error(), "synthetic-") || strings.Contains(err.Error(), endpoint) && endpoint != "" {
			t.Fatal("endpoint leaked through error text")
		}
		var parseError *url.Error
		if errors.As(err, &parseError) || errors.Unwrap(err) != nil {
			t.Fatal("registration exposed underlying URL parse error")
		}
		requireDefault(t, p, "")
		inventory, err := profiles.ListProfiles(p)
		if err != nil || len(inventory) != 0 {
			t.Fatal("invalid endpoint mutated inventory")
		}
	}
}

func TestLegacyAddProfileStillChoosesFirstDefault(t *testing.T) {
	p, err := profiles.CreateProfiler(profiles.ProfileDriverMemory)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.AddProfile(&profiles.ProfileConfig{Name: "first"}, false); err != nil {
		t.Fatal(err)
	}
	requireDefault(t, p, "first")
}
