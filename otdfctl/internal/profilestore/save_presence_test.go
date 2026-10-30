package profilestore

import (
	"bytes"
	"errors"
	"testing"

	"github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/store"
	"github.com/zalando/go-keyring"
)

// Like the legacy keyring probe, an empty value or failed read looks absent.
type savePresenceStore struct{ registrationStore }

func (s *savePresenceStore) Exists() bool {
	data, err := s.Get()
	return err == nil && len(data) > 0
}

func TestCoreSavePresenceFailureDoesNotOverwriteLatest(t *testing.T) {
	previous := store.NewCustomStore
	t.Cleanup(func() { store.NewCustomStore = previous })
	for _, scope := range []string{"profile", "global"} {
		for _, failure := range []string{"lookup", "empty-record"} {
			t.Run(scope+"/"+failure, func(t *testing.T) {
				global := &savePresenceStore{registrationStore{data: []byte(`{"version":"1.0","profiles":["alpha"],"defaultProfile":""}`)}}
				profile := &savePresenceStore{registrationStore{data: []byte(`{"profile":"alpha","endpoint":"https://old.invalid"}`)}}
				factory := func(_ string, key string, _ ...store.DriverOpt) (store.Interface, error) {
					if key == "global" {
						return global, nil
					}
					return profile, nil
				}
				p, err := New("save_presence", WithCustomStore(factory))
				if err != nil {
					t.Fatal(err)
				}
				loaded, err := GetProfile[*fixtureProfile](p, "alpha")
				if err != nil {
					t.Fatal(err)
				}
				target := profile
				save := loaded.Save
				latest := []byte(`{"profile":"alpha","endpoint":"https://old.invalid","future":true,"extensions":{"newer":{"keep":true}}}`)
				if scope == "global" {
					target = global
					save = func() error { return GetGlobalConfig(p).SetDefaultProfile("alpha") }
					latest = []byte(`{"version":"1.0","profiles":["alpha"],"defaultProfile":"","future":true,"extensions":{"newer":{"keep":true}}}`)
				}
				// Another completed write occurs after loading the stale handle.
				target.data = bytes.Clone(latest)
				lookupError := errors.New("transient lookup failure")
				if failure == "lookup" {
					target.readErrors = []error{lookupError}
				} else {
					target.data = []byte{}
				}
				original := bytes.Clone(target.data)
				writes := target.writes
				err = save()
				if err == nil || (failure == "lookup" && !errors.Is(err, lookupError)) {
					t.Fatalf("save must reject %s: %v", failure, err)
				}
				if target.writes != writes || !bytes.Equal(target.data, original) {
					t.Fatal("failed presence check changed stored bytes")
				}
				if GetGlobalConfig(p).GetDefaultProfile() != "" {
					t.Fatal("failed save changed cached default")
				}
				// A later successful read must rebase on the persisted record.
				target.data = latest
				if err := save(); err != nil {
					t.Fatal(err)
				}
				if !bytes.Contains(target.data, []byte(`"future":true`)) || !bytes.Contains(target.data, []byte(`"newer":{"keep":true}`)) {
					t.Fatalf("retry lost newer opaque data: %s", target.data)
				}
			})
		}
	}
}

func TestCoreSaveRejectsExistingEmptyKeyringRecord(t *testing.T) {
	for _, scope := range []string{"profile", "global"} {
		t.Run(scope, func(t *testing.T) {
			keyring.MockInit()
			const namespace = "empty_save_presence"
			p, err := New(namespace, WithKeyringStore())
			if err != nil {
				t.Fatal(err)
			}
			loaded, err := RegisterProfile(p, &fixtureProfile{Name: "alpha"})
			if err != nil {
				t.Fatal(err)
			}
			key := "profile-alpha"
			save := loaded.Save
			if scope == "global" {
				key = "global"
				save = func() error { return GetGlobalConfig(p).SetDefaultProfile("alpha") }
			}
			if err := keyring.Set(namespace, key, ""); err != nil {
				t.Fatal(err)
			}
			if err := save(); err == nil {
				t.Fatal("empty persisted record was accepted")
			}
			if value, err := keyring.Get(namespace, key); err != nil || value != "" {
				t.Fatalf("empty record overwritten: %q %v", value, err)
			}
		})
	}
}
