package profilestore

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/store"
)

var errRegistrationWrite = errors.New("injected write failure")

type registrationStore struct {
	data []byte
	fail bool
}

func (s *registrationStore) Exists() bool         { return s.data != nil }
func (s *registrationStore) Get() ([]byte, error) { return s.data, nil }
func (s *registrationStore) Delete() error        { s.data = nil; return nil }
func (s *registrationStore) Set(value interface{}) error {
	if s.fail {
		return errRegistrationWrite
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	s.data = data
	return nil
}

func TestRegistrationAndDefaultStorageFailures(t *testing.T) {
	previous := store.NewCustomStore
	t.Cleanup(func() { store.NewCustomStore = previous })
	for _, initialDefault := range []string{"", "existing"} {
		t.Run("default="+initialDefault, func(t *testing.T) {
			globalStore := &registrationStore{data: []byte(`{"version":"1.0","profiles":["existing","target"],"defaultProfile":"` + initialDefault + `","future":true,"extensions":{"other":false}}`)}
			profileStore := &registrationStore{}
			factory := func(_ string, key string, _ ...store.DriverOpt) (store.Interface, error) {
				if key == "global" {
					return globalStore, nil
				}
				return profileStore, nil
			}
			p, err := New("registration_test", WithCustomStore(factory))
			if err != nil {
				t.Fatal(err)
			}
			original := string(globalStore.data)
			globalStore.fail = true
			if err := SetDefaultProfile(p, "target"); !errors.Is(err, errRegistrationWrite) {
				t.Fatal(err)
			}
			if got := GetGlobalConfig(p).GetDefaultProfile(); got != initialDefault {
				t.Fatalf("failed default cached %q", got)
			}
			if _, err := RegisterProfile(p, &fixtureProfile{Name: "new"}); !errors.Is(err, errRegistrationWrite) {
				t.Fatal(err)
			}
			if GetGlobalConfig(p).ProfileExists("new") || string(globalStore.data) != original {
				t.Fatal("failed registration changed global state")
			}
			if got := GetGlobalConfig(p).GetDefaultProfile(); got != initialDefault {
				t.Fatal("failed registration changed default")
			}
			globalStore.fail = false
			if _, err := RegisterProfile(p, &fixtureProfile{Name: "new"}); !errors.Is(err, ErrProfileNameConflict) {
				t.Fatalf("orphan retry: %v", err)
			}
			// A new engine sees the same retained default after the failed writes.
			fresh, err := New("registration_test", WithCustomStore(factory))
			if err != nil || GetGlobalConfig(fresh).GetDefaultProfile() != initialDefault {
				t.Fatalf("reload: %v", err)
			}
		})
	}
}
