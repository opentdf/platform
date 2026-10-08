package profilestore

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/store"
)

var errRegistrationWrite = errors.New("injected write failure")

type registrationStore struct {
	data        []byte
	fail        bool
	partialFail bool
	readErrors  []error
	reads       int
	writes      int
}

// Match the legacy keyring behavior: lookup errors collapse to false.
func (s *registrationStore) Exists() bool {
	data, err := s.Get()
	return err == nil && data != nil
}

func (s *registrationStore) Get() ([]byte, error) {
	s.reads++
	if len(s.readErrors) > 0 {
		err := s.readErrors[0]
		s.readErrors = s.readErrors[1:]
		if err != nil {
			return nil, err
		}
	}
	return s.data, nil
}
func (s *registrationStore) Delete() error { s.data = nil; return nil }
func (s *registrationStore) Set(value interface{}) error {
	s.writes++
	if s.fail {
		return errRegistrationWrite
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	s.data = data
	if s.partialFail {
		return errRegistrationWrite
	}
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

func TestRegistrationLookupFailureNeverUpdatesOrphan(t *testing.T) {
	previous := store.NewCustomStore
	t.Cleanup(func() { store.NewCustomStore = previous })
	for _, initialDefault := range []string{"", "existing"} {
		t.Run("default="+initialDefault, func(t *testing.T) {
			globalStore := &registrationStore{data: []byte(`{"version":"1.0","profiles":["existing"],"defaultProfile":"` + initialDefault + `","future":true}`)}
			const originalProfile = ` {"profile":"orphan","endpoint":"https://old.invalid","future":{"keep":true}} `
			profileStore := &registrationStore{data: []byte(originalProfile)}
			factory := func(_ string, key string, _ ...store.DriverOpt) (store.Interface, error) {
				if key == "global" {
					return globalStore, nil
				}
				return profileStore, nil
			}
			p, err := New("lookup_test", WithCustomStore(factory))
			if err != nil {
				t.Fatal(err)
			}
			originalGlobal := string(globalStore.data)
			lookupError := errors.New("temporary lookup failure")
			profileStore.readErrors = []error{lookupError, nil}
			_, err = RegisterProfile(p, &fixtureProfile{Name: "orphan", Endpoint: "https://new.invalid"})
			if !errors.Is(err, lookupError) {
				t.Fatalf("lookup error: %v; profile writes=%d, global writes=%d, orphan changed=%v", err, profileStore.writes, globalStore.writes, string(profileStore.data) != originalProfile)
			}
			if profileStore.reads != 1 {
				t.Fatalf("unexpected repeat lookup: %d", profileStore.reads)
			}
			// The next bounded read succeeds, demonstrating the transient sequence.
			data, err := profileStore.Get()
			if err != nil || string(data) != originalProfile {
				t.Fatal("orphan mutated after read failure")
			}
			if _, err := RegisterProfile(p, &fixtureProfile{Name: "orphan"}); !errors.Is(err, ErrProfileNameConflict) {
				t.Fatalf("retry: %v", err)
			}
			if profileStore.writes != 0 || globalStore.writes != 0 || string(globalStore.data) != originalGlobal || string(profileStore.data) != originalProfile {
				t.Fatal("unauthorized write or changed raw bytes")
			}
			if GetGlobalConfig(p).ProfileExists("orphan") || GetGlobalConfig(p).GetDefaultProfile() != initialDefault {
				t.Fatal("global cache changed")
			}
		})
	}
}

func TestRegistrationCreateWriteFailureStates(t *testing.T) {
	previous := store.NewCustomStore
	t.Cleanup(func() { store.NewCustomStore = previous })
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-write", true: "partial-write"}[partial], func(t *testing.T) {
			globalStore := &registrationStore{data: []byte(`{"version":"1.0","profiles":[],"defaultProfile":""}`)}
			profileStore := &registrationStore{fail: !partial, partialFail: partial}
			factory := func(_ string, key string, _ ...store.DriverOpt) (store.Interface, error) {
				if key == "global" {
					return globalStore, nil
				}
				return profileStore, nil
			}
			p, err := New("write_test", WithCustomStore(factory))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := RegisterProfile(p, &fixtureProfile{Name: "new"}); !errors.Is(err, errRegistrationWrite) {
				t.Fatal(err)
			}
			if globalStore.writes != 0 || GetGlobalConfig(p).ProfileExists("new") || GetGlobalConfig(p).GetDefaultProfile() != "" {
				t.Fatal("failed profile write registered/defaulted")
			}
			if (profileStore.data != nil) != partial {
				t.Fatal("unexpected partial record state")
			}
			profileStore.fail, profileStore.partialFail = false, false
			_, err = RegisterProfile(p, &fixtureProfile{Name: "new"})
			if partial {
				if !errors.Is(err, ErrProfileNameConflict) || profileStore.writes != 1 {
					t.Fatalf("partial retry: %v", err)
				}
			} else if err != nil || profileStore.writes != 2 || !GetGlobalConfig(p).ProfileExists("new") {
				t.Fatalf("clean retry: %v", err)
			}
		})
	}
}

func TestRegistrationMemoryCreateAndLegacyUpdate(t *testing.T) {
	p, err := New("memory_create", WithInMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	created, err := RegisterProfile(p, &fixtureProfile{Name: "new", Endpoint: "https://old.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	if GetGlobalConfig(p).GetDefaultProfile() != "" {
		t.Fatal("memory create chose default")
	}
	created.Profile = &fixtureProfile{Name: "new", Endpoint: "https://updated.invalid"}
	if err := created.Save(); err != nil {
		t.Fatal(err)
	}
	updated, err := GetStoredProfile[*fixtureProfile](created)
	if err != nil || updated.Endpoint != "https://updated.invalid" {
		t.Fatalf("legacy update: %v", err)
	}
	if _, err := RegisterProfile(p, &fixtureProfile{Name: "new"}); !errors.Is(err, ErrProfileNameConflict) {
		t.Fatal(err)
	}
}

func TestRegistrationGlobalPartialWriteIsNotRollback(t *testing.T) {
	previous := store.NewCustomStore
	t.Cleanup(func() { store.NewCustomStore = previous })
	globalStore := &registrationStore{data: []byte(`{"version":"1.0","profiles":[],"defaultProfile":""}`), partialFail: true}
	profileStore := &registrationStore{}
	factory := func(_ string, key string, _ ...store.DriverOpt) (store.Interface, error) {
		if key == "global" {
			return globalStore, nil
		}
		return profileStore, nil
	}
	p, err := New("partial_global", WithCustomStore(factory))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RegisterProfile(p, &fixtureProfile{Name: "new"}); !errors.Is(err, errRegistrationWrite) {
		t.Fatal(err)
	}
	if GetGlobalConfig(p).ProfileExists("new") || GetGlobalConfig(p).GetDefaultProfile() != "" {
		t.Fatal("cached state changed after failed write")
	}
	if profileStore.writes != 1 || globalStore.writes != 1 {
		t.Fatal("unexpected writes")
	}
	// The custom driver persisted before returning an error. No write-back rollback
	// is promised: a fresh engine sees the registered record and retained default.
	fresh, err := New("partial_global", WithCustomStore(factory))
	if err != nil || !GetGlobalConfig(fresh).ProfileExists("new") || GetGlobalConfig(fresh).GetDefaultProfile() != "" {
		t.Fatalf("partial reload: %v", err)
	}
	if _, err := RegisterProfile(p, &fixtureProfile{Name: "new"}); !errors.Is(err, ErrProfileNameConflict) {
		t.Fatal(err)
	}
	if profileStore.writes != 1 || globalStore.writes != 1 {
		t.Fatal("partial retry wrote")
	}
}
