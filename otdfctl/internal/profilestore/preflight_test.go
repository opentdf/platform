package profilestore

import (
	"errors"
	"testing"

	"github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/store"
)

func TestOpenDefersGlobalInitializationAndUpgrade(t *testing.T) {
	previous := store.NewCustomStore
	t.Cleanup(func() { store.NewCustomStore = previous })
	for _, data := range []string{"", `{"version":"old","profiles":[],"defaultProfile":"","future":true}`} {
		t.Run(data, func(t *testing.T) {
			raw := &registrationStore{data: []byte(data)}
			if data == "" {
				raw.data = nil
			}
			factory := func(_ string, _ string, _ ...store.DriverOpt) (store.Interface, error) { return raw, nil }
			p, err := Open("preflight_test", WithCustomStore(factory))
			if err != nil {
				t.Fatal(err)
			}
			if len(ListProfiles(p)) != 0 || GetGlobalConfig(p).GetDefaultProfile() != "" {
				t.Fatal("unexpected preflight inventory/default")
			}
			if raw.writes != 0 || string(raw.data) != data {
				t.Fatal("Open wrote the global record")
			}
			if _, err := New("preflight_test", WithCustomStore(factory)); err != nil {
				t.Fatal(err)
			}
			if raw.writes != 1 || string(raw.data) == data {
				t.Fatal("New no longer initializes/upgrades the global record")
			}
		})
	}
}

func TestOpenAndHasProfileStorePropagateLookupFailure(t *testing.T) {
	previous := store.NewCustomStore
	t.Cleanup(func() { store.NewCustomStore = previous })
	lookupError := errors.New("temporary lookup failure")
	globalStore := &registrationStore{data: []byte(`{"version":"1.0","profiles":[],"defaultProfile":""}`)}
	profileStore := &registrationStore{data: []byte(`{"profile":"orphan"}`)}
	factory := func(_ string, key string, _ ...store.DriverOpt) (store.Interface, error) {
		if key == "global" {
			return globalStore, nil
		}
		return profileStore, nil
	}
	globalStore.readErrors = []error{lookupError, nil}
	if _, err := Open("preflight_test", WithCustomStore(factory)); !errors.Is(err, lookupError) {
		t.Fatalf("Open ignored lookup failure: %v", err)
	}
	p, err := Open("preflight_test", WithCustomStore(factory))
	if err != nil {
		t.Fatal(err)
	}
	profileStore.readErrors = []error{lookupError, nil}
	if exists, err := HasProfileStore(p, "orphan"); exists || !errors.Is(err, lookupError) {
		t.Fatalf("presence ignored lookup failure: %v %v", exists, err)
	}
	if exists, err := HasProfileStore(p, "orphan"); !exists || err != nil {
		t.Fatalf("presence missed orphan: %v %v", exists, err)
	}
	if globalStore.writes != 0 || profileStore.writes != 0 {
		t.Fatal("preflight wrote to storage")
	}
}
