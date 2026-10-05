package profilestore

import (
	"errors"
	"strings"
	"testing"

	"github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/store"
	"github.com/zalando/go-keyring"
)

func TestCopyUnknownToRejectsDistinctGlobalAndProfileFields(t *testing.T) {
	keyring.MockInit()
	for _, fixture := range []struct {
		namespace string
		value     string
	}{
		{"copy_source", `{"version":"1.0","profiles":["alpha"],"defaultProfile":"alpha","futureGlobal":1}`},
		{"copy_destination", `{"version":"1.0","profiles":["alpha"],"defaultProfile":"alpha","futureGlobal":2}`},
	} {
		if err := keyring.Set(fixture.namespace, "global", fixture.value); err != nil {
			t.Fatal(err)
		}
		value := `{"profile":"alpha","futureProfile":1}`
		if fixture.namespace == "copy_destination" {
			value = `{"profile":"alpha","futureProfile":2}`
		}
		if err := keyring.Set(fixture.namespace, "profile-alpha", value); err != nil {
			t.Fatal(err)
		}
	}
	source, err := New("copy_source", WithKeyringStore())
	if err != nil {
		t.Fatal(err)
	}
	destination, err := New("copy_destination", WithKeyringStore())
	if err != nil {
		t.Fatal(err)
	}
	if err := GetGlobalConfig(source).CopyUnknownTo(GetGlobalConfig(destination)); !errors.Is(err, store.ErrOpaqueConflict) {
		t.Fatalf("global unknown overwrite accepted: %v", err)
	}
	sourceProfile, err := GetProfile[*embeddedNamedProfile](source, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	destinationProfile, err := GetProfile[*embeddedNamedProfile](destination, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if err := sourceProfile.CopyUnknownTo(destinationProfile); !errors.Is(err, store.ErrOpaqueConflict) {
		t.Fatalf("profile unknown overwrite accepted: %v", err)
	}
	for key, want := range map[string]string{"global": `"futureGlobal":2`, "profile-alpha": `"futureProfile":2`} {
		got, err := keyring.Get("copy_destination", key)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(got, want) {
			t.Fatalf("destination %s changed: %s", key, got)
		}
	}
}
