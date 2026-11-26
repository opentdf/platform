package store

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/zalando/go-keyring"
)

func TestKeyringCreatePresenceDistinguishesLookupErrors(t *testing.T) {
	keyring.MockInit()
	t.Cleanup(keyring.MockInit)
	s, err := NewKeyringStore("create_test", "profile")
	if err != nil {
		t.Fatal(err)
	}
	if exists, err := ExistsForCreate(s); err != nil || exists {
		t.Fatalf("missing: %v %v", exists, err)
	}
	// Even an empty keyring value is an observed record, not permission to overwrite.
	if err := keyring.Set("create_test", "profile", ""); err != nil {
		t.Fatal(err)
	}
	if exists, err := ExistsForCreate(s); err != nil || !exists {
		t.Fatalf("empty existing: %v %v", exists, err)
	}
	lookupError := errors.New("keyring lookup unavailable")
	keyring.MockInitWithError(lookupError)
	if exists, err := ExistsForCreate(s); exists || !errors.Is(err, lookupError) {
		t.Fatalf("lookup failure: %v %v", exists, err)
	}
	if s.Exists() {
		t.Fatal("legacy Exists behavior changed")
	}
}

func TestFilesystemCreatePresenceWithoutKeyring(t *testing.T) {
	// Any accidental key retrieval fails; presence checks must use native Stat only.
	keyring.MockInitWithError(errors.New("keyring must not be accessed"))
	t.Cleanup(keyring.MockInit)
	dir := t.TempDir()
	s := &fileStore{filePath: filepath.Join(dir, "record")}
	if exists, err := ExistsForCreate(s); err != nil || exists {
		t.Fatalf("missing: %v %v", exists, err)
	}
	if err := os.WriteFile(s.filePath, []byte("opaque existing bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if exists, err := ExistsForCreate(s); err != nil || !exists {
		t.Fatalf("existing: %v %v", exists, err)
	}
	// A path with a regular-file parent has a native Stat error, not absence.
	s.filePath = filepath.Join(s.filePath, "child")
	if exists, err := ExistsForCreate(s); exists || err == nil {
		t.Fatalf("stat failure: %v %v", exists, err)
	}
}

type customCreateRead struct {
	data []byte
	err  error
}

func (s customCreateRead) Exists() bool          { panic("create must not use lossy Exists") }
func (s customCreateRead) Get() ([]byte, error)  { return s.data, s.err }
func (s customCreateRead) Set(interface{}) error { panic("presence check must not write") }
func (s customCreateRead) Delete() error         { panic("presence check must not delete") }

func TestCustomCreatePresenceContract(t *testing.T) {
	lookupError := errors.New("custom lookup failed")
	for _, tc := range []struct {
		name       string
		input      customCreateRead
		wantExists bool
		wantErr    error
	}{
		{"nil absence", customCreateRead{}, false, nil},
		{"explicit absence", customCreateRead{err: fs.ErrNotExist}, false, nil},
		{"empty existing", customCreateRead{data: []byte{}}, true, nil},
		{"invalid existing", customCreateRead{data: []byte("invalid JSON")}, true, nil},
		{"lookup failure", customCreateRead{err: lookupError}, false, lookupError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exists, err := ExistsForCreate(tc.input)
			if exists != tc.wantExists || !errors.Is(err, tc.wantErr) {
				t.Fatalf("presence: %v %v", exists, err)
			}
		})
	}
}
