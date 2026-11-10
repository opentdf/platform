package cukes

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// recordingHandler captures records so tests can assert on emitted attributes.
type recordingHandler struct {
	records *[]slog.Record
}

func (recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h recordingHandler) Handle(_ context.Context, r slog.Record) error {
	*h.records = append(*h.records, r)
	return nil
}

func (h recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h recordingHandler) WithGroup(string) slog.Handler { return h }

func TestChangePermissions_RecursesFilesButNotDirs(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "sub", "deeper")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	files := []string{
		filepath.Join(root, "top.pem"),
		filepath.Join(root, "sub", "mid.pem"),
		filepath.Join(nested, "leaf.pem"),
	}
	for _, f := range files {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := changePermissions(root, 0o644); err != nil {
		t.Fatalf("changePermissions: %v", err)
	}

	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o644 {
			t.Errorf("%s: got mode %o, want 644", f, got)
		}
	}
	// Directories are skipped, so the 0700 created above must survive.
	info, err := os.Stat(nested)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("%s: directory mode changed to %o, want 700", nested, got)
	}
}

func TestLogKeyFiles_OnlyReadsPEMs(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "kas.pem"), []byte("PEMBODY"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "notes.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}

	var logged []slog.Record
	handler := recordingHandler{records: &logged}
	if err := logKeyFiles(root, slog.New(handler)); err != nil {
		t.Fatalf("logKeyFiles: %v", err)
	}

	if len(logged) != 1 {
		t.Fatalf("got %d records, want 1 (only the .pem)", len(logged))
	}
	attrs := map[string]string{}
	logged[0].Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})
	if want := filepath.Join(root, "sub", "kas.pem"); attrs["path"] != want {
		t.Errorf("path attr = %q, want %q", attrs["path"], want)
	}
	if attrs["content"] != "PEMBODY" {
		t.Errorf("content attr = %q, want %q", attrs["content"], "PEMBODY")
	}
}
