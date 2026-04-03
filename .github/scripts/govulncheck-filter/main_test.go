package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsCalled(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		f      *Finding
		called bool
	}{
		{
			name:   "empty trace",
			f:      &Finding{OSV: "GO-2024-0001", Trace: nil},
			called: false,
		},
		{
			name: "module-level only (no function)",
			f: &Finding{
				OSV:   "GO-2024-0001",
				Trace: []Frame{{Module: "example.com/mod"}},
			},
			called: false,
		},
		{
			name: "symbol-level (has function)",
			f: &Finding{
				OSV:   "GO-2024-0001",
				Trace: []Frame{{Module: "example.com/mod", Function: "DoSomething"}},
			},
			called: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.called, isCalled(tt.f))
		})
	}
}

func TestLoadAllowlist(t *testing.T) {
	t.Parallel()

	t.Run("missing file returns empty map", func(t *testing.T) {
		t.Parallel()
		m, err := loadAllowlist(filepath.Join(t.TempDir(), "nonexistent.yaml"))
		require.NoError(t, err)
		assert.Empty(t, m)
	})

	t.Run("valid allowlist", func(t *testing.T) {
		t.Parallel()
		content := `
- id: GO-2024-0001
  reason: "no fix available"
  expires: 2099-12-31
- id: GO-2024-0002
  reason: "tracking upstream"
  expires: 2099-06-15
`
		path := filepath.Join(t.TempDir(), "allowlist.yaml")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		m, err := loadAllowlist(path)
		require.NoError(t, err)
		require.Len(t, m, 2)
		assert.Equal(t, "no fix available", m["GO-2024-0001"].Reason)
	})

	t.Run("missing id field", func(t *testing.T) {
		t.Parallel()
		content := `
- reason: "no fix"
  expires: 2099-12-31
`
		path := filepath.Join(t.TempDir(), "allowlist.yaml")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		_, err := loadAllowlist(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing 'id'")
	})

	t.Run("missing reason field", func(t *testing.T) {
		t.Parallel()
		content := `
- id: GO-2024-0001
  expires: 2099-12-31
`
		path := filepath.Join(t.TempDir(), "allowlist.yaml")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		_, err := loadAllowlist(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing 'reason'")
	})

	t.Run("invalid date format", func(t *testing.T) {
		t.Parallel()
		content := `
- id: GO-2024-0001
  reason: "test"
  expires: 12/31/2099
`
		path := filepath.Join(t.TempDir(), "allowlist.yaml")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		_, err := loadAllowlist(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid expires date")
	})

	t.Run("duplicate id keeps sooner expiry", func(t *testing.T) {
		t.Parallel()
		content := `
- id: GO-2024-0001
  reason: "later entry"
  expires: 2099-12-31
- id: GO-2024-0001
  reason: "sooner entry"
  expires: 2026-06-01
`
		path := filepath.Join(t.TempDir(), "allowlist.yaml")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		m, err := loadAllowlist(path)
		require.NoError(t, err)
		require.Len(t, m, 1)
		assert.Equal(t, "2026-06-01", m["GO-2024-0001"].Expires)
		assert.Equal(t, "sooner entry", m["GO-2024-0001"].Reason)
	})

	t.Run("duplicate id sooner entry first", func(t *testing.T) {
		t.Parallel()
		content := `
- id: GO-2024-0001
  reason: "sooner entry"
  expires: 2026-06-01
- id: GO-2024-0001
  reason: "later entry"
  expires: 2099-12-31
`
		path := filepath.Join(t.TempDir(), "allowlist.yaml")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		m, err := loadAllowlist(path)
		require.NoError(t, err)
		require.Len(t, m, 1)
		assert.Equal(t, "2026-06-01", m["GO-2024-0001"].Expires)
		assert.Equal(t, "sooner entry", m["GO-2024-0001"].Reason)
	})
}

func TestFindCalledVulns(t *testing.T) {
	t.Parallel()

	t.Run("pretty-printed JSON with mixed message types", func(t *testing.T) {
		t.Parallel()
		content := `{
  "config": {
    "protocol_version": "v1.0.0",
    "scanner_name": "govulncheck"
  }
}
{
  "osv": {
    "id": "GO-2024-0001",
    "summary": "Vuln one"
  }
}
{
  "osv": {
    "id": "GO-2024-0002",
    "summary": "Vuln two"
  }
}
{
  "finding": {
    "osv": "GO-2024-0001",
    "trace": [
      {
        "module": "example.com/mod",
        "package": "example.com/mod/pkg",
        "function": "Bad"
      }
    ]
  }
}
{
  "finding": {
    "osv": "GO-2024-0002",
    "trace": [
      {
        "module": "example.com/other",
        "package": "example.com/other/pkg"
      }
    ]
  }
}
`
		path := filepath.Join(t.TempDir(), "output.json")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		calledIDs, err := findCalledVulns(path)
		require.NoError(t, err)

		// Only GO-2024-0001 has a function-level trace (called).
		require.Len(t, calledIDs, 1)
		assert.Equal(t, "GO-2024-0001", calledIDs[0])
	})

	t.Run("no findings", func(t *testing.T) {
		t.Parallel()
		content := `{
  "config": {
    "protocol_version": "v1.0.0"
  }
}
`
		path := filepath.Join(t.TempDir(), "output.json")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		calledIDs, err := findCalledVulns(path)
		require.NoError(t, err)
		assert.Empty(t, calledIDs)
	})

	t.Run("deduplicates findings for same OSV", func(t *testing.T) {
		t.Parallel()
		content := `{
  "osv": {"id": "GO-2024-0001", "summary": "Vuln"}
}
{
  "finding": {
    "osv": "GO-2024-0001",
    "trace": [{"module": "m", "package": "p", "function": "A"}]
  }
}
{
  "finding": {
    "osv": "GO-2024-0001",
    "trace": [{"module": "m", "package": "p", "function": "B"}]
  }
}
`
		path := filepath.Join(t.TempDir(), "output.json")
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		calledIDs, err := findCalledVulns(path)
		require.NoError(t, err)
		require.Len(t, calledIDs, 1)
	})
}

func makeEntry(t *testing.T, id, reason, expires string) AllowlistEntry { //nolint:unparam // test helper
	t.Helper()
	parsed, err := time.Parse(time.DateOnly, expires)
	require.NoError(t, err)
	return AllowlistEntry{ID: id, Reason: reason, Expires: expires, expires: parsed}
}

func TestCheckFindings(t *testing.T) {
	t.Parallel()

	now, _ := time.Parse(time.DateOnly, "2026-04-01")
	futureDate := "2026-12-31"
	pastDate := "2026-01-01"

	t.Run("vuln not in allowlist", func(t *testing.T) {
		t.Parallel()
		excluded, failed := checkFindings(
			[]string{"GO-2024-0001"},
			map[string]AllowlistEntry{},
			now,
		)
		assert.Empty(t, excluded)
		require.Len(t, failed, 1)
		assert.Equal(t, "GO-2024-0001", failed[0])
	})

	t.Run("vuln in allowlist and not expired", func(t *testing.T) {
		t.Parallel()
		excluded, failed := checkFindings(
			[]string{"GO-2024-0001"},
			map[string]AllowlistEntry{
				"GO-2024-0001": makeEntry(t, "GO-2024-0001", "no fix", futureDate),
			},
			now,
		)
		require.Len(t, excluded, 1)
		assert.Equal(t, "GO-2024-0001", excluded[0])
		assert.Empty(t, failed)
	})

	t.Run("vuln in allowlist but expired", func(t *testing.T) {
		t.Parallel()
		excluded, failed := checkFindings(
			[]string{"GO-2024-0001"},
			map[string]AllowlistEntry{
				"GO-2024-0001": makeEntry(t, "GO-2024-0001", "was no fix", pastDate),
			},
			now,
		)
		assert.Empty(t, excluded)
		require.Len(t, failed, 1)
	})

	t.Run("vuln checked on its expiry date is still excluded", func(t *testing.T) {
		t.Parallel()
		excluded, failed := checkFindings(
			[]string{"GO-2024-0001"},
			map[string]AllowlistEntry{
				"GO-2024-0001": makeEntry(t, "GO-2024-0001", "expires today", "2026-04-01"),
			},
			now,
		)
		require.Len(t, excluded, 1)
		assert.Empty(t, failed)
	})

	t.Run("mixed: one excluded, one failed", func(t *testing.T) {
		t.Parallel()
		excluded, failed := checkFindings(
			[]string{"GO-2024-0001", "GO-2024-0002"},
			map[string]AllowlistEntry{
				"GO-2024-0001": makeEntry(t, "GO-2024-0001", "no fix", futureDate),
			},
			now,
		)
		require.Len(t, excluded, 1)
		assert.Equal(t, "GO-2024-0001", excluded[0])
		require.Len(t, failed, 1)
		assert.Equal(t, "GO-2024-0002", failed[0])
	})

	t.Run("no findings", func(t *testing.T) {
		t.Parallel()
		excluded, failed := checkFindings(nil, nil, now)
		assert.Empty(t, excluded)
		assert.Empty(t, failed)
	})
}
