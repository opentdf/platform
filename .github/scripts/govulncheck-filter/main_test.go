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
				Trace: []Frame{{Module: "example.com/mod", Package: "example.com/mod/pkg"}},
			},
			called: false,
		},
		{
			name: "symbol-level (has function)",
			f: &Finding{
				OSV:   "GO-2024-0001",
				Trace: []Frame{{Module: "example.com/mod", Package: "example.com/mod/pkg", Function: "DoSomething"}},
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
}

func TestParseGovulncheckJSON(t *testing.T) {
	t.Parallel()

	t.Run("pretty-printed JSON with mixed message types", func(t *testing.T) {
		t.Parallel()
		// Simulate govulncheck's actual pretty-printed output format.
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

		osvMap, calledIDs, err := parseGovulncheckJSON(path)
		require.NoError(t, err)

		// Should have both OSV entries.
		require.Len(t, osvMap, 2)
		assert.Equal(t, "Vuln one", osvMap["GO-2024-0001"])

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

		_, calledIDs, err := parseGovulncheckJSON(path)
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

		_, calledIDs, err := parseGovulncheckJSON(path)
		require.NoError(t, err)
		require.Len(t, calledIDs, 1)
	})
}

func TestCheckFindings(t *testing.T) {
	t.Parallel()

	now, _ := time.Parse(time.DateOnly, "2026-04-01")
	futureDate := "2026-12-31"
	pastDate := "2026-01-01"

	t.Run("vuln not in allowlist", func(t *testing.T) {
		t.Parallel()
		results := checkFindings(
			[]string{"GO-2024-0001"},
			map[string]string{"GO-2024-0001": "Bad thing"},
			map[string]AllowlistEntry{},
			now,
		)
		require.Len(t, results, 1)
		assert.Equal(t, "failed", results[0].status)
	})

	t.Run("vuln in allowlist and not expired", func(t *testing.T) {
		t.Parallel()
		results := checkFindings(
			[]string{"GO-2024-0001"},
			map[string]string{"GO-2024-0001": "Bad thing"},
			map[string]AllowlistEntry{
				"GO-2024-0001": {ID: "GO-2024-0001", Reason: "no fix", Expires: futureDate},
			},
			now,
		)
		require.Len(t, results, 1)
		assert.Equal(t, "excluded", results[0].status)
	})

	t.Run("vuln in allowlist but expired", func(t *testing.T) {
		t.Parallel()
		results := checkFindings(
			[]string{"GO-2024-0001"},
			map[string]string{"GO-2024-0001": "Bad thing"},
			map[string]AllowlistEntry{
				"GO-2024-0001": {ID: "GO-2024-0001", Reason: "was no fix", Expires: pastDate},
			},
			now,
		)
		require.Len(t, results, 1)
		assert.Equal(t, "expired", results[0].status)
	})

	t.Run("vuln checked on its expiry date is still excluded", func(t *testing.T) {
		t.Parallel()
		// now is 2026-04-01, expires is also 2026-04-01 — should still be valid.
		results := checkFindings(
			[]string{"GO-2024-0001"},
			map[string]string{"GO-2024-0001": "Bad thing"},
			map[string]AllowlistEntry{
				"GO-2024-0001": {ID: "GO-2024-0001", Reason: "expires today", Expires: "2026-04-01"},
			},
			now,
		)
		require.Len(t, results, 1)
		assert.Equal(t, "excluded", results[0].status)
	})

	t.Run("mixed: one excluded, one failed", func(t *testing.T) {
		t.Parallel()
		results := checkFindings(
			[]string{"GO-2024-0001", "GO-2024-0002"},
			map[string]string{"GO-2024-0001": "Vuln one", "GO-2024-0002": "Vuln two"},
			map[string]AllowlistEntry{
				"GO-2024-0001": {ID: "GO-2024-0001", Reason: "no fix", Expires: futureDate},
			},
			now,
		)
		require.Len(t, results, 2)
		assert.Equal(t, "excluded", results[0].status)
		assert.Equal(t, "failed", results[1].status)
	})

	t.Run("no findings", func(t *testing.T) {
		t.Parallel()
		results := checkFindings(nil, nil, nil, now)
		assert.Empty(t, results)
	})
}

func TestPrintReport(t *testing.T) {
	t.Parallel()

	t.Run("returns 0 when no results", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 0, printReport(nil))
	})

	t.Run("returns 0 when all excluded", func(t *testing.T) {
		t.Parallel()
		code := printReport([]result{
			{id: "GO-2024-0001", status: "excluded", reason: "no fix", expires: "2099-12-31"},
		})
		assert.Equal(t, 0, code)
	})

	t.Run("returns 1 when any failed", func(t *testing.T) {
		t.Parallel()
		code := printReport([]result{
			{id: "GO-2024-0001", status: "excluded", reason: "no fix", expires: "2099-12-31"},
			{id: "GO-2024-0002", status: "failed", summary: "Bad vuln"},
		})
		assert.Equal(t, 1, code)
	})

	t.Run("returns 1 when expired", func(t *testing.T) {
		t.Parallel()
		code := printReport([]result{
			{id: "GO-2024-0001", status: "expired", summary: "Old vuln", expires: "2025-01-01"},
		})
		assert.Equal(t, 1, code)
	})
}
