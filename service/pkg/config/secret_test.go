package config

import (
	"encoding/json"
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecret_Literal(t *testing.T) {
	s := NewLiteralSecret("super-secret")
	assert.Equal(t, "[REDACTED]", s.String())
	got, err := s.Resolve(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "super-secret", got)
	raw, err := s.Export()
	require.NoError(t, err)
	assert.Equal(t, "super-secret", raw)
}

func TestSecret_FromEnv(t *testing.T) {
	const env = "OPENTDF_TEST_SECRET"
	t.Setenv(env, "env-secret")

	s := NewEnvSecret(env)
	assert.Equal(t, "[REDACTED]", s.String())
	got, err := s.Resolve(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "env-secret", got)
}

func TestSecret_FromFile_Trim(t *testing.T) {
	dir := t.TempDir()
	p := dir + "/s.txt"
	// Include trailing newline to simulate typical secret mounts
	require.NoError(t, os.WriteFile(p, []byte("abc\n"), 0o600))
	s := NewFileSecret(p)
	got, err := s.Resolve(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "abc", got, "expected trimmed value")
}

func TestSecret_JSONRedacted(t *testing.T) {
	s := NewLiteralSecret("dont-log-me")
	b, err := json.Marshal(s)
	require.NoError(t, err)
	assert.Equal(t, "\"[REDACTED]\"", string(b))
}

func TestSecret_Resolve_Concurrent(t *testing.T) {
	t.Setenv("OPENTDF_CONCUR", "concur")
	s := NewEnvSecret("OPENTDF_CONCUR")

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	errs := make(chan error, n)
	vals := make(chan string, n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			v, err := s.Resolve(t.Context())
			if err != nil {
				errs <- err
				return
			}
			vals <- v
		}()
	}
	wg.Wait()
	close(errs)
	close(vals)
	require.Empty(t, errs, "expected no resolve errors")
	for v := range vals {
		assert.Equal(t, "concur", v)
	}
}
