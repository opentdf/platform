package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"sync"
)

// Secret represents a sensitive value. It holds an internal pointer to state
// so copying Secret values does not copy the underlying lock.
type Secret struct{ state *secretState }

type secretState struct {
	mu       sync.Mutex
	value    string
	source   string
	resolved bool
}

var (
    // ErrSecretNotResolved is returned when attempting to access a secret that hasn't been resolved yet.
    ErrSecretNotResolved = errors.New("secret not resolved")
    // ErrSecretMissingEnv indicates the requested env var does not exist.
    ErrSecretMissingEnv = errors.New("secret env var not set")
)

const redactedPlaceholder = "[REDACTED]"

// NewLiteralSecret creates a Secret from a literal value and marks it resolved.
func NewLiteralSecret(v string) Secret {
	return Secret{state: &secretState{value: v, source: "literal", resolved: true}}
}

// NewEnvSecret creates a Secret that will resolve from the given environment variable.
func NewEnvSecret(envName string) Secret {
	return Secret{state: &secretState{source: "env:" + envName}}
}

// NewFileSecret creates a Secret that will resolve from the contents of a file path.
// The value is read as-is; callers can trim/parse if needed.
func NewFileSecret(path string) Secret {
	// Normalize to absolute-ish source marker
	if !strings.HasPrefix(path, "file:") {
		return Secret{state: &secretState{source: "file:" + path}}
	}
	return Secret{state: &secretState{source: path}}
}

// Resolve ensures the secret is materialized and returns its value.
// If the secret references an environment variable, it reads it from the process environment.
func (s Secret) Resolve(ctx context.Context) (string, error) {
	if s.state == nil {
		return "", ErrSecretNotResolved
	}
	st := s.state
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.resolved {
		return st.value, nil
	}

	if st.source == "" {
		return "", ErrSecretNotResolved
	}

	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return "", err
		}
	}

	switch {
	case len(st.source) > 4 && st.source[:4] == "env:":
		envName := st.source[4:]
		if envName == "" {
			return "", errors.New("empty env directive")
		}
		if v, ok := os.LookupEnv(envName); ok {
			st.value = v
			st.resolved = true
			return st.value, nil
		}
		return "", fmt.Errorf("%w: %s", ErrSecretMissingEnv, envName)
	case len(st.source) > 5 && st.source[:5] == "file:":
		path := st.source[5:]
		if path == "" {
			return "", errors.New("empty file directive")
		}
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return "", err
			}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			// Mask file not found vs other errors in public message
			if errors.Is(err, fs.ErrNotExist) {
				return "", fmt.Errorf("secret file not found: %s", path)
			}
			return "", fmt.Errorf("error reading secret file %s: %w", path, err)
		}
		st.value = strings.TrimSpace(string(b))
		st.resolved = true
		return st.value, nil
	case st.source == "literal":
		// Should have been resolved already; treat as not resolved if empty.
		if st.resolved {
			return st.value, nil
		}
		return "", ErrSecretNotResolved
	default:
		// Placeholder for future resolvers (e.g., fromURI)
		return "", fmt.Errorf("unrecognized secret source: %s", st.source)
	}
}

// String implements fmt.Stringer and returns a redacted representation.
func (s Secret) String() string { return redactedPlaceholder }

// LogValue implements slog.LogValuer to prevent accidental secret leakage in logs.
func (s Secret) LogValue() slog.Value {
    if s.state != nil && s.state.source != "" {
        return slog.GroupValue(
            slog.String("value", redactedPlaceholder),
            slog.String("source", s.state.source),
        )
    }
    return slog.StringValue(redactedPlaceholder)
}

// MarshalJSON redacts the value when serialized to JSON.
func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal(redactedPlaceholder) }

// Export returns the raw secret value if resolved, otherwise returns an error.
// Intended for explicit, narrow use when the raw value is required.
func (s Secret) Export() (string, error) {
	if s.state == nil {
		return "", ErrSecretNotResolved
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	if !s.state.resolved {
		return "", ErrSecretNotResolved
	}
	return s.state.value, nil
}

// IsZero reports whether the secret has no value and no source.
func (s Secret) IsZero() bool {
	if s.state == nil {
		return true
	}
	s.state.mu.Lock()
	defer s.state.mu.Unlock()
	return !s.state.resolved && s.state.source == "" && s.state.value == ""
}
