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
)

// Secret represents a sensitive value that should not be logged or marshaled plainly.
// It can be provided literally or by reference (e.g., environment variable).
type Secret struct {
	// value holds the resolved secret when available.
	value string

	// source is a human-readable origin for the secret (e.g., "literal", "env:OPENTDF_FOO").
	source string

	// resolved indicates whether value has been materialized.
	resolved bool
}

var (
	// ErrSecretNotResolved is returned when attempting to access a secret that hasn't been resolved yet.
	ErrSecretNotResolved = errors.New("secret not resolved")
	// ErrSecretMissingEnv indicates the requested env var does not exist.
	ErrSecretMissingEnv = errors.New("secret env var not set")
)

// NewLiteralSecret creates a Secret from a literal value and marks it resolved.
func NewLiteralSecret(v string) Secret {
	return Secret{value: v, source: "literal", resolved: true}
}

// NewEnvSecret creates a Secret that will resolve from the given environment variable.
func NewEnvSecret(envName string) Secret {
	return Secret{source: "env:" + envName}
}

// NewFileSecret creates a Secret that will resolve from the contents of a file path.
// The value is read as-is; callers can trim/parse if needed.
func NewFileSecret(path string) Secret {
	// Normalize to absolute-ish source marker
	if !strings.HasPrefix(path, "file:") {
		return Secret{source: "file:" + path}
	}
	return Secret{source: path}
}

// Resolve ensures the secret is materialized and returns its value.
// If the secret references an environment variable, it reads it from the process environment.
func (s *Secret) Resolve(_ context.Context) (string, error) {
	if s.resolved {
		return s.value, nil
	}

	// Resolve based on source scheme
	// If no source is set, the secret is unset/optional and not resolved
	if s.source == "" {
		return "", ErrSecretNotResolved
	}

	switch {
	case len(s.source) > 4 && s.source[:4] == "env:":
		envName := s.source[4:]
		if v, ok := os.LookupEnv(envName); ok {
			s.value = v
			s.resolved = true
			return s.value, nil
		}
		return "", fmt.Errorf("%w: %s", ErrSecretMissingEnv, envName)
	case len(s.source) > 5 && s.source[:5] == "file:":
		path := s.source[5:]
		b, err := os.ReadFile(path)
		if err != nil {
			// Mask file not found vs other errors in public message
			if errors.Is(err, fs.ErrNotExist) {
				return "", fmt.Errorf("secret file not found: %s", path)
			}
			return "", fmt.Errorf("error reading secret file: %w", err)
		}
		s.value = string(b)
		s.resolved = true
		return s.value, nil
	case s.source == "literal":
		// Should have been resolved already; treat as not resolved if empty.
		if s.resolved {
			return s.value, nil
		}
		return "", ErrSecretNotResolved
	default:
		// Placeholder for future resolvers (e.g., fromURI)
		return "", fmt.Errorf("unrecognized secret source: %s", s.source)
	}
}

// String implements fmt.Stringer and returns a redacted representation.
func (s Secret) String() string { return "[REDACTED]" }

// LogValue implements slog.LogValuer to prevent accidental secret leakage in logs.
func (s Secret) LogValue() slog.Value {
	if s.source != "" {
		return slog.GroupValue(
			slog.String("value", "[REDACTED]"),
			slog.String("source", s.source),
		)
	}
	return slog.StringValue("[REDACTED]")
}

// MarshalJSON redacts the value when serialized to JSON.
func (s Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal("[REDACTED]")
}

// Export returns the raw secret value if resolved, otherwise returns an error.
// Intended for explicit, narrow use when the raw value is required.
func (s Secret) Export() (string, error) {
	if !s.resolved {
		return "", ErrSecretNotResolved
	}
	return s.value, nil
}

// IsZero reports whether the secret has no value and no source.
func (s Secret) IsZero() bool { return !s.resolved && s.source == "" && s.value == "" }
