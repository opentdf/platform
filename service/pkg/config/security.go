package config

import (
	"time"
)

const (
	// DefaultUnsafeClockSkew is the default tolerated clock skew used when an unsafe override is not provided.
	DefaultUnsafeClockSkew = time.Minute
)

// SecurityConfig collects platform-wide security toggles and overrides.
type SecurityConfig struct {
	Unsafe UnsafeSecurityConfig `mapstructure:"unsafe" json:"unsafe"`
}

// UnsafeSecurityConfig exposes overrides that may weaken standard security guarantees.
type UnsafeSecurityConfig struct {
	// ClockSkew increases the tolerated clock skew for token validation. Defaults to 1 minute.
	ClockSkew time.Duration `mapstructure:"clock_skew" json:"clock_skew"`
}

// ClockSkew returns the configured clock skew, defaulting to DefaultUnsafeClockSkew when unset.
func (s *SecurityConfig) ClockSkew() time.Duration {
	if s == nil {
		return DefaultUnsafeClockSkew
	}
	if s.Unsafe.ClockSkew <= 0 {
		return DefaultUnsafeClockSkew
	}
	return s.Unsafe.ClockSkew
}
