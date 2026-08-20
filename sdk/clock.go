package sdk

import "time"

// Clock supplies the current time to the chunked Writer and, through
// it, to the zipstream layer that stamps ZIP header timestamps.
// Injected so tests can pin timestamps and produce byte-for-byte
// deterministic TDF output.
type Clock interface {
	// Now returns the current wall-clock time.
	Now() time.Time
}

// SystemClock returns time.Now(). Production default.
type SystemClock struct{}

// Now returns the current wall-clock time.
func (SystemClock) Now() time.Time { return time.Now() }

// FixedClock returns the same time on every call. Test helper for
// deterministic ZIP output.
type FixedClock struct {
	// T is the wall-clock time to return from Now.
	T time.Time
}

// Now returns the pinned time.
func (c FixedClock) Now() time.Time { return c.T }
