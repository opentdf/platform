package sdk

import "time"

// Clock supplies the current time to the chunked Writer.
// Injected so tests can pin timestamps embedded in manifests,
// assertions, and JWTs without patching global state.
type Clock interface {
	// Now returns the current wall-clock time.
	Now() time.Time
}

// SystemClock returns time.Now(). Production default.
type SystemClock struct{}

// Now returns the current wall-clock time.
func (SystemClock) Now() time.Time { return time.Now() }

// FixedClock returns the same time on every call. Test helper.
type FixedClock struct {
	// T is the wall-clock time to return from Now.
	T time.Time
}

// Now returns the pinned time.
func (c FixedClock) Now() time.Time { return c.T }
