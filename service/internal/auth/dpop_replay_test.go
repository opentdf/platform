package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDPoPReplayCache_FirstUseThenReplay(t *testing.T) {
	c := newDPoPReplayCache(time.Hour)
	now := time.Now()

	require.False(t, c.observe("jti-1", now), "first use of a jti is not a replay")
	require.True(t, c.observe("jti-1", now), "second use of the same jti within the window is a replay")
	require.False(t, c.observe("jti-2", now), "a different jti is not a replay")
}

func TestDPoPReplayCache_ExpiredEntryIsReusable(t *testing.T) {
	ttl := time.Minute
	c := newDPoPReplayCache(ttl)
	now := time.Now()

	require.False(t, c.observe("jti", now))
	// After the TTL elapses the proof would already be rejected by the iat check,
	// so the jti is allowed to be re-recorded rather than reported as a replay.
	require.False(t, c.observe("jti", now.Add(ttl+time.Second)), "entry past its TTL should not count as a replay")
}

func TestDPoPReplayCache_GCPrunesExpiredEntries(t *testing.T) {
	ttl := time.Minute
	c := newDPoPReplayCache(ttl)
	now := time.Now()

	for _, jti := range []string{"a", "b", "c"} {
		require.False(t, c.observe(jti, now))
	}
	assert.Len(t, c.seen, 3)

	// A later observe past the GC interval prunes the expired entries, leaving
	// only the freshly recorded one.
	require.False(t, c.observe("d", now.Add(ttl+time.Second)))
	assert.Len(t, c.seen, 1, "expired entries should be pruned, leaving only the new jti")
}

func TestDPoPReplayCache_ZeroTTLDoesNotPanic(t *testing.T) {
	c := newDPoPReplayCache(0)
	now := time.Now()
	// With a non-positive TTL entries expire immediately, so nothing is ever a replay.
	require.False(t, c.observe("jti", now))
	require.False(t, c.observe("jti", now))
}
