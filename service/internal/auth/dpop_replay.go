package auth

import (
	"sync"
	"time"
)

// dpopReplayCache rejects replayed DPoP proofs by their `jti` value within the
// acceptance window, per RFC 9449 §11.1. Entries expire after ttl (set to the
// DPoP `iat` skew): a proof older than that window is already rejected by the
// `iat` freshness check, so the `jti` need not be remembered any longer.
type dpopReplayCache struct {
	mu     sync.Mutex
	seen   map[string]time.Time // jti -> expiry
	ttl    time.Duration
	lastGC time.Time
}

func newDPoPReplayCache(ttl time.Duration) *dpopReplayCache {
	return &dpopReplayCache{
		seen: make(map[string]time.Time),
		ttl:  ttl,
	}
}

// observe records jti and reports whether it is a replay (already seen and not
// yet expired). The first time a jti is seen it returns false and is remembered
// until now+ttl; any subsequent call within that window returns true.
func (c *dpopReplayCache) observe(jti string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.gc(now)

	if expiry, ok := c.seen[jti]; ok && expiry.After(now) {
		return true
	}
	c.seen[jti] = now.Add(c.ttl)
	return false
}

// gc prunes expired entries to keep the map bounded. It is throttled to run at
// most once per ttl so the common (cache-hot) path stays O(1). Callers must hold
// c.mu.
func (c *dpopReplayCache) gc(now time.Time) {
	if c.ttl <= 0 || now.Sub(c.lastGC) < c.ttl {
		return
	}
	for jti, expiry := range c.seen {
		if !expiry.After(now) {
			delete(c.seen, jti)
		}
	}
	c.lastGC = now
}
