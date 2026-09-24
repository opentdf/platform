---
status: 'proposed'
date: '2026-08-15'
tags:
 - auth
 - dpop
 - kas
 - scalability
driver: '@dmihalcik-virtru'
---
# Pluggable DPoP Replay and Nonce Stores

## Context and Problem Statement

DPoP proof validation keeps two pieces of server-side state, both of which are
per-process and in-memory today:

- **`jti` replay cache** (`service/internal/auth/dpop_replay.go`): a
  mutex-guarded `map[string]time.Time`, TTL set to `DPoPSkew` (default `1h`),
  swept by a scan throttled to once per TTL.
- **Server nonce** (`dpopNonceManager`, `service/internal/auth/authn.go:141`):
  a random 16-byte value generated at process start, rotated lazily on read,
  with the current and previous values accepted.

Neither survives horizontal scaling, which is the deployment style the platform
is actually run in:

1. **Replay protection does not hold across replicas.** An attacker who captures
   a DPoP proof replays it against a different replica, whose cache has never
   seen the `jti`. With `DPoPSkew: 1h` the proof stays usable for an hour. The
   protection the code advertises (RFC 9449 §11.1) is only real for a
   single-process deployment.
2. **`require_nonce: true` is unusable behind a load balancer.** Each replica
   mints its own nonce, so a client that obtains a nonce from replica A and
   lands on replica B gets `use_dpop_nonce`, retries, gets B's nonce, and then
   may land on C. Clients bounce through challenge/retry indefinitely instead of
   converging. This is why `require_nonce` still defaults to `false`
   (`service/internal/auth/config.go:49`) despite the machinery being complete.

We need both stores to be replaceable by deployment-appropriate backends
without forcing a shared-state dependency on every operator, and without adding
a network round trip to the hot path where it can be avoided.

## Decision Drivers

* Correct replay and nonce semantics across N replicas, with no load-balancer
  affinity requirement.
* No new mandatory infrastructure dependency for single-node and dev
  deployments.
* Hot-path latency: rewrap already pays asymmetric crypto plus an authorization
  round trip; DPoP validation must not add a second unavoidable network hop.
* Extensibility by embedders, matching the pattern already established for
  role providers (`service/pkg/authz/role_provider.go`,
  `WithAuthZRoleProviderFactory`).
* Explicit, configurable behavior when a backing store is unavailable — no
  silent downgrade of a security control.

## Considered Options

* **A. Shared cache for both stores.** Put `jti` and the nonce in Redis/Valkey.
  Correct, but makes a shared cache mandatory for anyone enforcing DPoP, and
  puts a network round trip in front of every authenticated request including
  the nonce read.
* **B. Sticky sessions.** Pin clients to replicas at the load balancer. Rejected:
  pushes a security requirement into infrastructure the platform does not
  control, breaks on rescale, and does nothing for replay across a rolling
  deploy.
* **C. Pluggable interfaces, with a stateless nonce as the default answer for
  multi-replica.** Define `ReplayGuard` and `NonceSource` interfaces plus a
  factory registry. Ship an in-memory driver (today's behavior, honest about
  its scope), an HMAC-derived stateless nonce driver that needs no coordination
  at all, and let operators plug a shared store for `jti` when they need
  cross-replica replay protection.

## Decision Outcome

Chosen option: **C**.

The two problems are not symmetric and should not get the same solution:

- **Nonces do not need shared state.** A nonce only has to be recognizable by
  the issuer as recent and self-issued. Deriving it as
  `HMAC(K, time_bucket)` makes every replica holding `K` able to issue and
  validate the same nonce with zero coordination, zero storage, and zero extra
  latency. This eliminates the load-balancer problem outright rather than
  distributing the state.
- **Replay detection genuinely needs a shared decision point** — it is a
  distributed uniqueness claim. That cost is real, so it is opt-in, it is one
  atomic round trip, and the acceptance window shrinks so the store stays small.

### Interfaces

New exported package `service/pkg/auth/dpop`, so out-of-tree deployments can
implement drivers (siblings to `service/pkg/authz`):

```go
// Package dpop defines the pluggable state stores used by DPoP proof validation.
package dpop

// ReplayGuard records single-use DPoP proof identifiers (RFC 9449 §11.1).
type ReplayGuard interface {
	// Observe atomically records id for ttl and reports whether it had already
	// been recorded.
	//
	// Implementations MUST be atomic with respect to every other caller sharing
	// the same backend: of N concurrent Observe calls carrying the same id,
	// exactly one returns seen=false. A read-then-write implementation is not
	// acceptable; the TOCTOU window is precisely the race an attacker replays into.
	//
	// A non-nil error means the guard could not reach a decision. Callers apply
	// the configured on-error policy; they MUST NOT treat an error as seen=false.
	Observe(ctx context.Context, id string, ttl time.Duration) (seen bool, err error)
}

// NonceSource issues and validates server nonces (RFC 9449 §8, §9).
type NonceSource interface {
	// Issue returns the nonce to advertise in a DPoP-Nonce response header.
	Issue(ctx context.Context) (string, error)
	// Validate reports whether nonce is currently acceptable. It returns nil when
	// the nonce is good, ErrNonceStale when the client should retry with a fresh
	// one, and ErrNonceMalformed when the proof is simply invalid.
	Validate(ctx context.Context, nonce string) error
}

var (
	// ErrNonceStale is retryable: the caller answers with a use_dpop_nonce
	// challenge and a fresh DPoP-Nonce header.
	ErrNonceStale = errors.New("dpop nonce expired or unrecognized")
	// ErrNonceMalformed is not retryable: the caller answers with
	// invalid_dpop_proof.
	ErrNonceMalformed = errors.New("dpop nonce malformed")
)

// Factories construct drivers at startup.
type (
	ReplayGuardFactory func(ctx context.Context, cfg ProviderConfig, log *logger.Logger) (ReplayGuard, error)
	NonceSourceFactory func(ctx context.Context, cfg ProviderConfig, log *logger.Logger) (NonceSource, error)
)

// ProviderConfig carries driver-specific settings plus the window the
// authenticator enforces, so drivers can size themselves without duplicating
// configuration.
type ProviderConfig struct {
	Config map[string]any
	Window time.Duration
}
```

`Validate` returning a typed error rather than `bool` is deliberate: it maps
directly onto the existing retryable/non-retryable split
(`DPoPNonceError` vs `DPoPNonceMalformedError`, `authn.go:364-380`), which the
current `validateNonce() bool` collapses and then reconstructs at the call site.

### Built-in drivers

**`ReplayGuard`**

| Driver | Semantics | When to use |
|---|---|---|
| `memory` (default) | Time-bucketed sharded maps; O(1) eviction by dropping whole buckets instead of the current throttled full scan. | Single replica, dev, and deployments that accept per-replica scope. |
| `none` | Always returns `seen=false`. | Explicit, audited opt-out — better than a store that looks like it works and does not. |
| *registered* | Supplied by the embedder via factory. | Redis/Valkey, DynamoDB, any store with a conditional insert. |

A shared driver's `Observe` is one atomic conditional insert, e.g. Redis
`SET dpop:jti:<id> 1 NX PX <ttl>` where a nil reply means "already present".
Note that `service/pkg/cache.Cache` is deliberately **not** used for this: its
`Get`/`Set` pair (`service/pkg/cache/cache.go:95-131`) is not atomic, so a
guard built on it would have exactly the race `Observe` forbids.

Any remote guard is wrapped in a **tiered guard**: consult the local
time-bucketed map first and reject immediately on a local hit, otherwise fall
through to the remote store and record locally. Detected replays then cost zero
network; only first-sight proofs pay the round trip.

**`NonceSource`**

| Driver | Semantics | When to use |
|---|---|---|
| `memory` (default) | Today's per-process random nonce, current + previous accepted. | Single replica, dev. Startup warns when combined with `require: true`. |
| `hmac` | Stateless, derived below. | Any multi-replica deployment. |
| *registered* | Supplied by the embedder. | Shared-store or HSM-backed variants. |

Stateless nonce construction:

```
bucket = floor(unix_seconds / expiration_seconds)
tag    = HMAC-SHA256(K_kid, "opentdf-dpop-nonce/v1" || uint32_be(bucket))
nonce  = base64url( uint32_be(bucket) || kid || tag[0:15] )
```

20 bytes, 27 base64url characters. Validation decodes the bucket and key id,
recomputes the tag, compares in constant time, and accepts
`bucket ∈ {current, current-1}` so a client is never rejected for straddling a
boundary. Key rotation is a newest-first list of secrets keyed by `kid`, so `K`
can be rolled with an overlap window. `K` is required configuration when
`nonce.driver: hmac`; startup fails rather than silently generating a
per-process secret, which would reintroduce the bug this driver exists to fix.

Beyond fixing the load-balancer problem, this delivers the property RFC 9449
§11.1 calls out — "a server managed timestamp via the nonce claim" — so proof
freshness stops depending on client clock accuracy, which is what forces the
`DPoPSkew` window to be generous today.

### Configuration

```yaml
server:
  auth:
    dpop:
      enforce: true
      strict_htu: true
      skew: 1m                 # proof acceptance window; also the replay TTL
      replay:
        driver: memory         # memory | none | <registered name>
        on_error: deny         # deny | allow | local
        config: {}
      nonce:
        require: false
        driver: memory         # memory | hmac | <registered name>
        expiration: 5m
        config:
          secrets:             # hmac driver
            - kid: "1"
              secret_ref: env:DPOP_NONCE_SECRET
```

`on_error` governs a guard that returns an error, and is a genuine
availability/security trade rather than something to pick a default for
silently:

- `deny` (default) — fail closed. A store outage stops rewraps.
- `local` — degrade to the in-memory guard, emit an audit event and a metric.
  Recommended for deployments that cannot trade availability for this control.
- `allow` — skip the check, emit an audit event and a metric.

Factories are injected exactly like role providers: `mapstructure:"-"` fields on
`auth.Config`, populated from new `WithDPoPReplayGuardFactory(name, factory)` and
`WithDPoPNonceSourceFactory(name, factory)` start options
(`service/pkg/server/options.go:162` is the model), and resolved in
`NewAuthenticator` by `resolveReplayGuard`/`resolveNonceSource` mirroring
`resolveRoleProvider` (`service/internal/auth/authn.go:323`).

### Validation ordering

`validateDPoP` keeps checking `jti` **last**, after signature verification
(`service/internal/auth/authn.go:1304-1317`). It is tempting to start the
`Observe` round trip early and join later to hide its latency behind signature
verification, but that would let unauthenticated garbage proofs write into a
shared store — a cheap remote-fill DoS. Signature verification is well under a
millisecond; the ordering property is worth more than the overlap.

### Observability

Every driver reports through the existing OTel pipeline:

- `dpop.replay.observe.duration` (histogram, tagged by driver and outcome)
- `dpop.replay.rejected` (counter)
- `dpop.replay.store_error` (counter, tagged by applied `on_error` policy)
- `dpop.nonce.challenge_issued` / `dpop.nonce.rejected` (counters)

`dpop.replay.store_error` with `on_error: local|allow` is the signal that a
security control is silently degraded, and should be alerted on.

## Consequences

* Good: `require_nonce: true` becomes deployable at scale with no shared state
  and no extra latency.
* Good: cross-replica replay protection becomes available to operators who want
  it, without imposing a dependency on those who do not.
* Good: the default configuration's actual guarantee (per-replica) becomes
  explicit at startup instead of implied by code comments.
* Good: replaces a throttled full-map scan with O(1) bucket eviction.
* Bad: three more configuration knobs, and a security control whose strength now
  varies by deployment — mitigated by startup warnings and the metrics above.
* Bad: a shared replay driver adds one round trip to first-sight proofs, and its
  outage becomes a rewrap-availability event under the default `deny` policy.

## Migration

1. Land interfaces, drivers, and config with `memory` defaults — no behavior
   change.
2. Warn at startup when `enforce: true` and `replay.driver: memory`, stating
   that replay protection is per-replica.
3. Shrink `skew` from `1h` to `1m` (tracked separately; see
   `docs/dpop-rewrap-hardening.md`), which shrinks replay state proportionally
   and makes a shared store cheap.
4. Document `nonce.driver: hmac` as the required setting for multi-replica
   deployments that enable `require: true`.
