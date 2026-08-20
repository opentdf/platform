# DPoP and Rewrap Hardening

Findings and proposed fixes from an audit of how DPoP interacts with the rewrap
protocol, covering both the implementation (`service/internal/auth`,
`service/kas/access`, `sdk/`) and the BaseTDF specification suite
(`spec/basetdf/`, v4.4 and v5).

Pluggable replay/nonce stores are designed separately in
[ADR: Pluggable DPoP Replay and Nonce Stores](../adr/decisions/2026-08-15-pluggable-dpop-replay-and-nonce-stores.md);
this document covers everything else.

## Background: the three-signature stack

A rewrap request carries three signed artifacts, two of them signed by the same
client key:

| # | Artifact | Signer | Claims | Verified at |
|---|---|---|---|---|
| 1 | Access token | IdP | `cnf.jkt` = SHA-256 thumbprint of the client DPoP key | `service/internal/auth/token_verifier.go` |
| 2 | DPoP proof (`DPoP:` header) | Client DPoP key | `typ`, `jwk`, `jti`, `htm`, `htu`, `iat`, `ath`, `nonce?` | `service/internal/auth/authn.go:1163` |
| 3 | SRT (`signedRequestToken`) | Same DPoP key | `requestBody`, `iat`, `exp` | `service/kas/access/rewrap.go:373` |

The two layers are joined only through request context: the authenticator stores
the verified DPoP JWK (`authn.go:1159`) and the KAS retrieves it to verify the
SRT (`rewrap.go:381`, `:403`).

Artifact 2 already provides everything RFC 9449 promises. Artifact 3 contributes
exactly one non-redundant property: integrity of the request body, which
RFC 9449 §11.7 explicitly declines to cover. Everything else about the SRT is a
duplicate signature, a duplicate temporal window with its own skew setting, and
a second serialization of the request body.

## Implementation fixes

### P0-1 — The SRT is unverified in the default configuration

`DPoP.Enforce` defaults to `false` (`service/internal/auth/config.go:48`). When
the access token has no `cnf` claim, `checkToken` returns before `validateDPoP`
(`authn.go:1140`), so no JWK reaches the context, so `requireVerification` is
false and `verifySRTSignature` never runs (`rewrap.go:384-406`). In the default
posture the SRT is parsed and trusted, providing no integrity at all.

**Fix:** default `server.auth.dpop.enforce` to `true`. For deployments that must
run without DPoP, keep the request working but record the fact — see P1-4.

### P0-2 — Proof acceptance window is one hour

`DPoPSkew` defaults to `1h` (`config.go:34`) and gates the `iat` freshness check
(`authn.go:1242`). It also sets the replay cache TTL (`authn.go:205-208`), so a
captured proof is usable for an hour and the cache retains an hour of `jti`
values. The future-dated direction is fine: `jwt.Parse` validates by default and
a `+2h` `iat` is rejected (`authn_test.go:1062`).

**Fix:** default to `1m`, matching `TokenSkew` and
`config.DefaultUnsafeClockSkew`. With the `hmac` nonce driver from the ADR,
freshness no longer depends on client clocks, so a tight window is safe.

### P0-3 — The client rewrap key is not ephemeral

Both specs argue that rewrap replay is harmless because the response is
encrypted to a per-request ephemeral key (`basetdf-kas.md` §11.5,
`basetdf-sec.md:344`). The Go SDK generates **one** RSA-2048 `kasSessionKey` per
SDK instance and reuses it for the process lifetime (`sdk/sdk.go:140-145`,
`sdk/options.go:50`). A replayed rewrap is therefore decryptable by anyone
holding that long-lived key, and there is no forward secrecy across requests.

**Fix:** generate the rewrap recipient key per request (or per decrypt
operation), and default it to EC P-256 rather than RSA-2048 — smaller, faster,
and the algorithm path the spec recommends. Verify the Java and JS SDKs for the
same pattern before relying on the spec claim.

### P1-1 — DPoP-bound tokens are accepted under the `Bearer` scheme

RFC 9449 §7.1 requires a `cnf`-bearing token to be presented as
`Authorization: DPoP`. The code detects the violation and only warns
(`authn.go:1133-1139`).

**Fix:** promote to a hard rejection behind a config flag, default it on one
release later. The warning has been in place long enough to identify
non-compliant SDKs; check xtest results for java/js before flipping.

### P1-2 — The SRT is not audience-bound

The SRT carries only `requestBody`, `iat`, and `exp`
(`sdk/kas_client.go:347-355`) — no `aud`, `htu`, `jti`, or `ath`. With DPoP
enforced, the proof's `htu` prevents cross-KAS replay. With DPoP off, nothing
does: in a split-key TDF, a malicious KAS-A can forward the client's bearer
token and SRT verbatim to KAS-B. The forwarded request yields a key wrapped to
the original client's public key, so KAS-A learns nothing, but it is an
unattributed access against KAS-B's policy and audit log.

**Fix:** add `aud` (the KAS URL) to the SRT and require the KAS to check it.
Superseded by P2-1 if that lands first.

### P1-3 — No rate limiting on rewrap

`basetdf-kas.md` §7 says the KAS SHOULD rate limit per entity; there is no rate
limiting anywhere in `service/kas`. Replay protection and rate limiting solve
different halves of the same abuse problem — a valid credential can still probe
the KAS as a chosen-policy oracle with fresh, non-replayed proofs.

**Fix:** per-entity (`sub` + `cnf.jkt`) token bucket on `/kas.AccessService/Rewrap`,
returning 429 with `Retry-After`. Shares the same pluggable-store problem as the
replay guard, so it should reuse that driver registry.

### P1-4 — Audit records do not identify the proving key or the binding mode

`RewrapAuditEventParams` (`service/logger/audit/rewrap.go:22-29`) records policy,
algorithm, key id, and policy binding, but not the DPoP key thumbprint and not
whether the request was DPoP-bound at all. Neither does the spec's required
field list (`basetdf-kas.md` §6.2). Without the thumbprint there is no way to
correlate abuse to a key, and no way to tell a bound request from an unbound one
after the fact.

**Fix:** add `dpopJkt` (thumbprint, already computable — see
`jwkThumbprintAttr`, `rewrap.go:143`) and `dpopBound` (bool) to the event
metadata, and to the spec's minimum field list.

### P2-1 — Fold the body binding into the DPoP proof and retire the SRT

RFC 9449 §4.2 permits additional claims, and §11.7 explicitly endorses this use:
*"additional information to be signed can be added into DPoP proofs."* Two
variants, in increasing order of coverage:

- **`cpk_jkt`** — thumbprint of the client's ephemeral rewrap key. Fixed size,
  no canonicalization concerns, and it states the actual invariant: the holder
  of the auth key is also the intended recipient of the DEK. A MITM can still
  substitute KAOs (denial, audit noise) but cannot redirect key material.
- **`rbh`** — base64url(SHA-256(request body)), covering the whole body. Stronger,
  but requires hashing the exact bytes received, because protobuf serialization
  is not canonical across language implementations. Practical approach: keep the
  body as an opaque JSON string field (which is what the `requestBody` claim
  already is) and hash that string, sidestepping canonicalization entirely.

Either way the request loses a signature, a duplicate temporal window, and a
~1.4× re-encoding of the body. Do not put the body itself in the proof — it is
an HTTP header and bulk rewrap would exceed the usual 8–16 KB limits.

The standards-track spelling of this is `Content-Digest` (RFC 9530) with
RFC 9421 HTTP Message Signatures; neither is vendored in the local reference
library, so confirm the details against the RFCs before writing spec text.

### P2-2 — Do not reuse the DPoP key as the rewrap recipient key

Recorded because it is the obvious-looking simplification and it is wrong: RSA
signing keys must not double as RSA-OAEP keys; browser WebCrypto DPoP keys are
created with `key_ops: ["sign"]` and cannot perform ECDH; and DPoP keys are
session-lifetime, which would destroy the per-request property P0-3 restores.
Bind the ephemeral key to the DPoP key (P2-1), do not merge them.

### P2-3 — Minor cleanups

- `verifySRTSignature` reads `alg` from the SRT header and only checks it against
  an allowlist (`rewrap.go:277-299`). A mismatch against the DPoP key type fails
  verification, so this is not exploitable, but constraining `alg` to the key's
  family is cheap defense in depth.
- The `X-Virtrupubkey` legacy header is logged and otherwise unused
  (`rewrap.go:376-378`). Remove it or document why it is retained.
- `getCurrentNonce()` mutates state on a read path (`authn.go:178-193`). Resolved
  by the `hmac` driver in the ADR.
- The replay cache sweep is a throttled full scan (`dpop_replay.go:45-55`).
  Resolved by time-bucketed eviction in the ADR.

## Specification changes

Applies to `spec/basetdf/basetdf-kas.md` and `basetdf-sec.md`; the v4.4 and v5
authentication sections are currently byte-identical, so both need the edit.

### S-1 — §4 understates what the implementation does

`basetdf-kas.md` §4.2 lists three verification steps (extract DPoP key, verify
SRT signature, validate SRT temporal claims). It says nothing about `jti` replay
rejection, the proof acceptance window, `htm`/`htu` binding, `ath`, or server
nonces — all of which the platform implements. An independent implementation
following the spec literally would be materially weaker.

**Fix:** add a subsection enumerating proof checks by reference to RFC 9449 §4.3,
marking `jti` replay detection RECOMMENDED and nonce support OPTIONAL, and
stating the acceptance window as a bounded, configurable value.

### S-2 — §11.5 and `basetdf-sec.md:344` rest on a property no SDK provides

Both make the replay argument from a per-request ephemeral client key. See P0-3.

**Fix:** state the ephemerality requirement normatively — the client MUST
generate a fresh key pair per rewrap request — or weaken the replay claim to
match reality. The first is preferable; the second is dishonest about the
residual risk.

### S-3 — §4.3 should say plainly that non-DPoP mode has no body integrity

The current text ("the KAS MUST still verify the SRT structure and extract the
request body") reads as though something is verified. Without a DPoP key there
is nothing to verify the signature against.

**Fix:** state that in non-DPoP deployments the SRT signature is unverifiable and
the request body has only TLS-level integrity, and that the deployment therefore
does not satisfy SI-4.

### S-4 — SI-4 should require audience binding

Add to `basetdf-sec.md` SI-4: the SRT (or its successor claim) MUST be bound to
the specific KAS, so a request captured by one KAS cannot be presented to
another. See P1-2.

### S-5 — Add a deployment-considerations section

Neither document acknowledges that replay and nonce state are per-instance in a
scaled deployment. Add to `basetdf-kas.md` §11: implementations that detect
replay MUST either share that state across instances or derive it statelessly,
and MUST document which guarantee they provide.

### S-6 — §6.2 audit fields

Add the DPoP key thumbprint and a DPoP-bound indicator to the minimum audit
field list. See P1-4.

### S-7 — Pin hash agility

`jkt` and `ath` are SHA-256 throughout. RFC 9449 §11.10 raises hash agility as a
future concern. Pin SHA-256 explicitly in the spec rather than leaving it
implied, so a future change is a versioned decision rather than a silent
divergence.

### S-8 — Document the v5 direction for the SRT

If P2-1 is accepted, `spec/basetdf/v5/basetdf-kas.md` §3.2 and §4 should describe
the DPoP-proof claim as the primary mechanism with the SRT retained for
backward compatibility, and the terminology table entry for SRT marked
deprecated.

## Cross-SDK validation

Every item touching the wire format needs xtest coverage before it ships,
because the java and js SDKs build their own proofs and SRTs:

- P0-1 (`enforce: true` by default) — confirm all three SDKs send proofs on the
  rewrap path, not just the token endpoint.
- P0-3 (ephemeral recipient key) — verify per-SDK; the property is claimed
  normatively but implemented per-SDK.
- P1-1 (`Bearer` rejection) — this is the item most likely to break a client.
- P2-1 (new proof claim) — needs a negotiated rollout: KAS accepts either form
  until all SDKs emit the new claim.

Run with the branch under test wired into each `*-ref` input, and confirm
`test_dpop.py` actually ran rather than being skipped (see `AGENTS.md`).
