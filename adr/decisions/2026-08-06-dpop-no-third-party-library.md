---
status: 'proposed'
date: '2026-08-06'
tags:
 - dpop
 - sdk
 - authentication
 - dependencies
---
# Hand-Rolled DPoP Client Support in the Go SDK

## Context and Problem Statement

PR [#3581](https://github.com/opentdf/platform/pull/3581) (DSPX-3397) adds RFC 9449 (DPoP) client support to the Go SDK: roughly 2,800 lines across 20 files, of which about 1,000 are production code and 1,460 are tests. A change of that size invites a reasonable question — is this reimplementing a wheel that an existing Go library already provides?

The question was raised specifically about [`AxisCommunications/go-dpop`](https://github.com/AxisCommunications/go-dpop). This ADR records the evaluation of that library and of the closer-fitting [`conductorone/dpop`](https://github.com/conductorone/dpop), so the decision does not have to be relitigated in review or at every future DPoP change.

One detail frames the whole comparison: OpenTDF's **server-side** DPoP validation already existed on `main` before this PR — `validateDPoP` in `service/internal/auth/authn.go`, the `jti` replay cache in `dpop_replay.go`, and the `dpopNonceManager`. PR #3581 is almost entirely a *client*. Both candidate libraries are validator-first, so they address the half of RFC 9449 this repository had already solved.

## Decision Drivers

* The SDK depends on exactly one JOSE library, `lestrrat-go/jwx/v2`. Adding a second is a real cost in a module consumed by downstream integrators.
* `make lint` runs `govulncheck`; a dependency pinning a vulnerable transitive is a build-breaking problem, not a theoretical one.
* The client must interoperate with our own server, which advertises nine signature algorithms via `dpop_signing_alg_values_supported`.
* The client must handle server-issued nonce challenges (RFC 9449 §8). Our own server can require them (`DPoPConfig.RequireNonce`, default `false`) and issues them via `dpopNonceManager`, and Keycloak issues them independently of that setting.
* Requests are ConnectRPC over HTTP, so any nonce retry has to replay a body that ConnectRPC supplies without `GetBody`.

## Considered Options

* Hand-rolled implementation (the approach taken in PR #3581)
* `AxisCommunications/go-dpop`
* `conductorone/dpop`
* Wait for DPoP support in `golang.org/x/oauth2`

## Decision Outcome

Chosen option: **hand-rolled implementation**, because neither library covers the client-side work this PR actually does. The size of the PR is not duplicated wheel-building; it is nonce lifecycle, RFC 9449 §4.2 URI normalization, and ConnectRPC body replay — none of which are available off the shelf in Go today.

Adopting either library would still require writing the nonce cache and retry, the `htu` normalizer, token-endpoint classification, body buffering, and request cloning, while adding a second JOSE dependency and — in the `conductorone/dpop` case — dropping four signature algorithms our server accepts.

### Consequences

* 🟩 **Good**, because the SDK keeps a single JOSE dependency (`jwx/v2`), shared with `service/`, and the DPoP client and server halves are expressed in the same key type (`jwk.Key`).
* 🟩 **Good**, because the client supports the full ES256/384/512 and RS256/384/512 set rather than the narrower set any candidate library offers.
* 🟩 **Good**, because nonce handling, `htu` normalization, and ConnectRPC body replay are implemented and tested against our actual server behavior rather than adapted around a library's assumptions.
* 🟥 **Bad**, because we own the maintenance and the RFC-conformance burden for approximately 1,000 lines of security-relevant code.
* 🟥 **Bad**, because there are now two client proof builders in the SDK (see Validation), which is a direct consequence of adding the new transport alongside the legacy interceptor.

## Validation

The evaluation surfaced three genuine issues in our own code, tracked as follow-ups to PR #3581 rather than as growth of that PR:

1. **Two divergent proof builders.** `addDPoPProof` in `sdk/auth/dpop_transport.go` and `GetDPoPToken` in `sdk/auth/token_adding_interceptor.go` disagree on `htu` (full normalized URI versus bare ConnectRPC procedure path), on `jti` (UUID versus 14 random bytes), and on failure mode — the legacy path logs and sends the request unproofed rather than erroring. `sdk.go` already skips the interceptor when the DPoP transport is active, so the legacy path should be consolidated or removed.
2. **Two nonce-retry layers.** `sdk/auth/oauth/oauth.go` has its own one-shot `400` + `dpop-nonce` retry, which is live simultaneously with the transport's retry when a token source runs through `DPoPTransport`.
3. **SDK/server algorithm mismatch.** The server accepts and advertises PS256/384/512, which the SDK cannot generate. Either add them to `validDPoPAlgs` or document the client subset as intentional.

Ongoing validation of the implementation itself is the 24 tests in `sdk/auth/dpop_transport_test.go`. The seven nonce tests in particular (`_NonceRetry`, `_NoRetryWhenNonceUnchanged`, `_RetryOnRotatedNonce`, `_CachesNonceFromRetrySuccess`, `_NonceRetryReplaysConnectUnaryBody`, and the two body-replay variants) cover exactly the behavior neither candidate library provides, and are the regression net for any future refactor toward a shared signer.

Cross-language behavior is validated by the `opentdf/tests` xtest harness; `SupportedFeatures()` in `sdk/version.go` advertises `dpop` and `dpop_nonce_challenge` to it.

## Pros and Cons of the Options

### Hand-rolled implementation

* 🟩 **Good**, because it implements the full nonce lifecycle: a per-origin cache, a one-shot retry, and a guard against retry loops when the server returns an unchanged nonce.
* 🟩 **Good**, because `normalizeURI` implements RFC 9449 §4.2 properly — lowercased scheme and host, default ports stripped, `EscapedPath` so `%2F` survives, query and fragment removed.
* 🟩 **Good**, because it distinguishes token-endpoint from resource requests, so the token exchange does not carry a stale `ath`.
* 🟩 **Good**, because `bufferRequestBody` installs `GetBody` for ConnectRPC bodies, making nonce retries transparent.
* 🟩 **Good**, because it falls back to `Bearer` when the token source reports a non-DPoP scheme, rather than forcing DPoP on every caller.
* 🟥 **Bad**, because it is approximately 1,000 lines of security-relevant code we maintain ourselves.

### AxisCommunications/go-dpop

A server-side validator (`Parse`, ~330 lines implementing RFC 9449 §4.3) with a 25-line `Create` bolted on.

* 🟩 **Good**, because `Parse` is a readable and apparently correct implementation of the validation steps — but that is the half we already had.
* 🟥 **Bad**, because `Create` sets no claims for you. It generates no `jti`, no `iat`, and has no `ath` hashing helper ([issue #4](https://github.com/AxisCommunications/go-dpop/issues/4), open since 2023). It would replace roughly 30 lines of PR #3581.
* 🟥 **Bad**, because it builds on `golang-jwt/jwt/v5`, adding a second JOSE library to the SDK plus a `jwk.Key` to `crypto.Signer` adapter at every call site.
* 🟥 **Bad**, because its `go.mod` pins `jwt v5.2.1`, the version affected by [GO-2025-3553 / CVE-2025-30204](https://pkg.go.dev/vuln/GO-2025-3553). Dependabot PRs [#25](https://github.com/AxisCommunications/go-dpop/pull/25) (March 2025) and [#26](https://github.com/AxisCommunications/go-dpop/pull/26) (July 2025) remain unmerged.
* 🟥 **Bad**, because it is effectively unmaintained: last commit 2024-11-21, 16 total commits, 16 stars, one importer on pkg.go.dev. [PR #27](https://github.com/AxisCommunications/go-dpop/pull/27) was closed unmerged in October 2025 with the contributor stating they had decided to fork instead.
* 🟥 **Bad**, because it provides no replay store and no nonce lifecycle, so it would not fully replace our server-side code either.

### conductorone/dpop

The closer fit, and the more serious candidate. Apache-2.0, built on `go-jose/v4`, actively released (core v0.2.7, 2026-06-23).

* 🟩 **Good**, because `pkg/dpop.Proofer` has the pieces Axis lacks: `WithAccessToken` computes `ath`, `WithNonceFunc` supplies a nonce, and there is a JTI replay store with a Redis integration.
* 🟩 **Good**, because it ships an `http.RoundTripper`, gRPC interceptors, and Gin middleware.
* 🟥 **Bad**, because the transport is 21 lines and performs **no nonce handling at all** — it never reads `DPoP-Nonce`, caches nothing, and never retries. This is the single hardest part of PR #3581.
* 🟥 **Bad**, because it sends `req.URL.String()` verbatim as `htu`, including query and fragment, contrary to RFC 9449 §4.2.
* 🟥 **Bad**, because it always sets `ath` and `Authorization`, with no token-endpoint distinction, so a token exchange would carry the previous token's hash.
* 🟥 **Bad**, because it mutates the caller's `*http.Request` in place rather than cloning.
* 🟥 **Bad**, because `NewProofer` supports EdDSA, RS256, and ES256 only — it explicitly rejects P-384 and P-521 (`ErrInvalidECDSACurve`). Adopting it drops ES384, ES512, RS384, and RS512, all of which our server accepts; its one extra algorithm, EdDSA, is not in the server's `allowedSignatureAlgorithms`.
* 🟥 **Bad**, because `integrations/dpop_http` is a separately tagged module stuck at v0.2.4 (2025-03-27) while the core is at v0.2.7 (2026-06-23), and its `go.mod` requires core `v0.0.2` behind a `replace` directive that consumers do not honor.
* 🟥 **Bad**, because adoption is effectively zero (1 star, 0 forks, created February 2025), it is single-vendor, and it is pre-v1 with no API stability guarantee.
* 🟥 **Bad**, because it would add `go-jose/v4` as a second JOSE library in the SDK.

### Wait for golang.org/x/oauth2

* 🟩 **Good**, because if it landed it would be the dependency worth taking: already in our dependency graph, first-party, and stable.
* 🟥 **Bad**, because [golang/oauth2#651](https://github.com/golang/oauth2/issues/651) has been open since July 2023 with four comments and no implementation. Waiting is not an option for a feature we need now.

## More Information

For completeness, the following were also checked and have **zero** DPoP support: `zitadel/oidc` (v3.49.1), `ory/fosite` (v0.49.0), `coreos/go-oidc` (v3), `lestrrat-go/jwx` (v3.2.0), and `go-jose/go-jose` (v4.1.4). The JOSE libraries treat DPoP as out of scope by design — they are what one builds DPoP on top of.

**Revisit this decision if** DPoP support lands in `golang.org/x/oauth2`. That would remove the "second JOSE library" objection entirely and is the one outcome that would change the calculus. Absent that, the maintenance burden of the hand-rolled implementation is the accepted cost.

* [RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession](https://datatracker.ietf.org/doc/html/rfc9449)
* [PR #3581 — feat(sdk): add DPoP client support](https://github.com/opentdf/platform/pull/3581)
