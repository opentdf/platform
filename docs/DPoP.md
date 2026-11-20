# DPoP Capability Discovery

OpenTDF accepts DPoP ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) proofs bound to access tokens. Older platform releases accept only a legacy proof format, so a client has to learn what a server accepts before it builds a proof. The platform publishes this in its well-known configuration. SDK authors and test authors should read it as described here.

## Fetch the configuration without credentials

Read the configuration from either public route:

- HTTP: `GET <platform>/.well-known/opentdf-configuration`
- Connect/gRPC: `wellknownconfiguration.WellKnownService/GetWellKnownConfiguration`

Both routes are public in every release. Send the request **without** an `Authorization` or `DPoP` header, and do not reuse the authenticated SDK connection for it. A client cannot authenticate in a DPoP format it has not chosen yet: an older server rejects a compliant proof before the request reaches the discovery handler.

## Detection order

1. If the `dpop` object is present, use it (see [The `dpop` object](#the-dpop-object)).
2. Otherwise, if the top-level `dpop_signing_alg_values_supported` key is present, the server accepts RFC 9449 proofs: a full-URL `htu` and the `DPoP` authorization scheme. Every release since `service/v0.18.0` publishes this key.
3. Otherwise, assume the server accepts only legacy proofs, where `htu` is the bare request path.

The top-level `dpop_signing_alg_values_supported` and `dpop_nonce_required` keys are stable. They keep their meaning and values alongside the `dpop` object.

## The `dpop` object

Every field follows one rule: **a key's presence means the server implements that behavior, and its value is the setting the server enforces.** A server leaves out a key for behavior it does not implement. It never publishes a default it does not enforce. Values are the effective settings after deprecated aliases are resolved.

Treat a missing key as "unknown", not as `false`. Ignore keys you do not recognize.

| Field | Type | Meaning |
| --- | --- | --- |
| `rfc9449` | bool | Accepts compliant proofs: a full-URL `htu`, the `DPoP` scheme, and `DPoP-Nonce` challenges. |
| `signing_alg_values_supported` | string[] | JWS algorithms accepted for proofs. Same value as `dpop_signing_alg_values_supported`. |
| `nonce_required` | bool | Every proof must carry a server-issued nonce. Same value as `dpop_nonce_required`. |
| `path_only_htu_accepted` | bool | `true`: a proof whose `htu` is only a path is accepted when the path matches. `false`: `htu` must be a full URL (`server.auth.dpop.htu.strict`). |
| `bearer_scheme_accepted` | bool | `true`: a DPoP-bound token sent under the `Bearer` scheme is accepted with a warning. `false`: it is rejected with a 401 and `invalid_token`. Not published yet. Published when the scheme becomes configurable (DSPX-3573). |
| `htu_origins` | string[] | Normalized public origins that a full-URL `htu` must use. `[]` means the expected origin comes from the request. Lists only operator-configured origins (`server.auth.dpop.htu.origins`), never the request's `Host` or `Origin`. |
| `legacy_accepted` | bool | The server accepts some legacy proof form: `bearer_scheme_accepted \|\| path_only_htu_accepted`. Servers that do not publish `bearer_scheme_accepted` accept the `Bearer` scheme, so this is `true` for them. |

For example, a server with nonces required and default `htu` matching publishes:

```json
{
  "dpop_signing_alg_values_supported": ["ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512"],
  "dpop_nonce_required": true,
  "dpop": {
    "rfc9449": true,
    "signing_alg_values_supported": ["ES256", "ES384", "ES512", "PS256", "PS384", "PS512", "RS256", "RS384", "RS512"],
    "nonce_required": true,
    "path_only_htu_accepted": true,
    "htu_origins": [],
    "legacy_accepted": true
  }
}
```

## Gating tests on capabilities

Test suites such as xtest should gate DPoP tests on these keys, not on the reported version. Branch builds can report a stale version. When a key is present, run the test and pick the assertion from its value. When the key is missing, skip the test instead of failing it. This lets platform and test changes merge in either order.

## See also

- [OpenTDF and OpenID Connect](./OIDC.md)
- [Server configuration](./Configuring.md#server-configuration)
