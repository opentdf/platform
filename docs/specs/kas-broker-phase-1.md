---
title: "Phase-1 KAS brokered rewrap via core service"
status: draft
summary: "Add a core-scoped KAS broker service for rewrap only, advertise that capability through well-known configuration, and let newer SDKs opt into the broker path when it is explicitly published. Phase 1 stays intentionally narrow: one broker RPC, one downstream KAS base URL per call, no delegated caller-bound forwarding, and no change to direct KAS or base-key behavior."
owners:
  - "@platform"
created: "2026-05-24"
updated: "2026-05-24"
layers:
  - service
  - proto
  - sdk
  - cli
  - docs/ops
service_namespaces:
  - wellknown
  - kasbroker
runtime_modes:
  - core
  - all
related:
  adr:
    - "adr/decisions/2026-05-24-platform-kas-broker-and-capability-discovery.md"
    - "adr/decisions/2025-04-28-default-kas-keys.md"
  proto:
    - "service/kas/kas.proto"
    - "service/wellknownconfiguration/wellknown_configuration.proto"
    - "service/kasbroker/kas_broker.proto"
  implementation:
    - "service/pkg/server/services.go"
    - "service/pkg/server/start.go"
    - "service/wellknownconfiguration/"
    - "service/kas/"
    - "sdk/"
    - "otdfctl/"
---

# Phase-1 KAS brokered rewrap via core service

## Summary

Phase 1 adds a **core-hosted** broker endpoint for KAS `Rewrap` traffic without redefining the core platform as a KAS.

The phase-1 shape is deliberately small:

- the new service is a separate `kasbroker` namespace in `core`/`all` modes
- capability is advertised through `/.well-known/opentdf-configuration`
- newer SDKs use the broker only when that capability is explicitly advertised
- direct-to-KAS behavior remains the compatibility path when the capability is absent
- the broker handles only `Rewrap` and only for a single downstream KAS base URL per request

This is narrower than the ADR's longer-term broker direction. Phase 1 does **not** introduce multi-KAS fan-out, delegated end-user identity forwarding, platform-to-platform brokering, brokered public-key discovery, or richer topology-aware discovery.

## Goals

- Add a concrete phase-1 broker service for KAS `Rewrap` traffic under the core platform.
- Preserve the deployment and ownership distinction between core services and KAS services.
- Reuse well-known configuration for coarse, public-safe capability signaling.
- Keep rollout incremental: capability absent means SDKs keep current direct-to-KAS behavior.
- Reuse the existing `kas.RewrapRequest` and `kas.RewrapResponse` shapes so phase 1 is additive and implementable.

## Non-goals

- Making the core platform present itself as a KAS.
- Changing `kas.AccessService/PublicKey`, `kas.AccessService/LegacyPublicKey`, or default/base-key discovery behavior.
- Introducing multi-target brokering from one broker RPC call.
- Publishing downstream KAS inventories, tenant routing hints, or authorization hints in well-known configuration.
- Defining delegated caller-bound DPoP forwarding or end-to-end caller-token propagation to downstream KASes.
- Adding CLI product surface in `otdfctl/`.
- Solving future broker ambitions such as batching, routing across many KASes, obligation aggregation across platforms, or platform-to-platform mediation.

## Current behavior

Today the repo keeps core-platform and KAS behavior separate.

- `service/pkg/server/services.go` registers `wellknown` in `core`/`all` modes.
- The same file registers `kas` in `kas`/`all` modes.
- `service/wellknownconfiguration/wellknown_configuration.go` exposes public data at `/.well-known/opentdf-configuration` and stores that data as an open-ended map.
- `service/wellknownconfiguration/wellknown_configuration.proto` returns a `google.protobuf.Struct`, so additional public config can be added without changing that proto.
- `service/kas/kas.proto` defines the current KAS `AccessService/Rewrap` contract.
- `sdk/kas_client.go` sends rewrap requests directly to the KAS URL in the key access object and adds `X-Rewrap-Additional-Context` to that direct request.
- `sdk/basekey.go` and `sdk/tdf.go` already use well-known configuration for base/default KAS behavior during encryption planning; that behavior is separate from this phase-1 rewrap change.

Two current details matter for phase 1:

1. The modular-binary split is already visible in service registration, so the spec should preserve that operator mental model.
2. The SDK already operates on one downstream KAS URL per outbound rewrap call, so phase 1 can stay single-target without creating a new client-side batching model.

## Proposed behavior

### Service

Add a new core-owned service namespace, `kasbroker`, registered in `core` and `all` runtime modes.

Phase-1 ownership is:

- `wellknown` owns public capability publication.
- `kasbroker` owns the broker RPC and downstream KAS mediation.
- `kas` remains the owner of direct KAS behavior, key material operations, and KAS-specific operational responsibilities.

This separation is required because the service is **not** a KAS. In modular-binary deployments, operators may run core and KAS separately. Advertising or implementing the broker inside the `kas` namespace would blur which process owns KAS keys, KAS registration, and KAS-local operations. Even when running in `all` mode, the namespaces remain distinct.

Phase-1 service behavior:

- Add `kasbroker.KASBrokerService` with a single RPC: `Rewrap`.
- Host that RPC on the core platform endpoint, not the downstream KAS endpoint.
- Accept the same request message the SDK already builds for direct KAS rewrap.
- Determine the downstream KAS target from the `kas_url` values inside the request body's key access objects.
- Normalize target matching using the same base-URL interpretation the SDK uses when constructing the outbound transport target for direct KAS calls (scheme + host + optional port, without assuming the path is the routing key). Current SDK request grouping still starts from the original KAO `kas_url` values before that transport parsing step, so phase-1 broker normalization is a server-side rule rather than a claim that today’s client groups by normalized base URL.
- Require every key access object in one broker request to normalize to the same downstream KAS base URL.
- Reject requests that contain zero usable targets or more than one distinct normalized target with `InvalidArgument`.

Phase-1 safety/config assumptions:

- The broker only calls downstream KAS targets that are explicitly configured in an allowlist.
- The operator-facing configuration should live under `services.kasbroker.allowed_kas_base_urls`.
- If that allowlist is empty or invalid, the broker must not advertise capability in well-known configuration.
- If the broker RPC is called while not fully configured, it should fail clearly with `FailedPrecondition` rather than silently proxying to arbitrary targets.

Phase-1 forwarding behavior:

- The broker forwards the `signed_request_token` payload unchanged.
- The broker forwards `X-Rewrap-Additional-Context` unchanged when present.
- The broker returns the downstream `kas.RewrapResponse` as-is except for normal transport/status mapping.
- The broker does **not** reshape a direct-KAS response into a new broker-only response type.

Phase-1 auth and DPoP assumption:

- The incoming SDK-to-broker request is authenticated as a normal core-platform request.
- The broker terminates the incoming `Authorization` and `DPoP` headers at the core boundary.
- The broker does **not** forward the caller's `Authorization` header end-to-end.
- The broker does **not** forward the caller's inbound `DPoP` proof to the downstream KAS because that proof is bound to the broker RPC path, not the downstream KAS path.
- The broker makes its own outbound KAS request using the platform's configured service-to-service client/auth setup.

That means phase 1 is limited to operator-controlled deployments where the downstream KAS trusts the broker service identity for rewrap mediation. End-user-bound proof delegation and end-to-end caller context forwarding are future-phase work, not phase 1.

Capability signaling rules:

- The core platform publishes a coarse capability under well-known configuration when the broker service is enabled and fully configured.
- The phase-1 capability shape is:

```json
{
  "capabilities": {
    "kas": {
      "broker": {
        "rewrap": true
      }
    }
  }
}
```

- No downstream endpoint list, tenant list, auth hint, or routing metadata is published.
- No separate broker endpoint URL is published in phase 1; `rewrap: true` means "use the current core platform endpoint's broker RPC".
- If the broker is not configured, the capability is omitted rather than publishing `false`.

### Proto

Add a new proto at `service/kasbroker/kas_broker.proto`.

Phase-1 proto shape:

```proto
syntax = "proto3";

package kasbroker;

import "kas/kas.proto";

service KASBrokerService {
  rpc Rewrap(kas.RewrapRequest) returns (kas.RewrapResponse) {}
}
```

The proto intentionally stays limited to the service seam. Target selection, allowlisting, auth termination, capability publication, and compatibility behavior remain specified here in the phase-1 spec rather than being pushed into the proto contract.

Proto impact in phase 1:

- Additive only.
- No field changes to `service/kas/kas.proto`.
- No schema change to `service/wellknownconfiguration/wellknown_configuration.proto`; capability data is carried inside its existing `Struct` payload.
- Regenerate `protocol/go/` outputs and published gRPC/OpenAPI docs for the new broker service.

Reusing the existing KAS request/response messages is the key phase-1 constraint. It keeps the broker concrete and implementable without inventing a second rewrap payload model.

### SDK

SDK behavior in phase 1 is discovery-driven and intentionally conservative.

Selection rules:

- When well-known configuration contains `capabilities.kas.broker.rewrap == true`, the SDK should send rewrap traffic to `kasbroker.KASBrokerService/Rewrap` on the already-configured platform endpoint.
- When the capability is absent, the SDK keeps current direct-to-KAS behavior.
- Older SDKs that ignore the new capability field continue direct-to-KAS behavior unchanged.

Behavior that stays the same when brokering is selected:

- The SDK still builds `kas.RewrapRequest` the same way.
- The SDK still signs `signed_request_token` the same way.
- The SDK still includes `X-Rewrap-Additional-Context` the same way.
- The SDK still groups work so one outbound rewrap call corresponds to one downstream KAS base URL.

Fallback behavior:

- Discovery absence is the compatibility fallback: use direct KAS.
- A well-known read error while checking broker capability should be treated as capability unavailable for this decision path, with the SDK falling back to direct KAS.
- Once the SDK chooses the broker because capability was advertised, broker call failures must be surfaced to the caller.
- The SDK must **not** silently retry the same rewrap directly against the downstream KAS after a broker-path error.
- In other words, broker discovery selects the path for this call; the SDK should not reinterpret that failure as permission to bypass the broker on its own.
- Silent fallback would bypass the operator-configured allowlist and undermine the operator's intentional routing policy; if the broker path was selected, a failure on that path is a signal that must be surfaced, not hidden.

Unchanged SDK areas:

- Base/default KAS discovery from `base_key` remains unchanged.
- Encryption planning remains unchanged.
- No new client-side topology logic is added beyond the capability check and broker client selection.

### CLI

Not affected in phase 1.

- No new `otdfctl/` command, flag, or output shape is required.
- Operators can verify capability through the well-known endpoint and normal service docs.
- A broker-specific CLI/admin surface is a future follow-up if the feature proves operationally useful.

### Docs/Ops

Phase-1 docs and ops work is required even though the feature is intentionally small.

Docs and operator guidance must cover:

- the broker running as a **core** service, separate from `kas`
- the reason for that split: modular-binary deployment clarity and operator ownership clarity
- the allowlist-style configuration for downstream KAS base URLs under `services.kasbroker.allowed_kas_base_urls`
- rollout order: configure and deploy the broker-capable core service first, then upgrade SDKs
- the fact that well-known capability is coarse and public-safe, not an authorization promise
- the phase-1 auth assumption that the downstream KAS trusts the broker's service identity
- the fact that caller-bound DPoP forwarding is intentionally out of scope for phase 1

Example config shape:

```yaml
mode: core
services:
  kasbroker:
    allowed_kas_base_urls:
      - https://kas.example.com
      - https://kas-backup.example.com
```

The examples and deployment notes should also call out that enabling broker capability does **not** remove or replace direct KAS endpoints. Direct KAS remains part of the rollout and compatibility story.

## Data shapes and examples

### Well-known capability example

```json
{
  "base_key": {
    "kas_url": "https://default-kas.example.com/kas",
    "public_key": {
      "algorithm": "rsa:2048",
      "kid": "r1",
      "pem": "-----BEGIN PUBLIC KEY-----..."
    }
  },
  "capabilities": {
    "kas": {
      "broker": {
        "rewrap": true
      }
    }
  }
}
```

### Broker selection example

```text
Platform endpoint: https://platform.example.com
Well-known capability: capabilities.kas.broker.rewrap = true
Request KAO kas_url: https://kas.example.com/kas
SDK action: call https://platform.example.com/<kasbroker Rewrap RPC>
Broker action: call https://kas.example.com/<kas Rewrap RPC>
```

### Phase-1 request admissibility example

Allowed in phase 1:

- request contains KAOs that all normalize to `https://kas.example.com`

Rejected in phase 1:

- one KAO normalizes to `https://kas-a.example.com`
- another KAO normalizes to `https://kas-b.example.com`

That multi-target case is for a later broker phase.

## Concrete scenarios

### Scenario 1: broker advertised, new SDK uses broker

- Core deployment runs `wellknown` and `kasbroker`.
- Well-known config publishes `capabilities.kas.broker.rewrap = true`.
- SDK sees the capability and sends rewrap to `kasbroker.KASBrokerService/Rewrap` on the platform endpoint.
- Broker resolves the single downstream KAS base URL from the request, verifies it is allowlisted, forwards the request to that KAS, and returns the downstream response.

### Scenario 2: capability absent, compatibility path stays direct

- Core deployment does not advertise broker capability.
- SDK does not attempt brokered rewrap.
- SDK keeps current direct-to-KAS behavior using the KAO `kas_url`.

### Scenario 3: old SDK against new platform

- Platform publishes broker capability.
- Older SDK ignores the new well-known field.
- Rewrap remains direct-to-KAS.
- Result: rollout is additive, not breaking.

### Scenario 4: broker selected, downstream target not allowlisted

- Platform advertises broker capability.
- SDK selects broker.
- Request contains a downstream KAS base URL not present in `services.kasbroker.allowed_kas_base_urls`.
- Broker rejects the request with a clear error.
- SDK surfaces that broker error and does not silently bypass policy by calling the KAS directly.

### Scenario 5: broker selected, well-known was available but broker call fails

- SDK observed broker capability and chose the broker path.
- Broker call fails with transport, auth, or downstream service error.
- SDK returns that error.
- SDK does not fall back to direct KAS automatically.

### Scenario 6: multi-target request arrives at broker

- Request contains KAOs that normalize to multiple downstream KAS base URLs.
- Broker returns `InvalidArgument`.
- SDK should not create this shape in normal phase-1 flow, and future phases may widen this behavior.

## Compatibility and migration

Phase-1 compatibility rules:

- The change is additive.
- Direct KAS endpoints remain available and unchanged.
- Existing well-known consumers remain compatible because the response is already an open-ended struct.
- Older SDKs remain compatible because they ignore unknown well-known fields.
- Newer SDKs preserve compatibility by treating capability absence as "use direct KAS".

Recommended rollout order:

1. add broker proto/service and well-known capability publication in core
2. deploy/configure core with valid broker allowlist and downstream connectivity
3. update SDKs to honor the capability
4. optionally update docs/examples for operators

Important migration boundary:

- If the platform advertises broker capability, that is an operator assertion that the broker path is the intended path.
- Failure on that path is surfaced, not silently bypassed.

## Validation

The work is complete when all of the following are true:

- service registration includes a separate `kasbroker` namespace in `core`/`all` modes
- well-known configuration publishes `capabilities.kas.broker.rewrap` only when the broker is configured
- the broker service accepts and returns the existing KAS rewrap message types
- broker service tests cover:
  - single-target success
  - multi-target rejection
  - allowlist rejection
  - forwarding of `X-Rewrap-Additional-Context`
  - no publication of capability when broker config is absent
- SDK tests cover:
  - capability-driven broker selection
  - direct-KAS fallback when capability is absent
  - no silent direct fallback after broker-path failure
  - older behavior unchanged when capability is ignored
- generated proto outputs and gRPC/OpenAPI docs are updated for the new service
- manual verification shows the well-known endpoint publishing the capability and a brokered rewrap succeeding against an allowlisted downstream KAS

## Risks and open questions

- Phase 1 intentionally terminates caller-bound DPoP at the broker boundary; downstream KAS authorization therefore relies on the broker's service identity, not delegated end-user proof.
- Public capability signaling remains coarse, so successful discovery does not guarantee a given caller is authorized to use the broker.
- The `RegisterConfiguration` API (`service/wellknownconfiguration/wellknown_configuration.go`) claims a single top-level well-known namespace key exclusively and returns an error on duplicate registration with no merge or deregistration path. Publishing under a shared `capabilities` key means only one service may call `RegisterConfiguration("capabilities", ...)`. Any future service that also wants to contribute to a `capabilities` top-level block would collide at startup, so implementation must treat that key as exclusively broker-owned for now or introduce a merge mechanism before multiple services publish capability sub-keys.

## Out-of-scope follow-ups

- Multi-KAS fan-out or aggregation from a single broker call.
- Brokering of `PublicKey` or other KAS endpoints.
- Forwarding, transforming, or delegating caller `Authorization` and `DPoP` end-to-end.
- Richer discovery metadata such as per-tenant capability, routing hints, or downstream endpoint lists.
- Platform-to-platform brokering or federation-aware routing.
- CLI/admin surfaces for broker diagnostics.
- Obligation aggregation or other response mediation beyond today's `X-Rewrap-Additional-Context` and direct downstream response handling.
