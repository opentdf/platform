---
status: 'proposed'
date: '2026-05-24'
tags:
 - kas
 - broker
 - discovery
 - sdk
---
# Platform KAS Broker and Capability Discovery

## Context and Problem Statement

Today the repository draws a clean runtime boundary between platform core behavior and KAS behavior:

- `service/pkg/server/services.go` registers `wellknown` in `core`/`all` modes.
- The same file registers `kas` in `kas`/`all` modes.
- `service/wellknownconfiguration/wellknown_configuration.go` exposes public platform discovery data at `/.well-known/opentdf-configuration`.
- `service/kas/kas.proto` defines the existing KAS `AccessService/Rewrap` contract.

That split matters operationally. In modular-binary deployments, operators may run the core platform and KAS as separate processes or on separate infrastructure. If the core platform starts presenting its brokered rewrap behavior as though it were itself a KAS, operators and integrators can easily infer the wrong topology and the wrong ownership boundary.

At the same time, the platform needs a way to advertise that it can broker KAS-facing work for clients. The SDK already uses the well-known configuration endpoint for public discovery, including the default/base KAS direction captured in `adr/decisions/2025-04-28-default-kas-keys.md`. Future federation and obligation-related discussions also point toward broader platform mediation patterns rather than a permanently narrow pass-through model, as noted directionally in `adr/decisions/2025-10-17-sdk-obligations-from-rewrap.md`.

We therefore need a directional architecture decision for:

1. where platform-side brokered rewrap behavior lives,
2. how clients discover that capability,
3. what public information may be exposed, and
4. how to leave room for future brokering work without over-specifying phase-1 mechanics.

## Decision Drivers

* Preserve the deployment and mental-model distinction between core platform services and KAS services.
* Reuse an existing SDK-consumed discovery mechanism where the data is safe for public exposure.
* Keep public discovery coarse-grained and non-sensitive.
* Avoid naming that constrains the feature to a forever-simple HTTP pass-through.
* Maintain compatibility with existing direct-to-KAS behavior during rollout.
* Leave protocol details such as DPoP handling and header forwarding to a later, narrower spec.

## Considered Options

* Extend the existing KAS service and treat brokered rewrap as KAS behavior.
* Add a separate core service but name and frame it as a proxy.
* Add a separate core `kasbroker.KASBrokerService` with `Rewrap`, and advertise coarse capability through well-known configuration.
* Avoid platform discovery and rely on SDK heuristics or operator-supplied configuration.
* Publish detailed broker topology or authorization hints in well-known discovery.

## Decision Outcome

Chosen option: "Add a separate core `kasbroker.KASBrokerService` with `Rewrap`, and advertise coarse capability through well-known configuration."

### Service placement

Platform-side broker behavior will be a separate core service, not an extension of the KAS service.

The platform is not, by that fact alone, a KAS. Keeping broker behavior outside the KAS namespace preserves the runtime model already implied by the service registry and avoids teaching operators that a core deployment necessarily owns KAS identity, keys, or KAS-local operational responsibilities.

The preferred service shape is a dedicated `kasbroker.KASBrokerService` with an RPC named `Rewrap`.

### Naming

We choose **broker** over **proxy**.

"Proxy" would describe the first narrow use case reasonably well, but it prematurely centers the architecture on transparent forwarding. The intended direction has broader ambition: batching, routing, mediation across multiple KASes or platforms, and other platform-to-platform evolution. "Broker" better matches that trajectory without committing this ADR to any specific future expansion.

### Capability discovery

Capability signaling belongs in `WellKnownService` / `/.well-known/opentdf-configuration` for now.

This is the repository's existing public discovery surface, it already fits the `core` runtime mode, and SDKs already consume it. Using well-known configuration avoids introducing a separate discovery channel before there is evidence that one is needed.

The capability signal should be categorized and coarse-grained under a public capabilities section. A representative shape is:

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

The exact field names remain spec/proto work. The architectural decision is that:

- discovery is published through well-known configuration,
- the signal is grouped under a capabilities-oriented structure,
- it advertises broad availability rather than encoding mechanics, and
- it is safe for unauthenticated public exposure.

### Public-safety boundary

Capability data published through well-known configuration must not encode authorization, tenant-specific behavior, sensitive topology, downstream endpoint inventories, policy mappings, or other information that would make the discovery surface an access-control or network-design oracle.

Clients may learn that the platform supports brokered KAS rewrap. They should not learn who is allowed to use it, which downstream KASes are reachable, or how the platform routes for a particular tenant or document.

### SDK direction and compatibility

SDK behavior should evolve directionally as follows:

- If the well-known capability indicates brokered rewrap support, newer SDKs may use the platform broker path.
- If the capability is absent, SDKs should continue current direct-to-KAS behavior.
- Older SDKs that ignore new well-known fields remain compatible and continue existing behavior.

This preserves incremental rollout. Discovery absence means "not advertised," not "hard failure."

What an SDK should do after a broker path has been chosen but the broker call fails remains a narrower compatibility and product decision for a later spec. This ADR does not require silent fallback that could hide misconfiguration or undermine operator intent.

### DPoP and forwarding direction

The broker will need to preserve caller-bound security context when invoking downstream KAS operations. Directionally, that includes the DPoP-bound request model and relevant rewrap-related headers or equivalent propagated context.

However, this ADR does **not** define the low-level forwarding protocol.

That detail is intentionally deferred because DPoP proof material is bound to request method and target, and naïve forwarding may break those guarantees. A later spec must define the trust model and exact handling for items such as:

- whether the original DPoP proof is forwarded, transformed, or replaced,
- how downstream request target binding is preserved,
- which headers are forwarded end-to-end,
- how additional rewrap context is propagated, and
- what audit and error semantics apply when downstream platforms participate.

### Consequences

* 🟩 **Good**, because the core platform can expose broker behavior without masquerading as a KAS deployment.
* 🟩 **Good**, because well-known discovery aligns with existing `core` runtime behavior and existing SDK discovery patterns.
* 🟩 **Good**, because coarse capabilities are suitable for public exposure and avoid coupling discovery to authorization.
* 🟩 **Good**, because the broker name leaves room for future mediation patterns beyond simple pass-through.
* 🟨 **Neutral**, because a new service namespace, proto surface, and SDK behavior will still need to be specified and implemented.
* 🟨 **Neutral**, because direct KAS rewrap remains part of the ecosystem and must coexist with broker-aware clients during rollout.
* 🟥 **Bad**, because brokering authenticated rewrap traffic is security-sensitive, and DPoP/header semantics are not trivial.
* 🟥 **Bad**, because coarse capability discovery cannot express whether a specific caller or tenant is authorized to use the broker; runtime authorization still decides that.

## Validation

This ADR is validated when subsequent specs and implementation preserve the following properties:

- brokered rewrap is introduced as a separate core service rather than folded into the KAS service identity,
- public discovery is exposed through well-known configuration,
- the published capability is coarse-grained and safe for public exposure,
- SDK rollout preserves a compatibility path when the capability is absent, and
- detailed forwarding rules are specified separately rather than implied by this ADR.

## Pros and Cons of the Options

### Extend the existing KAS service and treat brokered rewrap as KAS behavior

* 🟩 **Good**, because it minimizes the number of new service names and may look simpler at first.
* 🟨 **Neutral**, because the wire shape could resemble existing `Rewrap` behavior.
* 🟥 **Bad**, because it blurs the line between a platform deployment and a KAS deployment.
* 🟥 **Bad**, because it conflicts with modular-binary operating models where KAS may run separately from core.
* 🟥 **Bad**, because it teaches operators the wrong ownership model for keys and KAS responsibilities.

### Add a separate core service but name and frame it as a proxy

* 🟩 **Good**, because it correctly separates the capability from KAS identity.
* 🟩 **Good**, because it matches the likely first implementation shape more closely than "broker".
* 🟨 **Neutral**, because it could still use well-known discovery.
* 🟥 **Bad**, because it narrows the conceptual model to transparent forwarding.
* 🟥 **Bad**, because it leaves less room for future routing, batching, and platform-mediated evolution.

### Add a separate core `kasbroker.KASBrokerService` with `Rewrap`, and advertise coarse capability through well-known configuration

* 🟩 **Good**, because it preserves the architectural distinction between core platform and KAS.
* 🟩 **Good**, because it reuses an existing public discovery surface already consumed by SDKs.
* 🟩 **Good**, because it supports incremental rollout through additive capability signaling.
* 🟩 **Good**, because broker-oriented naming leaves room for future federation and mediation scenarios.
* 🟨 **Neutral**, because exact proto shape, capability schema, and forwarding details still require follow-on work.
* 🟥 **Bad**, because the downstream auth/DPoP story remains a non-trivial design area.

### Avoid platform discovery and rely on SDK heuristics or operator-supplied configuration

* 🟩 **Good**, because it keeps public discovery unchanged.
* 🟨 **Neutral**, because it could be workable for tightly controlled private deployments.
* 🟥 **Bad**, because it creates rollout friction and inconsistent client behavior.
* 🟥 **Bad**, because it duplicates configuration burden across operators and SDK consumers.
* 🟥 **Bad**, because it ignores an existing repository pattern for public capability discovery.

### Publish detailed broker topology or authorization hints in well-known discovery

* 🟩 **Good**, because it might reduce some client guesswork.
* 🟥 **Bad**, because it would expose topology and policy-adjacent details on a public endpoint.
* 🟥 **Bad**, because discovery would start carrying authorization meaning that does not belong there.
* 🟥 **Bad**, because it would be harder to evolve safely and could become a compatibility burden.

## More Information

This ADR intentionally stays broad.

It does **not** decide:

- the exact proto package layout or message fields for brokered `Rewrap`,
- the final JSON/proto representation of the capability block,
- how the broker selects one or more downstream KASes,
- whether future brokering includes batching, obligation mediation, or platform-to-platform orchestration,
- or the exact DPoP/header propagation rules.

Those belong in a narrower spec and implementation review.

The phase-1 spec should carry the concrete behavioral contract for capability naming, broker selection, single-target handling, and compatibility/error behavior. The proto should stay tighter still and capture only the broker service seam.

What this ADR does decide is the direction:

- broker behavior belongs to a separate core service,
- discovery should use well-known configuration for now,
- published capability must remain coarse and public-safe,
- and the system should use broker terminology so future work is not boxed into the phase-1 proxy mental model.
