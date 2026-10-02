---
status: 'proposed'
date: '2026-10-02'
tags:
 - otdfctl
 - configuration
 - profiles
---

# Support named, typed extensions to otdfctl configuration

## Context and Problem Statement

[`otdfctl` configuration extension issue #4132](https://github.com/opentdf/platform/issues/4132) asks how consumers of its command and profile facilities can persist their own settings without maintaining a parallel store or modifying core profile fields. Today `otdfctl` uses `go-osprofiles` for global/default-profile state and profile persistence, while `ProfileConfig` has only concrete core fields. Its current load/save and filesystem-to-keyring migration paths operate on those concrete types; simply adding a field to one struct does not establish an extension contract or guarantee preservation of data unknown to a particular consumer.

## Decision Drivers

* Keep installation-level and selected-profile settings distinct while using the existing configuration and profile stores.
* Give independent consumers a typed API with isolated names, rather than requiring access to storage internals.
* Preserve core and unrecognized data through reads, writes, and migrations, including when an extension is not registered.
* Avoid exposing extension values or credentials implicitly in CLI output, logs, or diagnostics.
* Keep existing profiles and callers usable without extension registration.

## Considered Options

1. Add lossless namespaced opaque storage to the copied engine, with a typed variadic-functional-option (VFO) API in `otdfctl`.
2. Add every consumer's fields directly to core configuration types.
3. Require each consumer to manage its own configuration store.
4. Expose raw, untyped storage maps to callers.

## Decision Outcome

Chosen option: **a small, lossless storage mechanism in the copied engine, with a typed VFO API in `otdfctl`**. The storage engine persists opaque values under separate global and per-profile namespaces alongside existing configuration in the selected store (filesystem or keyring). It does not interpret consumer shapes or require a central schema registry. Namespace boundaries isolate independently owned values from core fields. Loading, saving, and migration must preserve unknown namespaces and fields, including fields unknown to a registered consumer; updating one namespace must not discard another or silently lose unknown data. Global-only data must migrate even when the source has no profiles. This is storage capability, not a requirement for every caller to understand every extension.

At the `otdfctl` boundary, a consumer opts in under a stable namespace and a declared value shape, separately for installation/global settings and profile-scoped settings. Go variadic functional options provide the consumer-facing registration and typed read/write ergonomics, including optional consumer-provided validation where needed. No registration is required for ordinary `otdfctl` operation. Invalid or duplicate namespaces, conflicting registrations, and values that cannot be decoded into a registered shape produce actionable, scope-qualified errors without corrupting stored data. Typed writes must not silently erase opaque fields they do not understand. Global extensions must be usable without creating or selecting a profile, including when no profiles or default profile exist. Existing stored configurations without extensions remain readable: an absent value has explicit typed absence/default behavior, and registration alone must not write defaults over existing data.

Schema evolution belongs to the namespace owner, not the storage engine: an owner may include a version in its own payload and handle validation/migration as its use case requires. No automatic schema version or mandatory validation is imposed on every extension before demonstrated need. A consumer that cannot interpret a present value (including an unsupported owner-defined version) must return an explicit error rather than overwrite it; opaque storage must still preserve that value through save and driver migration. The public API documentation must specify namespace ownership, registration lifetime, scope, absence/default and decoding errors, and the owner's responsibility for version compatibility.

Extension content is private by default: it is not included automatically in profile display, command output, logging, or diagnostics. Consumers must explicitly decide whether to show their own values; the extension mechanism must not reveal credentials or other stored payloads through error messages. Existing profile creation, default selection, authentication, and core config operations retain their behavior with and without registered extensions.

### Sequencing and ownership

Before implementing extensions, copy `go-osprofiles` into `otdfctl` in a **separate dependent PR**, so the storage layer can be adapted without requiring upstream changes. The copy PR must make the source revision and provenance traceable, review the upstream license and required notices for redistribution, remove the external module dependency and update imports/build metadata, and state who maintains the copy and how upstream fixes/security updates will be tracked. Relocation must preserve existing persisted filesystem and keyring identities (filenames, URN encryption-key derivation, and service/key names) so pre-copy data remains readable without reconfiguration. This ADR does **not** assume that copying automatically satisfies licensing requirements or decide an unknown redistribution/maintenance policy: provenance, license/notice compliance, and maintenance ownership are an explicit review hold to resolve before the copy is merged. The extension implementation follows the reviewed copy as a separate PR; it must not silently substitute a different storage architecture.

### Consequences

* 🟩 **Good**, because consumers get scoped, typed settings while sharing the existing storage lifecycle.
* 🟩 **Good**, because preserved opaque data lets older or partial installations update core fields without deleting another consumer's settings.
* 🟥 **Bad**, because lossless migration across storage drivers and owner-managed version compatibility require careful testing.
* 🟥 **Bad**, because maintaining a local copy creates ongoing licensing, provenance, and security-update obligations that the prerequisite PR must explicitly address.

## Pros and Cons of the Options

### Lossless opaque storage with typed VFO extensions in `otdfctl`

* 🟩 Isolates consumers by name and scope without requiring a shared schema registry; owners can validate and evolve their own values.
* 🟥 Requires changes to the persistence layer to avoid lossy decode/save/migration.

### Add fields to core types

* 🟩 Simple for one known consumer.
* 🟥 Couples unrelated consumers to core releases and cannot model independently versioned settings.

### Separate consumer stores

* 🟩 Avoids changes to the current storage layer.
* 🟥 Splits lifecycle, migration, and profile selection across stores.

### Raw storage maps

* 🟩 Flexible for arbitrary data.
* 🟥 Exposing raw maps as the public API shifts namespace conflicts, type safety, and privacy onto every caller; the chosen option keeps raw storage below the typed API.

## Validation

The implementation PR should test opaque global and profile storage round trips through each supported driver and typed VFO read/write over it; global create/read/update with zero profiles and no default profile; global-only migration with no profiles; old data and absent registrations; multiple isolated consumers; rejected duplicate/invalid namespaces and conflicting registrations; explicit absence and typed decoding/owner-defined version errors without mutation; preservation of unknown fields/namespaces through core and typed updates and driver migration; and absence of extension payloads in routine output/logs. The prerequisite copy PR must test reading pre-copy filesystem and keyring fixtures after relocation, including identity-sensitive encrypted data, and be reviewed independently for provenance, license notices, removed dependency, and an explicit maintenance plan before proceeding.
