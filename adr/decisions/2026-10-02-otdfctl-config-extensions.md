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

1. Register named, typed global and profile extensions with variadic functional options, stored alongside existing configuration.
2. Add every consumer's fields directly to core configuration types.
3. Require each consumer to manage its own configuration store.
4. Expose raw, untyped storage maps to callers.

## Decision Outcome

Chosen option: **register named, typed global and profile extensions with variadic functional options**. A consumer opts in at startup under a stable namespace and a declared value type, separately for installation/global settings and profile-scoped settings. Registration uses Go variadic functional options for extension-specific behavior such as validation; typed retrieval and update operate on the registered value for the chosen scope. No registration is required for ordinary `otdfctl` operation. Names belong to one registration per scope; invalid names, duplicates, conflicting type/schema declarations, and malformed registered values produce actionable errors before a destructive write.

Extension values live alongside existing global or profile configuration in the currently selected store (filesystem or keyring), not in a second file managed by the consumer. Namespaces form the boundary between independently owned extension values and reserved core fields. Loading and saving must retain unknown namespaces and unknown fields, including fields not understood by the current version of a registered extension; updating one namespace must not rewrite or discard another. Migration between supported drivers must carry the global and profile extension payloads and other unknown data without dropping them. Existing stored configurations without extensions remain readable: an absent extension has an explicit typed absence/default behavior rather than changing the meaning of existing core fields. Registration alone must not write defaults over existing data.

Each registered extension declares a schema version and validation rules for its own payload. Readers validate known versions and values, reject malformed data with namespace/scope context, and must not overwrite it on failure. A newer or unrecognized version must remain intact for round-trip and migration, with a clear unsupported-version error if typed access or update cannot safely interpret it. Version evolution is the namespace owner's responsibility; there is no implicit coercion or lossy downgrade. The implementation's public API documentation must specify registration lifetime, scope, absence/default semantics, version handling, and error behavior.

Extension content is private by default: it is not included automatically in profile display, command output, logging, or diagnostics. Consumers must explicitly decide whether to show their own values; the extension mechanism must not reveal credentials or other stored payloads through error messages. Existing profile creation, default selection, authentication, and core config operations retain their behavior with and without registered extensions.

### Sequencing and ownership

Before implementing extensions, copy `go-osprofiles` into `otdfctl` in a **separate dependent PR**, so the storage layer can be adapted without requiring upstream changes. The copy PR must make the source revision and provenance traceable, review the upstream license and required notices for redistribution, remove the external module dependency and update imports/build metadata, and state who maintains the copy and how upstream fixes/security updates will be tracked. This ADR does **not** assume that copying automatically satisfies licensing requirements or decide an unknown redistribution/maintenance policy: resolve those questions in review before the copy is merged. The extension implementation follows the reviewed copy as a separate PR; it must not silently substitute a different storage architecture.

### Consequences

* 🟩 **Good**, because consumers get scoped, typed settings while sharing the existing storage lifecycle.
* 🟩 **Good**, because preserved opaque data lets older or partial installations update core fields without deleting another consumer's settings.
* 🟥 **Bad**, because validation, version compatibility, and lossless migration add complexity across storage drivers.
* 🟥 **Bad**, because maintaining a local copy creates ongoing licensing, provenance, and security-update obligations that the prerequisite PR must explicitly address.

## Pros and Cons of the Options

### Register typed extensions alongside existing configuration

* 🟩 Isolates consumers by name and scope and supports validation and compatible round-trips.
* 🟥 Requires changes to the persistence layer to avoid lossy decode/save/migration.

### Add fields to core types

* 🟩 Simple for one known consumer.
* 🟥 Couples unrelated consumers to core releases and cannot model independently versioned settings.

### Separate consumer stores

* 🟩 Avoids changes to the current storage layer.
* 🟥 Splits lifecycle, migration, and profile selection across stores.

### Raw storage maps

* 🟩 Flexible for arbitrary data.
* 🟥 Shifts namespace conflicts, type safety, validation, and privacy onto every caller.

## Validation

The implementation PR should test typed global and profile round trips through each supported storage driver; old data and absent registrations; multiple isolated consumers; rejected duplicates, invalid names, types, versions, and malformed values without mutation; preservation of unknown fields/namespaces through core updates and driver migration; and absence of extension payloads in routine output/logs. Review the prerequisite copy PR independently for provenance, license notices, removed dependency, and an explicit maintenance plan before proceeding.
