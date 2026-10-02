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

[`otdfctl` issue #4132](https://github.com/opentdf/platform/issues/4132) asks consumers to persist their own global and profile settings alongside existing configuration. Today the concrete `ProfileConfig` and `go-osprofiles` storage paths do not offer a supported, lossless extension contract.

## Considered Options

* Copy the storage engine, add opaque namespaced values, and expose typed variadic functional options (VFO) in `otdfctl`.
* Add each consumer's fields to core types (couples consumers to core releases).
* Use separate consumer stores or expose raw maps publicly (splits lifecycle or shifts safety to callers).

## Decision Outcome

Choose **opaque storage beneath a typed VFO API**. The copied engine stores global and per-profile extension payloads alongside existing filesystem/keyring configuration without interpreting consumer schemas. Core saves and driver migration preserve unknown namespaces and opaque fields. An explicit typed `Write*Extension` fully replaces its namespace and may drop fields absent from the replacement; API comments/docs must warn callers. Other namespaces remain intact. Global settings work without any profile or default profile, including global-only migration. Existing configuration remains readable without registration.

In `otdfctl`, consumers register a namespace and value shape for global or profile scope using variadic functional options, then read/write typed values. Reject invalid or conflicting registrations and return explicit absence or decoding errors without destructive writes. Namespace owners handle any validation or payload version evolution they need; do not mandate a central schema registry or automatic versions. Extension payloads and credentials are never included automatically in output, logs, or diagnostics.

### Sequencing and ownership

First, in a separate prerequisite PR, mechanically copy the pinned `go-osprofiles` revision into `otdfctl/internal/profilestore`, not `/lib` or a public package. Record provenance, retain MIT-compliant license/notice attribution, remove the external dependency, and adjust Go names/imports only as needed. Preserve persisted filenames, JSON, URN encryption-key derivation, and keyring service/key identities exactly. Review license/notice compliance and provenance before merging the copy. Only after that compatibility gate, change the in-tree engine for lossless storage and add the typed VFO API in a subsequent PR.

OpenTDF /otdfctl maintainers own this independent in-tree fork, including future fixes and security updates; there is no ongoing upstream-sync obligation.

### Consequences

* 🟩 **Good:** consumers share existing storage while owning isolated, typed settings.
* 🟥 **Risk:** relocation or a lossy update/migration could make existing settings unreadable or discard unknown data.
* 🟨 **Ownership:** in-tree maintenance and security updates are accepted OpenTDF /otdfctl duties.

## Validation

The copy PR must read pre-copy filesystem and keyring fixtures (including encrypted data) after relocation and check core create/load/update, default selection, authentication, and migration without changing persisted identities. The later storage/API PR must rerun those gates and test global-only operation and migration with zero profiles, typed round trips across drivers, multiple namespaces, unknown-field preservation on core saves/migration, full typed namespace replacement (including dropped omitted fields), errors without mutation, and no implicit payload disclosure.
