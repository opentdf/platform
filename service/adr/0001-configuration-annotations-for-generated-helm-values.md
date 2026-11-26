---
status: proposed
date: '2026-05-21'
tags:
 - configuration
 - helm
 - kubernetes
 - cobra
 - viper
 - code-generation
---
# Configuration annotations for generated Helm values

## Context and Problem Statement

OpenTDF platform configuration is defined in Go structs and loaded with Viper, with Cobra providing the operator-facing CLI entry points. The project already carries useful machine-readable metadata in `mapstructure`, `json`, `default`, and `validate` struct tags, and `DefaultSettingsLoader` derives runtime defaults from these tags.

Helm chart values and related chart metadata are currently managed outside of this source tree. This creates drift risk: chart defaults, environment variable names, secrets, documentation, and validation rules can diverge from the platform configuration that the binary actually accepts.

How should OpenTDF express configuration metadata so that Helm values, Helm JSON schema, Kubernetes Secret/ConfigMap mappings, and configuration documentation can be generated consistently from the platform source of truth?

## Decision Drivers

* Keep Go configuration structs as the primary source of truth for runtime configuration.
* Preserve existing Cobra/Viper behavior, including config files, environment variables, defaults, and validation.
* Avoid manual duplication of configuration paths, defaults, environment variables, and chart value names.
* Make Kubernetes-specific concerns explicit where they cannot be inferred safely, especially secrets and file mounts.
* Support external Helm chart repositories by generating stable, versioned artifacts that can be consumed elsewhere.
* Make the approach portable enough to apply to other Cobra/Viper Go services.
* Provide deterministic output suitable for CI drift checks.

## Considered Options

* Continue maintaining Helm values manually outside this repository.
* Infer all Helm metadata from existing Go tags and field names.
* Add an explicit configuration annotation tag layer and generate a normalized schema.
* Use runtime introspection of Cobra/Viper only.

## Decision Outcome

Chosen option: "Add an explicit configuration annotation tag layer and generate a normalized schema", because existing struct tags already provide much of the configuration contract, but Helm/Kubernetes behavior requires additional explicit semantics that cannot be inferred safely.

The implementation will introduce a small annotation layer on configuration structs, plus a generator that emits a stable intermediate schema. Helm values, Helm `values.schema.json`, documentation, and other deployment artifacts should be generated from that intermediate schema rather than independently maintained.

The normative behavior is defined in [Configuration Annotation and Helm Values Generation Specification](../pkg/config/configuration-annotations-spec.md).

### Consequences

* 🟩 **Good**, because runtime config, docs, and Helm chart inputs can share a single source of truth.
* 🟩 **Good**, because secret handling becomes explicit instead of relying on field-name heuristics.
* 🟩 **Good**, because external chart repositories can consume generated artifacts without importing application code at chart render time.
* 🟩 **Good**, because CI can detect stale generated files.
* 🟨 **Neutral**, because some service configuration currently held in dynamic maps will need an explicit schema registry.
* 🟥 **Bad**, because configuration authors must maintain additional metadata for fields that need Helm/Kubernetes-specific behavior.
* 🟥 **Bad**, because generated artifacts introduce another build step and require clear ownership in release workflows.

## Validation

Compliance should be validated by automated checks that:

* walk registered configuration structs and fail on exported fields that are neither included nor explicitly ignored;
* verify that generated schema, docs, and Helm artifacts are checked in and up to date;
* fail if secret-like fields are not explicitly annotated as sensitive or intentionally non-sensitive;
* fail if annotation metadata references invalid Helm paths, duplicate environment variables, or unsupported render modes;
* run golden tests for representative config structs and service registry entries.

## Pros and Cons of the Options

### Continue maintaining Helm values manually outside this repository

* 🟩 **Good**, because it requires no changes to application code.
* 🟩 **Good**, because chart authors retain full manual control.
* 🟥 **Bad**, because defaults, documentation, and chart validation can drift from runtime behavior.
* 🟥 **Bad**, because reviewers must manually correlate Go config changes with chart changes.
* 🟥 **Bad**, because secret handling and environment variable naming remain duplicated knowledge.

### Infer all Helm metadata from existing Go tags and field names

* 🟩 **Good**, because it minimizes annotation burden.
* 🟩 **Good**, because existing `mapstructure`, `default`, and `validate` tags are already useful.
* 🟥 **Bad**, because Kubernetes-specific behavior cannot be inferred safely.
* 🟥 **Bad**, because field-name heuristics for secrets are useful lint signals but insufficient as policy.
* 🟥 **Bad**, because dynamic service maps and external dependencies need explicit registration.

### Add an explicit configuration annotation tag layer and generate a normalized schema

* 🟩 **Good**, because it combines inference for common metadata with explicit annotations for ambiguous behavior.
* 🟩 **Good**, because it produces a reusable intermediate schema for Helm, docs, and validation.
* 🟩 **Good**, because it supports incremental adoption: fields can be annotated as they become chart-facing.
* 🟨 **Neutral**, because the project must define and maintain annotation semantics.
* 🟥 **Bad**, because annotations can become noisy if used for long-form documentation instead of machine behavior.

### Use runtime introspection of Cobra/Viper only

* 🟩 **Good**, because it reflects the binary operators execute.
* 🟨 **Neutral**, because Cobra flags are useful for CLI help but do not represent the full config file surface.
* 🟥 **Bad**, because Viper does not retain enough type, secret, dependency, or chart projection metadata by itself.
* 🟥 **Bad**, because runtime introspection is harder to consume from external chart repositories and release tooling.

## More Information

The generator should treat the normalized schema as the public contract. Helm chart repositories should consume generated files from releases, checked-in artifacts, or a published package rather than parsing Go source independently.

Implementation can be incremental. A first slice can generate schema for the root platform config, then add service-specific registry entries for dynamic `services.*` configuration, then generate Helm values/schema and documentation from the same schema.
