---
status: proposed
date: 2026-10-02
tags:
 - otdfctl
 - analytics
 - privacy
---
# Opt-in command outcome analytics for otdfctl

## Context and Problem Statement

[Issue #4133](https://github.com/opentdf/platform/issues/4133) asks for coarse command usage and outcome reporting through a pluggable sink without transmitting CLI inputs. `cmd.Execute(opts ...ExecuteOptFunc)` already offers functional options, but its normal path calls `RootCmd.ExecuteC()` and then `handleExecuteError`; `WithMountTo` instead mounts `RootCmd` under a caller's root and returns without executing it. The `cli.Cli` exit helpers (`ExitWith`, `ExitWithMessage`, and JSON `ExitWithJSON`) call `os.Exit`; the package-level helpers delegate to them. `os.Exit` skips defers and does not return to Cobra. Cobra `PostRun` cannot observe all successes and failures, and a wrapper around `ExecuteC` cannot observe those early exits. This ADR proposes a contract, **not** an implementation of exit-path refactoring.

## Decision Drivers

* No collection, sink construction, or analytics network activity unless a caller explicitly enables it after checking a local preference.
* No arguments, flag values, credentials, tokens, resource identifiers, endpoints, or raw error/output text cross the analytics boundary.
* Report both successful and failed invocations, including Cobra validation errors and existing exit-helper paths, without changing user-facing output or exit codes.
* A slow or failing sink must not hold up command completion; lifecycle and cancellation must be testable.
* Preserve mounted-root ownership of execution and avoid tracking a host application's commands.

## Considered Options

* Explicit `cmd.Execute` functional option with a pluggable sink and a single invocation lifecycle boundary (chosen).
* Instrument each command separately.
* Add a Cobra `PostRun` hook or observe only the return value of `RootCmd.ExecuteC()`.
* Enable built-in remote telemetry by default.

## Decision Outcome

Chosen option: **explicit `cmd.Execute` functional option with a pluggable sink and a single invocation lifecycle boundary**. Add a variadic option such as `cmd.WithAnalytics(sink AnalyticsSink)` to the existing `cmd.Execute(opts ...ExecuteOptFunc)` API. The caller must first evaluate its own explicit local preference and pass the option only if that preference allows collection; the CLI must not infer consent from environment, profile, or sink availability. Without the option, analytics stays disabled: no event allocation for delivery, sink calls, background worker, or analytics network access. A nil sink must not implicitly enable analytics. The sink is caller supplied (for example, an interface accepting a context and an `AnalyticsEvent`); no built-in destination, device identifier, or implicit HTTP client is part of this decision. The option only controls otdfctl's instrumentation, not activity a caller independently performs when constructing its sink.

The event is an allowlisted value, not a map of command state: a stable **static command identifier** from the registered otdfctl command tree (never a raw command line or arbitrary host command), a coarse duration, and a categorical outcome (`success` or `failure`). No argument strings, flags/values, profile, endpoint, resource name, username, token, raw error text, output, stack trace, or arbitrary metadata are fields. For unknown or unregistered invocations, use a fixed identifier such as `unknown`, never user input or Cobra's error string. Do not attach error subclasses until separately reviewed for privacy. The sink receives only this value; logging a failed delivery must likewise avoid serializing sensitive command data.

Create the invocation lifecycle only after the caller's gate passes. Capture start once per execution, classify success on normal completion or an explicit success exit, and failure on Cobra parsing/validation/pre-run errors or an explicit error exit. Emit **at most one** outcome per invocation, including when both an exit helper and the outer boundary can report an error. Deliver with a fresh, value-free context rooted at `context.Background()`, **not** the command or host context: command context values may contain secrets. Relay only cancellation/deadline signals into the delivery context, with a finite flush deadline. Use a fixed cap on pending events and in-flight sink calls; when capacity is exhausted, drop events rather than spawning a goroutine per event or retrying without bound. The caller waits at most the flush deadline; cancellation cannot stop a sink that ignores its context, so occupied slots remain unavailable until those calls return. A slow or failed sink must not change exit code, output, or command result. Do not promise guaranteed delivery from a process being terminated.

**Architectural prerequisite for implementation:** Existing `os.Exit` calls inside `pkg/cli/errors.go` bypass deferred finalization and `ExecuteC`'s return path; `cmd.Execute(WithMountTo(...))` returns before the host root executes and the host owns shutdown and errors. Before claiming full outcome coverage, implementation must establish a shared, testable observation point for exit helpers and execution errors (e.g., return structured exit results through an outermost exit boundary, or explicitly perform bounded delivery before each unavoidable `os.Exit`). `WithMountTo` alone cannot promise outcomes for a later host execution. Whether v1 is standalone-only or offers an explicit host-owned invocation lifecycle remains an **open decision**; do not assume mounted-mode outcome coverage until that policy is resolved. This is a proposed design requirement, not a claim that current Cobra hooks or exit paths already satisfy it. Keep the existing process exit semantics and printed messages when implementing the prerequisite.

### Consequences

* 🟩 No default collection and no first-party sink lock-in; a fake sink can assert privacy and outcomes.
* 🟩 A single schema and lifecycle avoids per-command payload drift.
* 🟥 Existing immediate-exit helpers and mounted-root execution require coordinated lifecycle changes before complete coverage is possible.
* 🟥 Bounded best-effort delivery can lose events, especially on cancellation or abrupt termination.

## Pros and Cons of the Options

### Explicit option and invocation boundary

* 🟩 Matches existing `ExecuteOptFunc` extension point and keeps consent in the embedding caller's control.
* 🟥 Requires addressing immediate exits and host-owned mounted execution explicitly.

### Per-command instrumentation

* 🟩 Local to commands.
* 🟥 Duplicates privacy rules and misses parsing errors before a command runs.

### Cobra `PostRun` or `ExecuteC` only

* 🟩 Small change for normal returns.
* 🟥 Misses paths that call `os.Exit`, and `PostRun` does not cover all early errors.

### Built-in telemetry by default

* 🟩 Easy collection.
* 🟥 Violates opt-in and no-network-by-default requirements.

## Validation

* Test default `cmd.Execute` with a spy sink/transport: no sink invocation and no analytics network activity; test that an explicit local gate controls option creation and nothing is collected before it opens.
* Test enabled fake sink: registered static command ID, coarse duration, success and failure, at most one event, and no sensitive input/output even when args, flags, endpoints, credentials, and error text contain sentinels.
* Test Cobra parse/validation and pre-run errors, normal completion, and exit-helper success/failure in subprocess tests (because `os.Exit` kills the process). Assert unchanged output and exit codes.
* Test that sink contexts contain no command/host values, relay cancellation/deadlines, and that slow/failing/context-ignoring sinks cannot extend caller wait or grow in-flight calls beyond the cap; assert drops when full and no goroutine per event.
* Document the opt-in API, caller-owned preference gate and sink, privacy allowlist, delivery limitations, and the unresolved mounted-root policy before implementation.
