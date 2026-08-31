# Extending audit recording

OpenTDF records one canonical, externally constructible `Event` through an
immediate `Recorder`:

```go
err := params.Logger.Audit.Record(ctx, audit.Event{
	Verb:   audit.Verb("read"),
	Object: audit.Object{Type: "document", ID: documentID},
	Action: audit.Action{Type: "read", Result: "success"},
	ClientInfo: audit.ClientInfo{Platform: "extension"},
})
```

`Record` snapshots caller-owned data, stamps request attribution, validates the
generic event fields, and hands the event to the configured processor before
returning. Processing uses a bounded context detached from request cancellation.
Callers therefore do not need to detach contexts or create audit transactions.

For operations that require evidence before a side effect, generate an event ID
and record an `attempted` event first, then a separate `completed` event with
that same ID. If the attempted record is rejected, security-sensitive callers
should fail closed rather than perform the side effect.

## Processing and delivery

Embedding applications may install one instance-scoped processor:

```go
server.Start(
	server.WithAuditProcessor(audit.ProcessorFunc(
		func(ctx context.Context, event audit.Event) error {
			return processAuditEvent(ctx, event)
		},
	)),
)
```

A processor owns destination-specific validation, fan-out, delivery, and
recovery. A nil error means it accepted the event through its intended
destination or a durable recovery path. Processor errors and panics return to
the caller; OpenTDF does not retry or emit a second fallback record. The default
processor preserves `level:"AUDIT"`, `msg:<verb>`, and `audit:{...}`.

The authenticated request `Principal` is distinct from the event `Actor`; an
authorization decision may concern a subject other than the requester. JWT
claim mappings may enrich the legacy payload but must not establish resource
ownership. Downstream processors must derive ownership from authoritative
resource identifiers.

The default processor acknowledges slog handler acceptance only. It does not
prove that stdout, Fluent Bit, or a remote datastore durably persisted the
event. Deployments requiring durable audit guarantees must implement that
handoff, such as a WAL or transactional outbox, in their processor.
