# Extending audit recording

Injected services can record generic, typed audit events through the same
request transaction used by built-in OpenTDF services:

```go
err := params.Logger.Audit.Record(ctx, audit.Verb("read"), audit.RecordedEvent{
	Object: audit.RecordedObject{Type: "document", ID: documentID},
	Action: audit.RecordedAction{Type: "read", Result: "success"},
	Actor:  audit.RecordedActor{ID: actorID},
})
```

`Record` returns an error when the context has no active audit transaction or
the transaction has already closed. It snapshots the event before returning,
so later caller mutation cannot change the emitted record. The legacy
`LogAuditEvent` API retains its panic behavior for compatibility.

Applications embedding Platform can install one instance-scoped processor:

```go
server.Start(server.WithAuditProcessor(audit.ProcessorFunc(
	func(ctx context.Context, event audit.FinalizedEvent) (audit.ProcessResult, error) {
		return audit.ProcessResult{Emissions: []audit.Emission{{
			Level:   audit.LevelAudit,
			Message: string(event.Verb),
			Attrs:   []slog.Attr{slog.Any("audit", event.Audit)},
		}}}, nil
	},
)))
```

Processors receive a deep snapshot after request finalization and configured
JWT claim enrichment. They may return one or many ordered emissions. Producing
no output requires `Drop: true`; an accidental empty result, an error, or a
panic emits the unchanged default event once and writes an operational error.
Processors are shared across requests and must be concurrency-safe.

The default processor preserves the existing JSON shape:

```json
{"level":"AUDIT","msg":"read","audit":{}}
```

JWT claim mappings enrich caller and request context. They must not establish
resource ownership or tenant partitioning. Processors should derive ownership
from authoritative resource fields supplied by the service; `FinalizedEvent.Event`
retains those pre-enrichment fields for that purpose.
