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

`Record` snapshots caller-owned data, stamps request attribution, and hands the
event to the configured sink before returning. Encoding and sink handoff use a
bounded context detached from request cancellation. Callers therefore do not
need to detach contexts or create audit transactions.

For operations that require evidence before a side effect, record an
`attempted` event first and a separate `completed` event afterward with the
same event ID. If the attempted record is rejected, security-sensitive callers
should fail closed rather than perform the side effect.

## Encoding and delivery

Embedding applications may install one instance-scoped encoder and sink:

```go
server.Start(
	server.WithAuditEncoder(audit.EncoderFunc(
		func(ctx context.Context, event audit.Event) ([]audit.Emission, error) {
			return []audit.Emission{{
				Level: audit.LevelAudit,
				Message: string(event.Verb),
				Attrs: []slog.Attr{slog.String("message", encode(event))},
			}}, nil
		},
	)),
	server.WithAuditSink(mySink),
)
```

An encoder may produce one or many ordered emissions. Zero emissions are
invalid: errors, panics, or empty results fall back to the unchanged OpenTDF
wire record and return an error to the caller. The default encoder preserves
`level:"AUDIT"`, `msg:<verb>`, and `audit:{...}`.

The authenticated request `Principal` is distinct from the event `Actor`; an
authorization decision may concern a subject other than the requester. JWT
claim mappings may enrich the legacy payload but must not establish resource
ownership. Downstream encoders must derive ownership from authoritative
resource identifiers.

The default slog sink acknowledges handler acceptance only. It does not prove
that stdout, Fluent Bit, or a remote datastore durably persisted the event.
Deployments requiring durable audit guarantees must provide an acknowledging
sink, WAL, or transactional outbox.
