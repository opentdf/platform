# Extending audit recording

Use `Record` to submit an audit event:

```go
event := audit.NewEvent(audit.EventObjectParams{
	Object: audit.EventObjectInfo{Type: audit.ObjectTypeRegisteredResource, ID: documentID},
	Action: audit.EventObjectAction{Type: audit.ActionTypeRead, Result: audit.ActionResultSuccess},
	ClientInfo: audit.EventClientInfo{Platform: "extension"},
})
event.Verb = audit.Verb("read")
err := params.Logger.Audit.Record(ctx, *event)
```

`Record` adds request attribution, validates the event, and calls the processor
synchronously with a deadline detached from request cancellation. Check its
returned error.

## Processing and delivery

Register a custom processor at startup:

```go
server.Start(
	server.WithAuditTimeout(15*time.Second),
	server.WithAuditProcessor(audit.ProcessorFunc(
		func(ctx context.Context, event audit.Event) error {
			return processAuditEvent(ctx, event)
		},
	)),
)
```

The default processing timeout is five seconds. Zero or negative values use the
default. Processors must honor the context deadline, including during external
lookups and delivery.

Processors handle conversion, destination validation, delivery, and recovery.
Return nil after the destination or a durable recovery path accepts the event.
`Record` returns processor errors and recovered panics. OpenTDF does not retry
or emit a fallback.

Processors may run concurrently. They can change their local event value, but
must independently copy any maps, slices, or referenced data they modify or
retain. Callers must leave shared data unchanged until `Record` returns.

`Principal` identifies the authenticated requester; `Actor` may identify a
different subject. Derive resource ownership from authoritative resource data,
not the requester's JWT claims.

Without a custom processor, output remains `level:"AUDIT"`, `msg:<verb>`, and
`audit:{...}`. Success means the slog handler accepted the record, not that a
downstream datastore persisted it. Durable delivery belongs in the processor.
