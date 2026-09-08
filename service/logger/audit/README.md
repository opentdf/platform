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
returned error. Existing buffered helpers call the processor when the request
finishes, preserving each producer's context values. The configured timeout
covers the entire flush, not each individual event.

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

The timeout can also be set with `logger.audit_timeout` in YAML or
`OPENTDF_LOGGER_AUDIT_TIMEOUT`. An explicit `server.WithAuditTimeout` overrides
those settings. The default is five seconds; zero or negative values use it. Processors must honor the context deadline, including during external
lookups and delivery.

Processors handle conversion, destination validation, delivery, and recovery.
Return nil after the destination or a durable recovery path accepts the event.
`Record` returns processor errors and recovered panics; buffered helpers report
them through the operational logger. OpenTDF does not retry or emit a fallback.

Processors may run concurrently. They can change their local event value, but
must independently copy any maps, slices, or referenced data they modify or
retain. Callers must leave shared data unchanged until `Record` returns.

`Principal` identifies the authenticated requester; `Actor` may identify a
different subject. Derive resource ownership from authoritative resource data,
not the requester's JWT claims.

Without a custom processor, output remains `level:"AUDIT"`, `msg:<verb>`, and
`audit:{...}`. Success means the slog handler accepted the record, not that a
downstream datastore persisted it. Durable delivery belongs in the processor.

For a standalone logger, pass audit settings in its config:

```go
log, err := logger.NewLogger(logger.Config{
    Level: "info", Output: "stdout", Type: "json",
    AuditTimeout: 15 * time.Second,
    AuditProcessor: processor,
})
```

`AuditProcessor` is for Go callers and is excluded from serialized configuration.
