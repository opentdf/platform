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
returned error. Request context values remain available to the processor.

The built-in `RewrapSuccess`, `RewrapFailure`, `PolicyCRUDSuccess`,
`PolicyCRUDFailure`, `GetDecision`, and `GetDecisionV2` helpers construct an event
and call `Record`. They also return errors; callers must handle them. Record
policy success only after the database transaction commits. An audit failure
after a commit does not undo the operation.

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
lookups and delivery. The budget applies to each event, not the whole request;
a request that records several events can spend several processing budgets.

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

For a standalone logger, pass audit settings in its config:

```go
log, err := logger.NewLogger(logger.Config{
    Level: "info", Output: "stdout", Type: "json",
    AuditTimeout: 15 * time.Second,
    AuditProcessor: processor,
})
```

`AuditProcessor` is for Go callers and is excluded from serialized configuration.

## Migration from buffered recording

Events are processed when recorded, without waiting for an interceptor flush.
A later RPC error or panic does not change an already-recorded outcome.
Decision and rewrap events describe completed sub-operations, not proof that
the client received the final response.

`ContextServerInterceptor()` now only adds request metadata and takes no logger.
`LogAuditEvent`, `Logger.Detach`, and `Logger.LogPolicyCRUD` have been removed.
Use `Record` or the error-returning event helpers without an audit transaction.
Background work can retain its own context lifecycle; recording itself detaches
request cancellation and applies the configured timeout.
