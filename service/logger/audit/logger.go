package audit

import (
	"context"
	"log/slog"
)

// From the Slog docs (https://betterstack.com/community/guides/logging/logging-in-go/#customizing-slog-levels):
// The log/slog package provides four log levels by default, with each one
// associated with an integer value: DEBUG (-4), INFO (0), WARN (4), and ERROR (8).
const (
	// Currently setting AUDIT level to 10, a level above ERROR so it is always logged
	LevelAudit    = slog.Level(10)
	LevelAuditStr = "AUDIT"
)

// pendingEvent represents a single audit event waiting to be logged
type pendingEvent struct {
	verb  string
	event *EventObject
}

var logLevelNames = map[slog.Leveler]string{
	LevelAudit: LevelAuditStr,
}

type Logger struct {
	logger *slog.Logger
}

// Used to support custom log levels showing up with custom labels as well
// see https://betterstack.com/community/guides/logging/logging-in-go/#creating-custom-log-levels
func ReplaceAttrAuditLevel(_ []string, a slog.Attr) slog.Attr {
	if a.Key != slog.LevelKey {
		return a
	}
	level, ok := a.Value.Any().(slog.Level)
	if !ok {
		return a
	}

	levelLabel, exists := logLevelNames[level]
	if !exists {
		levelLabel = level.String()
	}
	a.Value = slog.StringValue(levelLabel)
	return a
}

func CreateAuditLogger(logger slog.Logger) *Logger {
	return &Logger{
		logger: &logger,
	}
}

func (a *Logger) With(key string, value string) *Logger {
	return &Logger{
		//nolint:sloglint // custom logger should support key/value pairs in With attributes
		logger: a.logger.With(key, value),
	}
}

// addEvent appends a pending audit event to the transaction
func (tx *auditTransaction) addEvent(verb string, event *EventObject) {
	// TK: Use a channel if concurrency becomes an issue
	tx.events = append(tx.events, pendingEvent{
		verb:  verb,
		event: event,
	})
}

// logClose completes an audit transaction and emits all recorded events.
// If success is false or err is not nil, events are logged as "cancelled" with the error attached.
// Otherwise, events are logged with their originally recorded success/failure status.
func (tx *auditTransaction) logClose(ctx context.Context, logger *slog.Logger, success bool, err error) {
	for _, event := range tx.events {
		auditEvent := event.event

		if !success {
			auditEvent.Action.Result = ActionResultCancel
		}

		if err != nil {
			if auditEvent.EventMetaData == nil {
				auditEvent.EventMetaData = make(auditEventMetadata)
			}
			auditEvent.EventMetaData["cancellation_error"] = err.Error()
		}

		logger.Log(ctx, LevelAudit, event.verb, slog.Any("audit", *auditEvent))
	}
}

func (a *Logger) RewrapSuccess(ctx context.Context, eventParams RewrapAuditEventParams) {
	eventParams.IsSuccess = true
	a.rewrapBase(ctx, eventParams)
}

func (a *Logger) RewrapFailure(ctx context.Context, eventParams RewrapAuditEventParams) {
	a.rewrapBase(ctx, eventParams)
}

func (a *Logger) PolicyCRUDSuccess(ctx context.Context, eventParams PolicyEventParams) {
	a.policyCrudBase(ctx, true, eventParams)
}

func (a *Logger) PolicyCRUDFailure(ctx context.Context, eventParams PolicyEventParams) {
	a.policyCrudBase(ctx, false, eventParams)
}

func (a *Logger) GetDecision(ctx context.Context, eventParams GetDecisionEventParams) {
	auditEvent, err := CreateGetDecisionEvent(ctx, eventParams)
	if err != nil {
		a.logger.ErrorContext(ctx, "error creating get decision audit event", slog.Any("error", err))
		return
	}
	LogAuditEvent(ctx, "decision", auditEvent)
}

func (a *Logger) GetDecisionV2(ctx context.Context, eventParams GetDecisionV2EventParams) {
	event, err := CreateV2GetDecisionEvent(ctx, eventParams)
	if err != nil {
		a.logger.ErrorContext(ctx, "error creating v2 get decision audit event", slog.Any("error", err))
		return
	}
	LogAuditEvent(ctx, "decision", event)
}

func LogAuditEvent(ctx context.Context, verb string, event *EventObject) {
	tx, ok := ctx.Value(contextKey{}).(*auditTransaction)
	if !ok {
		panic("audit transaction missing from context")
	}
	if event == nil {
		panic("nil audit event provided")
	}
	tx.addEvent(verb, event)
}

func (a *Logger) rewrapBase(ctx context.Context, eventParams RewrapAuditEventParams) {
	auditEvent, err := CreateRewrapAuditEvent(ctx, eventParams)
	if err != nil {
		a.logger.ErrorContext(ctx, "error creating rewrap audit event", slog.Any("error", err))
		return
	}

	LogAuditEvent(ctx, "rewrap", auditEvent)
}

func (a *Logger) policyCrudBase(ctx context.Context, isSuccess bool, eventParams PolicyEventParams) {
	auditEvent, err := CreatePolicyEvent(ctx, isSuccess, eventParams)
	if err != nil {
		a.logger.ErrorContext(ctx, "error creating policy attribute audit event", slog.Any("error", err))
		return
	}
	LogAuditEvent(ctx, "policy crud", auditEvent)
}
