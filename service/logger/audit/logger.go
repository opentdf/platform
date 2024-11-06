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
		logger: a.logger.With(key, value),
	}
}

func (a *Logger) RewrapSuccess(ctx context.Context, eventParams RewrapAuditEventParams) {
	eventParams.IsSuccess = true
	a.rewrapBase(ctx, eventParams)
}

func (a *Logger) RewrapFailure(ctx context.Context, eventParams RewrapAuditEventParams) {
	a.rewrapBase(ctx, eventParams)
}

func (a *Logger) rewrapBase(ctx context.Context, eventParams RewrapAuditEventParams) {
	auditEvent, err := CreateRewrapAuditEvent(ctx, eventParams)
	if err != nil {
		a.logger.ErrorContext(ctx, "error creating rewrap audit event", "err", err)
		return
	}

	a.logger.Log(ctx, LevelAudit, "rewrap", "audit", *auditEvent)
}

func (a *Logger) PolicyCRUDSuccess(ctx context.Context, eventParams PolicyEventParams) {
	a.policyCrudBase(ctx, true, eventParams)
}

func (a *Logger) PolicyCRUDFailure(ctx context.Context, eventParams PolicyEventParams) {
	a.policyCrudBase(ctx, false, eventParams)
}

func (a *Logger) policyCrudBase(ctx context.Context, isSuccess bool, eventParams PolicyEventParams) {
	auditEvent, err := CreatePolicyEvent(ctx, isSuccess, eventParams)
	if err != nil {
		a.logger.ErrorContext(ctx, "error creating policy attribute audit event", "err", err)
		return
	}

	a.logger.Log(ctx, LevelAudit, "policy crud", "audit", *auditEvent)
}

func (a *Logger) GetDecision(ctx context.Context, eventParams GetDecisionEventParams) {
	auditEvent, err := CreateGetDecisionEvent(ctx, eventParams)
	if err != nil {
		a.logger.ErrorContext(ctx, "error creating get decision audit event", "err", err)
		return
	}

	a.logger.Log(ctx, LevelAudit, "decision", "audit", *auditEvent)
}
