package audit

import (
	"context"
	"encoding/json"
	"log/slog"
)

// From the Slog docs (https://betterstack.com/community/guides/logging/logging-in-go/#customizing-slog-levels):
// The log/slog package provides four log levels by default, with each one
// associated with an integer value: DEBUG (-4), INFO (0), WARN (4), and ERROR (8).
const (
	// Currently setting AUDIT level to 10, a level above ERROR so it is always logged
	LevelAudit = slog.Level(10)
)

var AuditLogLevelNames = map[slog.Level]string{
	LevelAudit: "AUDIT",
}

type AuditLogger struct {
	logger *slog.Logger
}

func CreateAuditLogger(logger slog.Logger) *AuditLogger {
	return &AuditLogger{
		logger: &logger,
	}
}

func (a *AuditLogger) With(key string, value string) *AuditLogger {
	return &AuditLogger{
		logger: a.logger.With(key, value),
	}
}

func (a *AuditLogger) RewrapSuccess(ctx context.Context, eventParams RewrapAuditEventParams) {
	eventParams.IsSuccess = true
	a.rewrap(ctx, eventParams)
}

func (a *AuditLogger) RewrapFailure(ctx context.Context, eventParams RewrapAuditEventParams) {
	eventParams.IsSuccess = false
	a.rewrap(ctx, eventParams)
}

func (a *AuditLogger) PolicyAttributeSuccess(ctx context.Context, eventParams PolicyAttributeAuditEventParams) {
	eventParams.IsSuccess = true
	a.policyAttributeCrud(ctx, eventParams)
}

func (a *AuditLogger) policyAttributeCrud(ctx context.Context, eventParams PolicyAttributeAuditEventParams) {
	auditEvent, err := CreatePolicyAttributeAuditEvent(ctx, eventParams)
	if err != nil {
		a.logger.ErrorContext(ctx, "error creating policy attribute audit event", err)
		return
	}

	auditEventJSONBytes, err := json.Marshal(auditEvent)
	if err != nil {
		a.logger.ErrorContext(ctx, "error marshalling policy attribute audit event", err)
	}

	a.logger.Log(ctx, LevelAudit, string(auditEventJSONBytes))
}

func (a *AuditLogger) rewrap(ctx context.Context, eventParams RewrapAuditEventParams) {
	auditEvent, err := CreateRewrapAuditEvent(ctx, eventParams)
	if err != nil {
		a.logger.ErrorContext(ctx, "error creating rewrap audit event", err)
		return
	}

	auditEventJSONBytes, err := json.Marshal(auditEvent)
	if err != nil {
		a.logger.ErrorContext(ctx, "error marshalling rewrap audit event", err)
	}

	a.logger.Log(ctx, LevelAudit, string(auditEventJSONBytes))
}
