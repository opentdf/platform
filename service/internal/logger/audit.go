package logger

import (
	"context"
	"encoding/json"
	"log/slog"
)

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
