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

// KAS Rewrap Success Event Log
func (a *AuditLogger) RewrapSuccess(ctx context.Context, policy AuditPolicy) error {
	err := a.rewrapBase(ctx, policy, true)
	if err != nil {
		return err
	}
	return nil
}

// KAS Rewrap Failure Event Log
func (a *AuditLogger) RewrapFailure(ctx context.Context, policy AuditPolicy) error {
	err := a.rewrapBase(ctx, policy, false)
	if err != nil {
		return err
	}
	return nil
}

func (a *AuditLogger) rewrapBase(ctx context.Context, policy AuditPolicy, isSuccess bool) error {
	auditLog := createAuditLogBase(isSuccess)
	auditLog.Object.ID = policy.UUID.String()
	for _, value := range policy.Body.DataAttributes {
		auditLog.Object.Attributes.Attrs = append(auditLog.Object.Attributes.Attrs, value.URI)
	}
	auditLog.Object.Attributes.Dissem = policy.Body.Dissem

	auditLogJSONString, err := json.Marshal(auditLog)
	if err != nil {
		return err
	}

	a.logger.Log(ctx, LevelAudit, string(auditLogJSONString))
	return nil
}
