// The logger and it's sub-package audit are exposed publicly.
// Subsequent follow up work will require publicly exposing a generalized audit
// method that will accept a struct of the following form:

// type EventObject struct {
// 	Object        auditEventObject `json:"object"`
// 	Action        eventAction      `json:"action"`
// 	Actor         auditEventActor  `json:"actor"`
// 	EventMetaData interface{}      `json:"eventMetaData"`
// 	ClientInfo    eventClientInfo  `json:"clientInfo"`

// 	Original  map[string]interface{} `json:"original,omitempty"`
// 	Updated   map[string]interface{} `json:"updated,omitempty"`
// 	RequestID uuid.UUID              `json:"requestId"`
// 	Timestamp string                 `json:"timestamp"`
// }

// Defined here: platform/service/internal/logger/audit/utils.go

package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/opentdf/platform/service/logger/audit"
)

type Logger struct {
	*slog.Logger
	Audit *audit.Logger
}

type Config struct {
	Level  string `mapstructure:"level" json:"level" default:"info"`
	Output string `mapstructure:"output" json:"output" default:"stdout"`
	Type   string `mapstructure:"type" json:"type" default:"json"`
}

const (
	LevelTrace = slog.Level(-8)
)

func NewLogger(config Config) (*Logger, error) {
	var sLogger *slog.Logger
	logger := new(Logger)

	w, err := getWriter(config)
	if err != nil {
		return nil, err
	}

	level, err := getLevel(config)
	if err != nil {
		return nil, err
	}

	switch config.Type {
	case "json":
		j := slog.NewJSONHandler(w, &slog.HandlerOptions{
			Level:       level,
			ReplaceAttr: logger.replaceAttrChain,
		})
		sLogger = slog.New(j)
	case "text":
		t := slog.NewTextHandler(w, &slog.HandlerOptions{
			Level:       level,
			ReplaceAttr: logger.replaceAttrChain,
		})
		sLogger = slog.New(t)
	default:
		return nil, fmt.Errorf("invalid logger type: %s", config.Type)
	}

	// Audit logger will always log at the AUDIT level and be JSON formatted
	auditLoggerHandler := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level:       audit.LevelAudit,
		ReplaceAttr: audit.ReplaceAttrAuditLevel,
	})

	auditLoggerBase := slog.New(auditLoggerHandler)
	auditLogger := audit.CreateAuditLogger(*auditLoggerBase)

	logger.Logger = sLogger
	logger.Audit = auditLogger

	return logger, nil
}

func (l *Logger) With(key string, value string) *Logger {
	nextLogger := l.Logger
	if l.Logger != nil {
		nextLogger = l.Logger.With(key, value)
	}

	nextAudit := l.Audit
	if l.Audit != nil {
		nextAudit = l.Audit.With(key, value)
	}

	return &Logger{
		Logger: nextLogger,
		Audit:  nextAudit,
	}
}

func getWriter(config Config) (io.Writer, error) {
	switch config.Output {
	case "stdout":
		return os.Stdout, nil
	default:
		return nil, fmt.Errorf("invalid logger output: %s", config.Output)
	}
}

func getLevel(config Config) (slog.Leveler, error) {
	switch config.Level {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "error":
		return slog.LevelError, nil
	case "trace":
		return LevelTrace, nil
	default:
		return nil, fmt.Errorf("invalid logger level: %s", config.Level)
	}
}

func (l *Logger) Trace(msg string, args ...any) {
	l.Log(context.Background(), LevelTrace, msg, args...)
}

func (l *Logger) TraceContext(ctx context.Context, msg string, args ...any) {
	l.Log(ctx, LevelTrace, msg, args...)
}

func CreateTestLogger() *Logger {
	logger, _ := NewLogger(Config{
		Level:  "debug",
		Output: "stdout",
		Type:   "json",
	})
	return logger
}

// TODO: We can filter by keys if we need to in the future so they don't get proccessed by the masqer
func (l *Logger) replaceAttrChain(groups []string, a slog.Attr) slog.Attr {
	return audit.ReplaceAttrAuditLevel(groups, a)
}
