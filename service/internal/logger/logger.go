package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/opentdf/platform/service/internal/logger/audit"
)

type Logger struct {
	*slog.Logger
	Audit *audit.Logger
}

type Config struct {
	Level  string `yaml:"level" default:"info"`
	Output string `yaml:"output" default:"stdout"`
	Type   string `yaml:"type" default:"json"`
}

const (
	LevelTrace = slog.Level(-8)
)

func NewLogger(config Config) (*Logger, error) {
	var logger *slog.Logger

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
			ReplaceAttr: audit.CustomReplaceAttr,
		})
		logger = slog.New(j)
	case "text":
		t := slog.NewTextHandler(w, &slog.HandlerOptions{
			Level:       level,
			ReplaceAttr: audit.CustomReplaceAttr,
		})
		logger = slog.New(t)
	default:
		return nil, fmt.Errorf("invalid logger type: %s", config.Type)
	}

	// Audit logger will always log at the AUDIT level and be JSON formatted
	auditLoggerHandler := slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level:       audit.LevelAudit,
		ReplaceAttr: audit.CustomReplaceAttr,
	})

	auditLoggerBase := slog.New(auditLoggerHandler)
	auditLogger := audit.CreateAuditLogger(*auditLoggerBase)

	return &Logger{
		Logger: logger,
		Audit:  auditLogger,
	}, nil
}

func (l *Logger) With(key string, value string) *Logger {
	return &Logger{
		Logger: l.Logger.With(key, value),
		Audit:  l.Audit.With(key, value),
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
