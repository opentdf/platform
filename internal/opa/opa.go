package opa

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/open-policy-agent/opa/hooks"
	opalog "github.com/open-policy-agent/opa/logging"
	"github.com/open-policy-agent/opa/sdk"
)

type Engine struct {
	*sdk.OPA
}

type Config struct {
	Path     string `yaml:"path" default:"./opentdf-opa.yaml"`
	Embedded bool   `yaml:"embedded" default:"false"`
	// Logger to use otherwise slog.Default(), mainly for testability.
	Logger *slog.Logger
}

func NewEngine(config Config) (*Engine, error) {
	var (
		err     error
		bConfig []byte
		mock    *mockBundleServer
	)

	if config.Embedded {
		mock, err = createMockServer()
		if err != nil {
			return nil, err
		}
	}

	if config.Embedded {
		bConfig = mock.config
	} else {
		bConfig, err = os.ReadFile(config.Path)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}
	asl := config.Logger
	if asl == nil {
		asl = slog.Default()
	}
	logger := AdapterSlogger{
		logger: asl,
	}

	opa, err := sdk.New(context.Background(), sdk.Options{
		Config:        bytes.NewReader(bConfig),
		Logger:        &logger,
		ConsoleLogger: &logger,
		ID:            "opentdf",
		Ready:         nil,
		Store:         nil,
		Hooks:         hooks.Hooks{},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create new sdk: %w", err)
	}

	return &Engine{
		OPA: opa,
	}, nil
}

// AdapterSlogger is the adapter to slog using OPA logger interface.
type AdapterSlogger struct {
	logger *slog.Logger
	fields map[string]interface{}
}

// WithFields provides additional fields to include in log output.
func (l *AdapterSlogger) WithFields(fields map[string]interface{}) opalog.Logger {
	cp := *l
	cp.fields = make(map[string]interface{})
	for k, v := range l.fields {
		cp.fields[k] = v
	}
	for k, v := range fields {
		cp.fields[k] = v
	}
	return &cp
}

// SetLevel noop, uses slog.
func (l *AdapterSlogger) SetLevel(opalog.Level) {
	// noop, uses slog
}

// GetLevel noop, uses slog so no current log level.
func (l *AdapterSlogger) GetLevel() opalog.Level {
	return opalog.Error
}

// getFields returns additional fields of this logger.
func (l *AdapterSlogger) getFieldsKV() []interface{} {
	kv := make([]interface{}, len(l.fields)*2) //nolint:gomnd key and value is added so double the length
	i := 0
	for k, v := range l.fields {
		kv[i] = k
		i++
		kv[i] = v
		i++
	}
	return kv
}

// Debug logs at debug level.
func (l *AdapterSlogger) Debug(msg string, a ...interface{}) {
	l.logger.With(l.getFieldsKV()...).Debug(fmt.Sprintf(msg, a...))
}

// Info logs at info level.
func (l *AdapterSlogger) Info(msg string, a ...interface{}) {
	l.logger.With(l.getFieldsKV()...).Info(fmt.Sprintf(msg, a...))
}

// Error logs at error level.
func (l *AdapterSlogger) Error(msg string, a ...interface{}) {
	l.logger.With(l.getFieldsKV()...).Error(fmt.Sprintf(msg, a...))
}

// Warn logs at warn level.
func (l *AdapterSlogger) Warn(msg string, a ...interface{}) {
	l.logger.With(l.getFieldsKV()...).Warn(fmt.Sprintf(msg, a...))
}
