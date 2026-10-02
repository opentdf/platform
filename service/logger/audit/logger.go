package audit

import (
	"context"
	"log/slog"
	"time"
)

// From the Slog docs (https://betterstack.com/community/guides/logging/logging-in-go/#customizing-slog-levels):
// The log/slog package provides four log levels by default, with each one
// associated with an integer value: DEBUG (-4), INFO (0), WARN (4), and ERROR (8).
const (
	// Currently setting AUDIT level to 10, a level above ERROR so it is always logged
	LevelAudit           = slog.Level(10)
	LevelAuditStr        = "AUDIT"
	defaultRecordTimeout = 5 * time.Second
)

type Verb string

const (
	VerbDecision   Verb = "decision"
	VerbPolicyCRUD Verb = "policy crud"
	VerbRewrap     Verb = "rewrap"
)

var logLevelNames = map[slog.Leveler]string{
	LevelAudit: LevelAuditStr,
}

type Logger struct {
	logger        *slog.Logger
	processor     Processor
	recordTimeout time.Duration
	config        Config
}

// Option configures an audit logger at construction time.
type Option func(*Logger)

// WithProcessor configures canonical event processing.
func WithProcessor(processor Processor) Option {
	return func(logger *Logger) {
		if processor != nil {
			logger.processor = processor
		}
	}
}

// WithRecordTimeout sets the processing budget. Non-positive values use five seconds.
func WithRecordTimeout(timeout time.Duration) Option {
	return func(logger *Logger) {
		logger.recordTimeout = timeout
	}
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

func CreateAuditLogger(logger slog.Logger, options ...Option) *Logger {
	auditLogger := &Logger{
		logger:        &logger,
		recordTimeout: defaultRecordTimeout,
	}
	for _, option := range options {
		option(auditLogger)
	}
	return auditLogger
}

func cloneConfig(cfg Config) Config {
	cloned := cfg
	cloned.JWTClaimMappings = append([]JWTClaimMapping(nil), cfg.JWTClaimMappings...)
	return cloned
}

// ApplyConfig validates and copies audit enrichment configuration.
// Call only during setup, before the logger is shared with other goroutines.
func (a *Logger) ApplyConfig(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	a.config = cloneConfig(cfg)
	return nil
}

func (a *Logger) With(key string, value string) *Logger {
	return &Logger{
		//nolint:sloglint // custom logger should support key/value pairs in With attributes
		logger:        a.logger.With(key, value),
		processor:     a.processor,
		recordTimeout: a.recordTimeout,
		config:        cloneConfig(a.config),
	}
}

// Processor returns the configured processor, or nil for default OpenTDF processing.
func (a *Logger) Processor() Processor {
	return a.processor
}

// RecordTimeout returns the configured processing budget, or the five-second default.
func (a *Logger) RecordTimeout() time.Duration {
	if a.recordTimeout <= 0 {
		return defaultRecordTimeout
	}
	return a.recordTimeout
}

// RewrapSuccess records a completed rewrap and returns any recording error.
func (a *Logger) RewrapSuccess(ctx context.Context, params RewrapAuditEventParams) error {
	params.IsSuccess = true
	return a.rewrapBase(ctx, params)
}

// RewrapFailure records a failed rewrap and returns any recording error.
func (a *Logger) RewrapFailure(ctx context.Context, params RewrapAuditEventParams) error {
	params.IsSuccess = false
	return a.rewrapBase(ctx, params)
}

// PolicyCRUDSuccess records a successful operation after its database commit.
func (a *Logger) PolicyCRUDSuccess(ctx context.Context, params PolicyEventParams) error {
	return a.policyCrudBase(ctx, true, params)
}

// PolicyCRUDFailure records a failed policy operation.
func (a *Logger) PolicyCRUDFailure(ctx context.Context, params PolicyEventParams) error {
	return a.policyCrudBase(ctx, false, params)
}

func (a *Logger) GetDecision(ctx context.Context, params GetDecisionEventParams) error {
	event, err := CreateGetDecisionEvent(ctx, params)
	if err != nil {
		return err
	}
	event.Verb = VerbDecision
	return a.Record(ctx, *event)
}

func (a *Logger) GetDecisionV2(ctx context.Context, params GetDecisionV2EventParams) error {
	event, err := CreateV2GetDecisionEvent(ctx, params)
	if err != nil {
		return err
	}
	event.Verb = VerbDecision
	return a.Record(ctx, *event)
}

func (a *Logger) rewrapBase(ctx context.Context, params RewrapAuditEventParams) error {
	event, err := CreateRewrapAuditEvent(ctx, params)
	if err != nil {
		return err
	}
	event.Verb = VerbRewrap
	return a.Record(ctx, *event)
}

func (a *Logger) policyCrudBase(ctx context.Context, success bool, params PolicyEventParams) error {
	event, err := CreatePolicyEvent(ctx, success, params)
	if err != nil {
		return err
	}
	event.Verb = VerbPolicyCRUD
	return a.Record(ctx, *event)
}
