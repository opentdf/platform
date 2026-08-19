package audit

import (
	"context"
	"log/slog"
	"sync"
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
	diagnostics   *slog.Logger
	encoder       Encoder
	sink          Sink
	recordTimeout time.Duration
	configMu      sync.RWMutex
	config        Config
}

// Option configures an audit logger at construction time.
type Option func(*Logger)

// WithEncoder configures the canonical event encoder.
func WithEncoder(encoder Encoder) Option {
	return func(logger *Logger) {
		if encoder != nil {
			logger.encoder = encoder
		}
	}
}

// WithSink configures the emission sink. The default sink writes through slog.
func WithSink(sink Sink) Option {
	return func(logger *Logger) {
		if sink != nil {
			logger.sink = sink
		}
	}
}

// WithDiagnosticLogger routes recorder failures to an operational logger.
func WithDiagnosticLogger(diagnostics *slog.Logger) Option {
	return func(logger *Logger) {
		if diagnostics != nil {
			logger.diagnostics = diagnostics
		}
	}
}

// WithRecordTimeout bounds encoding and sink handoff after request cancellation.
func WithRecordTimeout(timeout time.Duration) Option {
	return func(logger *Logger) {
		if timeout > 0 {
			logger.recordTimeout = timeout
		}
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
		diagnostics:   slog.Default(),
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

// ApplyConfig validates and stores the latest audit enrichment configuration.
func (a *Logger) ApplyConfig(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	a.configMu.Lock()
	a.config = cloneConfig(cfg)
	a.configMu.Unlock()
	return nil
}

//nolint:funcorder // keep configuration read and write synchronization together
func (a *Logger) configSnapshot() Config {
	a.configMu.RLock()
	defer a.configMu.RUnlock()
	return cloneConfig(a.config)
}

func (a *Logger) With(key string, value string) *Logger {
	diagnostics := a.diagnostics
	if diagnostics == nil {
		diagnostics = slog.Default()
	}
	return &Logger{
		//nolint:sloglint // custom logger should support key/value pairs in With attributes
		logger: a.logger.With(key, value),
		//nolint:sloglint // mirror the same scoped attributes on operational diagnostics
		diagnostics:   diagnostics.With(key, value),
		encoder:       a.encoder,
		sink:          a.sink,
		recordTimeout: a.recordTimeout,
		config:        a.configSnapshot(),
	}
}

// Encoder returns the configured encoder, or nil for the default OpenTDF encoder.
func (a *Logger) Encoder() Encoder {
	return a.encoder
}

// Sink returns the configured sink, or nil for the default slog sink.
func (a *Logger) Sink() Sink {
	return a.sink
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

// LogPolicyCRUD creates and immediately records a policy CRUD audit event.
//
// Deprecated: use Record with a canonical Event for new integrations.
func (a *Logger) LogPolicyCRUD(ctx context.Context, isSuccess bool, eventParams PolicyEventParams) {
	auditEvent, err := CreatePolicyEvent(ctx, isSuccess, eventParams)
	if err != nil {
		a.logger.ErrorContext(ctx, "error creating policy attribute audit event", slog.Any("error", err))
		return
	}
	a.recordBuiltIn(ctx, VerbPolicyCRUD, auditEvent)
}

func (a *Logger) GetDecision(ctx context.Context, eventParams GetDecisionEventParams) {
	auditEvent, err := CreateGetDecisionEvent(ctx, eventParams)
	if err != nil {
		a.logger.ErrorContext(ctx, "error creating get decision audit event", slog.Any("error", err))
		return
	}
	a.recordBuiltIn(ctx, VerbDecision, auditEvent)
}

func (a *Logger) GetDecisionV2(ctx context.Context, eventParams GetDecisionV2EventParams) {
	event, err := CreateV2GetDecisionEvent(ctx, eventParams)
	if err != nil {
		a.logger.ErrorContext(ctx, "error creating v2 get decision audit event", slog.Any("error", err))
		return
	}
	a.recordBuiltIn(ctx, VerbDecision, event)
}

// LogAuditEvent immediately records an event through the logger installed by
// the audit server interceptor. New integrations should retain a Recorder and
// call Record directly so delivery errors can be handled explicitly.
//
// Deprecated: use Recorder.Record.
func LogAuditEvent(ctx context.Context, verb Verb, event *EventObject) {
	if event == nil {
		panic("nil audit event provided")
	}
	auditCtx, ok := ctx.Value(contextKey{}).(auditContext)
	if !ok || auditCtx.logger == nil {
		panic("audit logger missing from context")
	}
	recorded := *event
	recorded.Verb = verb
	if err := auditCtx.logger.Record(ctx, recorded); err != nil {
		panic(err)
	}
}

func (a *Logger) rewrapBase(ctx context.Context, eventParams RewrapAuditEventParams) {
	auditEvent, err := CreateRewrapAuditEvent(ctx, eventParams)
	if err != nil {
		a.logger.ErrorContext(ctx, "error creating rewrap audit event", slog.Any("error", err))
		return
	}

	a.recordBuiltIn(ctx, VerbRewrap, auditEvent)
}

func (a *Logger) policyCrudBase(ctx context.Context, isSuccess bool, eventParams PolicyEventParams) {
	auditEvent, err := CreatePolicyEvent(ctx, isSuccess, eventParams)
	if err != nil {
		a.logger.ErrorContext(ctx, "error creating policy attribute audit event", slog.Any("error", err))
		return
	}
	a.recordBuiltIn(ctx, VerbPolicyCRUD, auditEvent)
}

func (a *Logger) recordBuiltIn(ctx context.Context, verb Verb, event *Event) {
	event.Verb = verb
	if err := a.Record(ctx, *event); err != nil {
		a.diagnosticLogger().ErrorContext(ctx, "failed to record audit event", slog.Any("error", err))
	}
}
