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

type Verb string

const (
	VerbDecision   Verb = "decision"
	VerbPolicyCRUD Verb = "policy crud"
	VerbRewrap     Verb = "rewrap"
)

// pendingEvent represents a single audit event waiting to be logged
type pendingEvent struct {
	verb  Verb
	event RecordedEvent
}

var logLevelNames = map[slog.Leveler]string{
	LevelAudit: LevelAuditStr,
}

type Logger struct {
	logger      *slog.Logger
	diagnostics *slog.Logger
	processor   Processor
	config      Config
}

// Option configures an audit logger at construction time.
type Option func(*Logger)

// WithProcessor configures the finalized-event processor.
func WithProcessor(processor Processor) Option {
	return func(logger *Logger) {
		if processor != nil {
			logger.processor = processor
		}
	}
}

// WithDiagnosticLogger routes processor failures to an operational logger.
func WithDiagnosticLogger(diagnostics *slog.Logger) Option {
	return func(logger *Logger) {
		if diagnostics != nil {
			logger.diagnostics = diagnostics
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
		logger:      &logger,
		diagnostics: slog.Default(),
		processor:   defaultProcessor{},
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
	a.config = cloneConfig(cfg)
	return nil
}

func (a *Logger) With(key string, value string) *Logger {
	diagnostics := a.diagnostics
	if diagnostics == nil {
		diagnostics = slog.Default()
	}
	processor := a.processor
	if processor == nil {
		processor = defaultProcessor{}
	}
	return &Logger{
		//nolint:sloglint // custom logger should support key/value pairs in With attributes
		logger: a.logger.With(key, value),
		//nolint:sloglint // mirror the same scoped attributes on operational diagnostics
		diagnostics: diagnostics.With(key, value),
		processor:   processor,
		config:      cloneConfig(a.config),
	}
}

// Processor returns the immutable processor configured for this logger.
func (a *Logger) Processor() Processor {
	if a.processor == nil {
		return defaultProcessor{}
	}
	return a.processor
}

// addEvent appends a pending audit event to the transaction
func (tx *auditTransaction) addEvent(verb Verb, event RecordedEvent) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if tx.closed {
		return ErrTransactionClosed
	}
	tx.events = append(tx.events, pendingEvent{
		verb:  verb,
		event: cloneRecordedEvent(event),
	})
	return nil
}

// logClose completes an audit transaction and emits all recorded events.
// If success is false or err is not nil, events are logged as "cancelled" with the error attached.
// Otherwise, events are logged with their originally recorded success/failure status.
func (tx *auditTransaction) logClose(ctx context.Context, auditLogger *Logger, success bool, err error) {
	tx.mu.Lock()
	if tx.closed {
		tx.mu.Unlock()
		return
	}
	tx.closed = true
	events := tx.events
	tx.events = nil
	tx.mu.Unlock()
	for _, event := range events {
		auditEvent := event.event

		if !success {
			auditEvent.Action.Result = ActionResultCancel.String()
		}

		if err != nil {
			if auditEvent.EventMetaData == nil {
				auditEvent.EventMetaData = make(map[string]any)
			}
			auditEvent.EventMetaData["cancellation_error"] = err.Error()
		}

		finalized := FinalizedEvent{
			Verb:  event.verb,
			Event: cloneRecordedEvent(auditEvent),
			Audit: auditLogger.buildRecordedLogEntry(ctx, auditEvent),
		}
		auditLogger.processAndEmit(ctx, finalized)
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
	LogAuditEvent(ctx, VerbDecision, auditEvent)
}

func (a *Logger) GetDecisionV2(ctx context.Context, eventParams GetDecisionV2EventParams) {
	event, err := CreateV2GetDecisionEvent(ctx, eventParams)
	if err != nil {
		a.logger.ErrorContext(ctx, "error creating v2 get decision audit event", slog.Any("error", err))
		return
	}
	LogAuditEvent(ctx, VerbDecision, event)
}

// LogAuditEvent records a legacy OpenTDF event and retains its historical panic
// behavior when no transaction exists or the event is nil.
//
// Deprecated: Use (*Logger).Record for externally supplied events.
func LogAuditEvent(ctx context.Context, verb Verb, event *EventObject) {
	tx, ok := ctx.Value(contextKey{}).(*auditTransaction)
	if !ok {
		panic("audit transaction missing from context")
	}
	if event == nil {
		panic("nil audit event provided")
	}
	if err := tx.addEvent(verb, recordedEventFromLegacy(*event)); err != nil {
		panic(err)
	}
}

// Record adds an externally constructed event to the current request audit
// transaction. The event is deeply snapshotted before Record returns.
func (a *Logger) Record(ctx context.Context, verb Verb, event RecordedEvent) error {
	if a == nil || verb == "" {
		return ErrInvalidEvent
	}
	tx, ok := ctx.Value(contextKey{}).(*auditTransaction)
	if !ok || tx == nil {
		return ErrNoTransaction
	}
	return tx.addEvent(verb, event)
}

func (a *Logger) rewrapBase(ctx context.Context, eventParams RewrapAuditEventParams) {
	auditEvent, err := CreateRewrapAuditEvent(ctx, eventParams)
	if err != nil {
		a.logger.ErrorContext(ctx, "error creating rewrap audit event", slog.Any("error", err))
		return
	}

	LogAuditEvent(ctx, VerbRewrap, auditEvent)
}

func (a *Logger) policyCrudBase(ctx context.Context, isSuccess bool, eventParams PolicyEventParams) {
	auditEvent, err := CreatePolicyEvent(ctx, isSuccess, eventParams)
	if err != nil {
		a.logger.ErrorContext(ctx, "error creating policy attribute audit event", slog.Any("error", err))
		return
	}
	LogAuditEvent(ctx, VerbPolicyCRUD, auditEvent)
}

func (a *Logger) processAndEmit(ctx context.Context, event FinalizedEvent) {
	processor := a.processor
	if processor == nil {
		processor = defaultProcessor{}
	}
	result, err := processEvent(ctx, processor, event)
	if err == nil {
		err = validateProcessResult(result)
	}
	if err != nil {
		diagnostics := a.diagnostics
		if diagnostics == nil {
			diagnostics = slog.Default()
		}
		diagnostics.ErrorContext(ctx, "audit processor failed; emitting default event", slog.Any("error", err))
		result, _ = defaultProcessor{}.Process(ctx, event)
	}
	if result.Drop {
		return
	}
	for _, emission := range result.Emissions {
		//nolint:sloglint // processor-defined audit messages are intentionally dynamic
		a.logger.LogAttrs(ctx, emission.Level, emission.Message, emission.Attrs...)
	}
}
