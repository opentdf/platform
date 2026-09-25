package audit

import (
	"context"
	"errors"
	"sync"

	"github.com/google/uuid"
)

// Phase distinguishes the records that make up one audit lifecycle.
type Phase string

const (
	// PhaseAttempted is recorded before cancellable work begins. It is
	// intentionally partial: the outcome, and usually the object, are not yet
	// known. A lone attempted record is still evidence that the operation
	// reached auditable processing.
	PhaseAttempted Phase = "attempted"
	// PhaseCompleted is recorded once, when the operation reaches a terminal
	// state. It never rewrites the attempted record.
	PhaseCompleted Phase = "completed"
)

// CancellationKind explains why an operation ended without producing a result.
// Cancellation is a result, not a denial, and must not be reported as one.
type CancellationKind string

const (
	// CancellationClientDisconnect means the caller went away before the
	// operation finished.
	CancellationClientDisconnect CancellationKind = "client_disconnect"
	// CancellationDeadlineExceeded means the request budget ran out.
	CancellationDeadlineExceeded CancellationKind = "deadline_exceeded"
)

// LifecycleMetaDataKey is the eventMetaData key carrying lifecycle correlation.
// Keeping correlation in eventMetaData rather than at the top level preserves
// the existing audit JSON shape for consumers that predate lifecycles. Pair
// records by this lifecycle id, not by the per-record event id and not by
// request id, since one request may contain many lifecycles.
const LifecycleMetaDataKey = "lifecycle"

// classifyCancellation maps a context error onto a cancellation kind. It
// reports false when err describes something other than an interruption.
func classifyCancellation(err error) (CancellationKind, bool) {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return CancellationDeadlineExceeded, true
	case errors.Is(err, context.Canceled):
		return CancellationClientDisconnect, true
	default:
		return "", false
	}
}

// lifecycleCore holds the correlation identity and terminal-once guard shared
// by every lifecycle type. Enrichment happens on a private mutable builder; the
// events handed to the recorder are immutable snapshots of it.
type lifecycleCore struct {
	recorder Recorder
	id       uuid.UUID
	slot     int

	mu        sync.Mutex
	completed bool
}

// annotate attaches lifecycle correlation to an event snapshot. Callers must
// hold the lifecycle mutex.
func (c *lifecycleCore) annotate(event *Event, phase Phase, cancellation CancellationKind) {
	meta := map[string]any{
		"id":    c.id.String(),
		"phase": string(phase),
		"slot":  c.slot,
	}
	if cancellation != "" {
		meta["cancellation"] = string(cancellation)
	}
	if event.EventMetaData == nil {
		event.EventMetaData = EventMetaData{}
	}
	event.EventMetaData[LifecycleMetaDataKey] = meta
}

// RewrapLifecycle records the append-only pair of audit events describing one
// key access object's journey through a rewrap request.
//
// The zero value is not usable; obtain one from Logger.BeginRewrap. A nil
// *RewrapLifecycle is safe to use and does nothing, so callers that could not
// begin a lifecycle do not need to guard every later call.
//
// The expected shape is:
//
//	lifecycle, err := logger.Audit.BeginRewrap(ctx, slot, params)
//	if err != nil {
//		// decide whether this operation fails closed
//	}
//	defer lifecycle.Close(ctx)
//
//	... cancellable work ...
//
//	lifecycle.SetPolicy(policy)
//	err = lifecycle.Success(ctx)
type RewrapLifecycle struct {
	lifecycleCore
	params RewrapAuditEventParams
}

// BeginRewrap records the attempted phase for one key access object and returns
// the lifecycle that will record its outcome. The lifecycle is returned even
// when recording fails, so a caller that does not fail closed can carry on and
// still emit a terminal record.
//
// slot identifies the key access object by its position in the request. It is
// deliberately not the key access object id, because those may be duplicated or
// absent and would collide.
func (a *Logger) BeginRewrap(ctx context.Context, slot int, params RewrapAuditEventParams) (*RewrapLifecycle, error) {
	lifecycle := &RewrapLifecycle{
		lifecycleCore: lifecycleCore{
			recorder: a,
			id:       uuid.New(),
			slot:     slot,
		},
		params: params,
	}

	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	return lifecycle, lifecycle.recordLocked(ctx, PhaseAttempted, ActionResultAttempted, "")
}

// ID returns the correlation identifier shared by this lifecycle's records.
func (l *RewrapLifecycle) ID() uuid.UUID {
	if l == nil {
		return uuid.Nil
	}
	return l.id
}

// SetPolicy attaches the policy once it has been resolved. It is a no-op after
// the terminal record, so an already-emitted outcome can never be rewritten.
func (l *RewrapLifecycle) SetPolicy(policy KasPolicy) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.completed {
		return
	}
	l.params.Policy = policy
}

// Success records the terminal record for a completed rewrap.
func (l *RewrapLifecycle) Success(ctx context.Context) error {
	return l.complete(ctx, ActionResultSuccess, "")
}

// Failure records the terminal record for a denied or failed rewrap. It uses
// the same action result the pre-lifecycle helpers emitted, so existing
// consumers see no change.
func (l *RewrapLifecycle) Failure(ctx context.Context) error {
	return l.complete(ctx, ActionResultError, "")
}

// Cancel records the terminal record for an interrupted rewrap.
func (l *RewrapLifecycle) Cancel(ctx context.Context, kind CancellationKind) error {
	return l.complete(ctx, ActionResultCancel, kind)
}

// Close records a terminal record if no explicit outcome was reported, and does
// nothing otherwise. Deferring it means an early return, a rejected request, or
// an interrupted handler still produces a terminal record rather than leaving
// the attempt dangling. The outcome is read from the context: an interrupted
// request is recorded as a cancellation, anything else as an error.
func (l *RewrapLifecycle) Close(ctx context.Context) error {
	if l == nil {
		return nil
	}
	if kind, ok := classifyCancellation(ctx.Err()); ok {
		return l.complete(ctx, ActionResultCancel, kind)
	}
	return l.complete(ctx, ActionResultError, "")
}

func (l *RewrapLifecycle) complete(ctx context.Context, result ActionResult, cancellation CancellationKind) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.completed {
		return nil
	}
	l.completed = true
	return l.recordLocked(ctx, PhaseCompleted, result, cancellation)
}

// recordLocked builds an immutable snapshot of the current parameters and hands
// it to the recorder. Callers must hold the lifecycle mutex.
func (l *RewrapLifecycle) recordLocked(ctx context.Context, phase Phase, result ActionResult, cancellation CancellationKind) error {
	event, err := CreateRewrapAuditEvent(ctx, l.params)
	if err != nil {
		return err
	}
	event.Verb = VerbRewrap
	event.Action.Result = result
	l.annotate(event, phase, cancellation)
	return l.recorder.Record(ctx, *event)
}
