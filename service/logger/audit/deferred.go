package audit

import (
	"context"
	"sync"

	"google.golang.org/protobuf/proto"
)

// deferred is the generic deferred audit implementation
type deferred[T any] struct {
	ctx           context.Context
	params        T
	onSuccess     func(context.Context, T)
	onFailure     func(context.Context, T)
	mu            sync.Mutex
	completed     bool
	successCalled bool
}

// markSuccess marks the event as successful (without logging yet)
func (d *deferred[T]) markSuccess() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		return
	}
	d.successCalled = true
	d.completed = true
	d.onSuccess(d.ctx, d.params)
}

// markFailure marks the event as failed (without logging yet)
func (d *deferred[T]) markFailure() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		return
	}
	d.completed = true
	d.onFailure(d.ctx, d.params)
}

// log must be called in a defer statement, invoked before any panic-able handler code
func (d *deferred[T]) log() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		return
	}
	d.completed = true

	// If neither Success() nor Failure() was called, treat as failure
	d.onFailure(d.ctx, d.params)
}

// PolicyCRUDEvent represents a policy CRUD audit event that will be logged
// as cancelled unless explicitly marked as success or failure
type PolicyCRUDEvent struct {
	*deferred[PolicyEventParams]
	params *PolicyEventParams // Store pointer for mutation
}

// RewrapEvent represents a rewrap audit event that will be logged
// as cancelled unless explicitly marked as success or failure
type RewrapEvent struct {
	*deferred[RewrapAuditEventParams]
}

// PolicyCRUD creates a deferred policy CRUD audit event.
// The event will be logged as cancelled unless Success() or Failure() is called.
// Usage:
//
//	auditEvent := logger.PolicyCRUD(ctx, params)
//	defer auditEvent.Log()
//	// ... perform operation ...
//	auditEvent.Success(updatedObject)
func (a *Logger) PolicyCRUD(ctx context.Context, params PolicyEventParams) *PolicyCRUDEvent {
	// Store a reference to params for mutation
	paramsCopy := params
	return &PolicyCRUDEvent{
		params: &paramsCopy,
		deferred: &deferred[PolicyEventParams]{
			ctx:    ctx,
			params: paramsCopy,
			onSuccess: func(ctx context.Context, p PolicyEventParams) {
				a.PolicyCRUDSuccess(ctx, p)
			},
			onFailure: func(ctx context.Context, p PolicyEventParams) {
				a.PolicyCRUDFailure(ctx, p)
			},
		},
	}
}

// Success marks the audit event as successful and logs it immediately.
// The updated parameter should contain the updated object state (can be nil for creates).
func (d *PolicyCRUDEvent) Success(updated proto.Message) {
	// Update the params with the updated object
	d.params.Updated = updated
	d.deferred.params = *d.params
	d.deferred.markSuccess()
}

// Failure marks the audit event as failed and logs it immediately.
func (d *PolicyCRUDEvent) Failure() {
	d.deferred.markFailure()
}

// Log should be called in a defer statement. If neither Success() nor Failure()
// was called, it will check the context for cancellation and log appropriately.
func (d *PolicyCRUDEvent) Log() {
	d.deferred.log()
}

// DeferRewrap creates a deferred rewrap audit event.
// The event will be logged as cancelled unless Success() or Failure() is called.
// Usage:
//
//	auditEvent := logger.DeferRewrap(ctx, params)
//	defer auditEvent.Log()
//	// ... perform operation ...
//	auditEvent.Success()
func (a *Logger) DeferRewrap(ctx context.Context, params RewrapAuditEventParams) *RewrapEvent {
	return &RewrapEvent{
		deferred: &deferred[RewrapAuditEventParams]{
			ctx:    ctx,
			params: params,
			onSuccess: func(ctx context.Context, p RewrapAuditEventParams) {
				a.RewrapSuccess(ctx, p)
			},
			onFailure: func(ctx context.Context, p RewrapAuditEventParams) {
				a.RewrapFailure(ctx, p)
			},
		},
	}
}

// Success marks the audit event as successful and logs it immediately.
func (d *RewrapEvent) Success() {
	d.deferred.markSuccess()
}

// Failure marks the audit event as failed and logs it immediately.
func (d *RewrapEvent) Failure() {
	d.deferred.markFailure()
}

// Log should be called in a defer statement. If neither Success() nor Failure()
// was called, it will check the context for cancellation and log appropriately.
func (d *RewrapEvent) Log() {
	d.deferred.log()
}
