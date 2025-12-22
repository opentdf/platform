package audit

import (
	"context"
	"sync"

	"google.golang.org/protobuf/proto"
)

// deferredAudit is the generic deferred audit implementation
type deferredAudit[T any] struct {
	ctx           context.Context
	params        T
	onSuccess     func(context.Context, T)
	onFailure     func(context.Context, T)
	mu            sync.Mutex
	completed     bool
	successCalled bool
}

// markSuccess marks the event as successful (without logging yet)
func (d *deferredAudit[T]) markSuccess() {
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
func (d *deferredAudit[T]) markFailure() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		return
	}
	d.completed = true
	d.onFailure(d.ctx, d.params)
}

// log should be called in a defer statement
func (d *deferredAudit[T]) log() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		return
	}
	d.completed = true

	// If neither Success() nor Failure() was called, treat as failure
	d.onFailure(d.ctx, d.params)
}

// DeferredPolicyAudit represents a policy CRUD audit event that will be logged
// as cancelled unless explicitly marked as success or failure
type DeferredPolicyAudit struct {
	inner  *deferredAudit[PolicyEventParams]
	params *PolicyEventParams // Store pointer for mutation
}

// DeferredRewrapAudit represents a rewrap audit event that will be logged
// as cancelled unless explicitly marked as success or failure
type DeferredRewrapAudit struct {
	inner *deferredAudit[RewrapAuditEventParams]
}

// DeferPolicyCRUD creates a deferred policy CRUD audit event.
// The event will be logged as cancelled unless Success() or Failure() is called.
// Usage:
//
//	auditEvent := logger.DeferPolicyCRUD(ctx, params)
//	defer auditEvent.Log()
//	// ... perform operation ...
//	auditEvent.Success(updatedObject)
func (a *Logger) DeferPolicyCRUD(ctx context.Context, params PolicyEventParams) *DeferredPolicyAudit {
	// Store a reference to params for mutation
	paramsCopy := params
	return &DeferredPolicyAudit{
		params: &paramsCopy,
		inner: &deferredAudit[PolicyEventParams]{
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
func (d *DeferredPolicyAudit) Success(updated proto.Message) {
	// Update the params with the updated object
	d.params.Updated = updated
	d.inner.params = *d.params
	d.inner.markSuccess()
}

// Failure marks the audit event as failed and logs it immediately.
func (d *DeferredPolicyAudit) Failure() {
	d.inner.markFailure()
}

// Log should be called in a defer statement. If neither Success() nor Failure()
// was called, it will check the context for cancellation and log appropriately.
func (d *DeferredPolicyAudit) Log() {
	d.inner.log()
}

// DeferRewrap creates a deferred rewrap audit event.
// The event will be logged as cancelled unless Success() or Failure() is called.
// Usage:
//
//	auditEvent := logger.DeferRewrap(ctx, params)
//	defer auditEvent.Log()
//	// ... perform operation ...
//	auditEvent.Success()
func (a *Logger) DeferRewrap(ctx context.Context, params RewrapAuditEventParams) *DeferredRewrapAudit {
	return &DeferredRewrapAudit{
		inner: &deferredAudit[RewrapAuditEventParams]{
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
func (d *DeferredRewrapAudit) Success() {
	d.inner.markSuccess()
}

// Failure marks the audit event as failed and logs it immediately.
func (d *DeferredRewrapAudit) Failure() {
	d.inner.markFailure()
}

// Log should be called in a defer statement. If neither Success() nor Failure()
// was called, it will check the context for cancellation and log appropriately.
func (d *DeferredRewrapAudit) Log() {
	d.inner.log()
}
