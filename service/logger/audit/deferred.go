package audit

import (
	"context"
	"sync"

	"google.golang.org/protobuf/proto"
)

// DeferredPolicyAudit represents a policy CRUD audit event that will be logged
// as cancelled unless explicitly marked as success or failure
type DeferredPolicyAudit struct {
	logger    *Logger
	ctx       context.Context
	params    PolicyEventParams
	mu        sync.Mutex
	completed bool
}

// DeferredRewrapAudit represents a rewrap audit event that will be logged
// as cancelled unless explicitly marked as success or failure
type DeferredRewrapAudit struct {
	logger    *Logger
	ctx       context.Context
	params    RewrapAuditEventParams
	mu        sync.Mutex
	completed bool
}

// DeferPolicyCRUD creates a deferred policy CRUD audit event.
// The event will be logged as cancelled unless Success() or Failure() is called.
// Usage:
//   auditEvent := logger.DeferPolicyCRUD(ctx, params)
//   defer auditEvent.Log()
//   // ... perform operation ...
//   auditEvent.Success(updatedObject)
func (a *Logger) DeferPolicyCRUD(ctx context.Context, params PolicyEventParams) *DeferredPolicyAudit {
	return &DeferredPolicyAudit{
		logger:    a,
		ctx:       ctx,
		params:    params,
		completed: false,
	}
}

// Success marks the audit event as successful and logs it immediately.
// The updated parameter should contain the updated object state (can be nil for creates).
func (d *DeferredPolicyAudit) Success(updated proto.Message) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		return
	}
	d.completed = true

	d.params.Updated = updated
	d.logger.PolicyCRUDSuccess(d.ctx, d.params)
}

// Failure marks the audit event as failed and logs it immediately.
func (d *DeferredPolicyAudit) Failure() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		return
	}
	d.completed = true

	d.logger.PolicyCRUDFailure(d.ctx, d.params)
}

// Log should be called in a defer statement. If neither Success() nor Failure()
// was called, it will check the context for cancellation and log appropriately.
func (d *DeferredPolicyAudit) Log() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		return
	}
	d.completed = true

	// Check if context was cancelled
	if err := d.ctx.Err(); err != nil {
		// Context was cancelled - this will be logged as cancelled by the interceptor
		d.logger.PolicyCRUDFailure(d.ctx, d.params)
	} else {
		// No explicit success/failure and no context cancellation - treat as failure
		d.logger.PolicyCRUDFailure(d.ctx, d.params)
	}
}

// DeferRewrap creates a deferred rewrap audit event.
// The event will be logged as cancelled unless Success() or Failure() is called.
// Usage:
//   auditEvent := logger.DeferRewrap(ctx, params)
//   defer auditEvent.Log()
//   // ... perform operation ...
//   auditEvent.Success()
func (a *Logger) DeferRewrap(ctx context.Context, params RewrapAuditEventParams) *DeferredRewrapAudit {
	return &DeferredRewrapAudit{
		logger:    a,
		ctx:       ctx,
		params:    params,
		completed: false,
	}
}

// Success marks the audit event as successful and logs it immediately.
func (d *DeferredRewrapAudit) Success() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		return
	}
	d.completed = true

	d.logger.RewrapSuccess(d.ctx, d.params)
}

// Failure marks the audit event as failed and logs it immediately.
func (d *DeferredRewrapAudit) Failure() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		return
	}
	d.completed = true

	d.logger.RewrapFailure(d.ctx, d.params)
}

// Log should be called in a defer statement. If neither Success() nor Failure()
// was called, it will check the context for cancellation and log appropriately.
func (d *DeferredRewrapAudit) Log() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		return
	}
	d.completed = true

	// Check if context was cancelled
	if err := d.ctx.Err(); err != nil {
		// Context was cancelled - this will be logged as cancelled by the interceptor
		d.logger.RewrapFailure(d.ctx, d.params)
	} else {
		// No explicit success/failure and no context cancellation - treat as failure
		d.logger.RewrapFailure(d.ctx, d.params)
	}
}
