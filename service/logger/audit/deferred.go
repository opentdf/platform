package audit

import (
	"context"
	"sync"

	"github.com/opentdf/platform/protocol/go/policy"
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

// GetDecisionEvent represents a GetDecision audit event that will be logged
// as a deny decision unless explicitly marked with a final decision
type GetDecisionEvent struct {
	*deferred[GetDecisionEventParams]
	params *GetDecisionEventParams // Store pointer for mutation
}

// GetDecisionV2Event represents a GetDecisionV2 audit event that will be logged
// as a deny decision unless explicitly marked with a final decision
type GetDecisionV2Event struct {
	*deferred[GetDecisionV2EventParams]
	params *GetDecisionV2EventParams // Store pointer for mutation
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

// Decision creates a deferred GetDecision audit event.
// The event will be logged with a deny decision unless Success() is called with the actual decision.
// Usage:
//
//	auditEvent := logger.Audit.Decision(ctx, entityChainID, resourceAttributeID, fqns)
//	defer auditEvent.Log()
//	// ... perform operation, enriching with UpdateEntitlements/UpdateEntityDecisions ...
//	auditEvent.Success(decision)
func (a *Logger) Decision(ctx context.Context, entityChainID string, resourceAttributeID string, fqns []string) *GetDecisionEvent {
	params := GetDecisionEventParams{
		Decision:                GetDecisionResultDeny, // Default to deny on cancellation
		EntityChainID:           entityChainID,
		ResourceAttributeID:     resourceAttributeID,
		FQNs:                    fqns,
		EntityChainEntitlements: []EntityChainEntitlement{},
		EntityDecisions:         []EntityDecision{},
	}
	paramsCopy := params

	return &GetDecisionEvent{
		params: &paramsCopy,
		deferred: &deferred[GetDecisionEventParams]{
			ctx:    ctx,
			params: paramsCopy,
			onSuccess: func(ctx context.Context, p GetDecisionEventParams) {
				a.getDecisionBase(ctx, p)
			},
			onFailure: func(ctx context.Context, p GetDecisionEventParams) {
				// On failure/cancellation, log with deny decision (already set in params)
				a.getDecisionBase(ctx, p)
			},
		},
	}
}

// UpdateEntitlements updates the entity chain entitlements as they are computed
func (d *GetDecisionEvent) UpdateEntitlements(entitlements []EntityChainEntitlement) {
	d.params.EntityChainEntitlements = entitlements
	d.deferred.params.EntityChainEntitlements = entitlements
}

// UpdateEntityDecisions updates the entity decisions as they are computed
func (d *GetDecisionEvent) UpdateEntityDecisions(decisions []EntityDecision) {
	d.params.EntityDecisions = decisions
	d.deferred.params.EntityDecisions = decisions
}

// Success marks the audit event with the final decision and logs it immediately.
func (d *GetDecisionEvent) Success(decision DecisionResult) {
	d.params.Decision = decision
	d.deferred.params = *d.params
	d.deferred.markSuccess()
}

// Failure marks the audit event as failed (logs with deny decision)
func (d *GetDecisionEvent) Failure() {
	d.deferred.markFailure()
}

// Log should be called in a defer statement. If neither Success() nor Failure()
// was called, it will log with a deny decision.
func (d *GetDecisionEvent) Log() {
	d.deferred.log()
}

// DecisionV2 creates a deferred GetDecisionV2 audit event.
// The event will be logged with a deny decision unless Success() is called with the actual decision.
// Usage:
//
//	auditEvent := logger.Audit.DecisionV2(ctx, entityID, actionName)
//	defer auditEvent.Log()
//	// ... perform operation, enriching with UpdateEntitlements/UpdateResourceDecisions/UpdateObligations ...
//	auditEvent.Success(decision)
func (a *Logger) DecisionV2(ctx context.Context, entityID string, actionName string) *GetDecisionV2Event {
	params := GetDecisionV2EventParams{
		EntityID:                       entityID,
		ActionName:                     actionName,
		Decision:                       GetDecisionResultDeny, // Default to deny on cancellation
		Entitlements:                   make(map[string][]*policy.Action),
		FulfillableObligationValueFQNs: []string{},
		ObligationsSatisfied:           false,
		ResourceDecisions:              nil,
	}
	paramsCopy := params

	return &GetDecisionV2Event{
		params: &paramsCopy,
		deferred: &deferred[GetDecisionV2EventParams]{
			ctx:    ctx,
			params: paramsCopy,
			onSuccess: func(ctx context.Context, p GetDecisionV2EventParams) {
				a.getDecisionV2Base(ctx, p)
			},
			onFailure: func(ctx context.Context, p GetDecisionV2EventParams) {
				// On failure/cancellation, log with deny decision (already set in params)
				a.getDecisionV2Base(ctx, p)
			},
		},
	}
}

// UpdateEntitlements updates the entitlements as they are computed
func (d *GetDecisionV2Event) UpdateEntitlements(entitlements map[string][]*policy.Action) {
	d.params.Entitlements = entitlements
	d.deferred.params.Entitlements = entitlements
}

// UpdateResourceDecisions updates the resource decisions as they are computed
func (d *GetDecisionV2Event) UpdateResourceDecisions(resourceDecisions any) {
	d.params.ResourceDecisions = resourceDecisions
	d.deferred.params.ResourceDecisions = resourceDecisions
}

// UpdateObligations updates the obligation information as it is computed
func (d *GetDecisionV2Event) UpdateObligations(fulfillable []string, satisfied bool) {
	d.params.FulfillableObligationValueFQNs = fulfillable
	d.params.ObligationsSatisfied = satisfied
	d.deferred.params.FulfillableObligationValueFQNs = fulfillable
	d.deferred.params.ObligationsSatisfied = satisfied
}

// Success marks the audit event with the final decision and logs it immediately.
func (d *GetDecisionV2Event) Success(decision DecisionResult) {
	d.params.Decision = decision
	d.deferred.params = *d.params
	d.deferred.markSuccess()
}

// Failure marks the audit event as failed (logs with deny decision)
func (d *GetDecisionV2Event) Failure() {
	d.deferred.markFailure()
}

// Log should be called in a defer statement. If neither Success() nor Failure()
// was called, it will log with a deny decision.
func (d *GetDecisionV2Event) Log() {
	d.deferred.log()
}
