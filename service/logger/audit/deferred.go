/*
`audit` provides event logging for ABAC control operations.

# Why Deferred Audit Events?

Continuous monitoring of access events is one component of the zero trust paradigm.

Deferred audit events provide a fail-safe mechanism to ensure that all operations are audited,
even when errors, timeouts, and client connection cancellations occur during processing.
This library uses go's `defer“ mechanism and explicit success/failure signal calls,
which allows services to log all operations with the appropriate outcome.

## A Note: Panicking and Errors

> A key goal of OpenTDF is to enable zero trust systems,
> so failures to properly log events block system functionality.

# Basic Usage Pattern

All deferred audit events follow a consistent three-step pattern:

1. Create the audit event with initial parameters
2. Register it with defer to ensure it's logged even on panic/error
3. Mark success or failure when the operation completes

# Example: Rewrap Operation

	func handleRewrap(ctx context.Context, logger *audit.Logger) error {
		// Step 1: Create the deferred audit event with initial parameters
		auditEvent := logger.Audit.Rewrap(ctx, audit.RewrapAuditEventParams{
			Policy:        kasPolicy,
			TDFFormat:     "tdf3",
			Algorithm:     "rsa-2048",
			PolicyBinding: "binding-hash",
			KeyID:         "key-123",
		})

		// Step 2: Register with defer - guarantees logging even on panic
		defer auditEvent.Log(ctx)

		// Step 3: Perform the rewrap operation (may panic)
		result, err := performRewrap(ctx)
		if err != nil {
			// On error, return without calling Success()
			// The deferred Log() will record this as a failure
			return err
		}

		// Step 4: Update event with additional details as they become available
		auditEvent.UpdatePolicy(enrichedPolicy)

		// Step 5: Mark the operation as successful
		auditEvent.Success(ctx)
		return nil
	}

# Example: Policy CRUD Operation

	func updateAttribute(ctx context.Context, logger *audit.Logger, id string, req *UpdateRequest) error {
		// Create audit event with known parameters
		auditEvent := logger.Audit.PolicyCRUD(ctx, audit.PolicyEventParams{
			ActionType: audit.ActionTypeUpdate,
			ObjectType: audit.ObjectTypeAttributeDefinition,
			ObjectID:   id,
		})
		defer auditEvent.Log(ctx)

		// Load the original object
		original, err := loadAttribute(id)
		if err != nil {
			return err
		}

		// Update the event with the original state
		auditEvent.UpdateOriginal(original)

		// Apply updates
		updated, err := applyUpdates(original, req)
		if err != nil {
			// Log will record this as a failure
			return err
		}

		// Persist the changes
		if err := saveAttribute(updated); err != nil {
			return err
		}

		// Mark success with the updated object
		auditEvent.Success(ctx, updated)
		return nil
	}

# Progressive Enrichment

For operations that compute results progressively, events can be enriched as
information becomes available using UpdateX methods:

	auditEvent := logger.Audit.Decision(ctx, entityChainID, resourceAttrID, fqns)
	defer auditEvent.Log(ctx)

	// Enrich with entitlements as they're computed
	entitlements := computeEntitlements()
	auditEvent.UpdateEntitlements(entitlements)

	// Enrich with entity decisions
	decisions := evaluateEntities()
	auditEvent.UpdateEntityDecisions(decisions)

	// Finally, record the outcome
	auditEvent.Success(ctx, finalDecision)

# No Updates After Completion

Once an event is completed
(by calling Success(), Failure(), or allowing Log() to execute),
the event is immutable.
Attempting to call any UpdateX methods after completion will panic with ErrAlreadyCompleted.

	auditEvent := logger.Audit.DecisionV2(ctx, entityID, actionName)
	defer auditEvent.Log(ctx)

	auditEvent.Success(ctx, decision) // Event is now completed

	// THIS WILL PANIC:
	auditEvent.UpdateEntitlements(newEntitlements)

# Fail-Safe Default Behavior

If neither Success() nor Failure() is explicitly called,
the deferred Log() function will record the operation as failed.

- Rewrap: Logged as failure if Success() not called
- PolicyCRUD: Logged as failure/cancelled if Success() not called
- Decision operations: Logged with DENY decision if Success() not called
*/
package audit

import (
	"context"
	"errors"
	"sync"

	"github.com/opentdf/platform/protocol/go/policy"
	"google.golang.org/protobuf/proto"
)

var ErrAlreadyCompleted = errors.New("cannot update entitlements after event is completed")

// deferred is the generic deferred audit implementation
type deferred[T any] struct {
	params        T
	onSuccess     func(context.Context, T)
	onFailure     func(context.Context, T)
	mu            sync.Mutex
	completed     bool
	successCalled bool
}

// markSuccess marks the event as successful (without logging yet)
func (d *deferred[T]) markSuccess(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		return
	}
	d.successCalled = true
	d.completed = true
	d.onSuccess(ctx, d.params)
}

// markFailure marks the event as failed (without logging yet)
func (d *deferred[T]) markFailure(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		return
	}
	d.completed = true
	d.onFailure(ctx, d.params)
}

// log must be called in a defer statement, invoked before any panic-able handler code
func (d *deferred[T]) log(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		return
	}
	d.completed = true

	// If neither Success() nor Failure() was called, treat as failure
	d.onFailure(ctx, d.params)
}

// PolicyCRUDEvent represents a policy CRUD audit event that will be logged
// as cancelled unless explicitly marked as success or failure
type PolicyCRUDEvent struct {
	*deferred[PolicyEventParams]
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
}

// GetDecisionV2Event represents a GetDecisionV2 audit event that will be logged
// as a deny decision unless explicitly marked with a final decision
type GetDecisionV2Event struct {
	*deferred[GetDecisionV2EventParams]
}

// PolicyCRUD creates a deferred policy CRUD audit event.
// The event will be logged as cancelled unless Success() or Failure() is called.
// Usage:
//
//	auditEvent := logger.PolicyCRUD(ctx, params)
//	defer auditEvent.Log(ctx)
//	// ... perform operation ...
//	auditEvent.Success(ctx, updatedObject)
func (a *Logger) PolicyCRUD(ctx context.Context, params PolicyEventParams) *PolicyCRUDEvent {
	if _, ok := ctx.Value(contextKey{}).(*auditTransaction); !ok {
		panic("audit transaction missing from context in PolicyCRUD")
	}

	return &PolicyCRUDEvent{
		deferred: &deferred[PolicyEventParams]{
			params: params,
			onSuccess: func(ctx context.Context, p PolicyEventParams) {
				a.PolicyCRUDSuccess(ctx, p)
			},
			onFailure: func(ctx context.Context, p PolicyEventParams) {
				a.PolicyCRUDFailure(ctx, p)
			},
		},
	}
}

// UpdateOriginal updates the original object state as it becomes available.
// This should be called after the event is created if the original object wasn't available at creation time.
func (d *PolicyCRUDEvent) UpdateOriginal(original proto.Message) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		panic(ErrAlreadyCompleted)
	}

	d.params.Original = original
}

// UpdateObjectID updates the object ID as it becomes available.
// This should be called after the event is created if the object ID wasn't available at creation time.
func (d *PolicyCRUDEvent) UpdateObjectID(objectID string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		panic(ErrAlreadyCompleted)
	}

	d.params.ObjectID = objectID
}

// Success marks the audit event as successful and logs it immediately.
// The updated parameter should contain the updated object state (can be nil for creates).
func (d *PolicyCRUDEvent) Success(ctx context.Context, updated proto.Message) {
	d.mu.Lock()
	// Update the params with the updated object
	d.params.Updated = updated
	d.mu.Unlock()

	d.markSuccess(ctx)
}

// Failure marks the audit event as failed and logs it immediately.
func (d *PolicyCRUDEvent) Failure(ctx context.Context) {
	d.markFailure(ctx)
}

// Log should be called in a defer statement. If neither Success() nor Failure()
// was called, it will check the context for cancellation and log appropriately.
func (d *PolicyCRUDEvent) Log(ctx context.Context) {
	d.log(ctx)
}

// Rewrap creates a deferred rewrap audit event.
// The event will be logged as cancelled unless Success() or Failure() is called.
// Usage:
//
//	auditEvent := logger.Rewrap(ctx, params)
//	defer auditEvent.Log(ctx)
//	// ... perform operation ...
//	auditEvent.Success(ctx)
func (a *Logger) Rewrap(ctx context.Context, params RewrapAuditEventParams) *RewrapEvent {
	if _, ok := ctx.Value(contextKey{}).(*auditTransaction); !ok {
		panic("audit transaction missing from context in Rewrap")
	}

	return &RewrapEvent{
		deferred: &deferred[RewrapAuditEventParams]{
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

func (d *RewrapEvent) UpdatePolicy(kasPolicy KasPolicy) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		panic(ErrAlreadyCompleted)
	}

	d.params.Policy = kasPolicy
}

// Success marks the audit event as successful and logs it immediately.
func (d *RewrapEvent) Success(ctx context.Context) {
	d.markSuccess(ctx)
}

// Failure marks the audit event as failed and logs it immediately.
func (d *RewrapEvent) Failure(ctx context.Context) {
	d.markFailure(ctx)
}

// Log should be called in a defer statement. If neither Success() nor Failure()
// was called, it will check the context for cancellation and log appropriately.
func (d *RewrapEvent) Log(ctx context.Context) {
	d.log(ctx)
}

// Decision creates a deferred GetDecision audit event.
// The event will be logged with a deny decision unless Success() is called with the actual decision.
// Usage:
//
//	auditEvent := logger.Audit.Decision(ctx, entityChainID, resourceAttributeID, fqns)
//	defer auditEvent.Log(ctx)
//	// ... perform operation, enriching with UpdateEntitlements/UpdateEntityDecisions ...
//	auditEvent.Success(ctx, decision)
func (a *Logger) Decision(ctx context.Context, entityChainID string, resourceAttributeID string, fqns []string) *GetDecisionEvent {
	if _, ok := ctx.Value(contextKey{}).(*auditTransaction); !ok {
		panic("audit transaction missing from context in Decision")
	}

	params := GetDecisionEventParams{
		Decision:                GetDecisionResultDeny, // Default to deny on cancellation
		EntityChainID:           entityChainID,
		ResourceAttributeID:     resourceAttributeID,
		FQNs:                    fqns,
		EntityChainEntitlements: []EntityChainEntitlement{},
		EntityDecisions:         []EntityDecision{},
	}

	return &GetDecisionEvent{
		deferred: &deferred[GetDecisionEventParams]{
			params: params,
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
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		panic(ErrAlreadyCompleted)
	}

	d.params.EntityChainEntitlements = entitlements
}

// UpdateEntityDecisions updates the entity decisions as they are computed
func (d *GetDecisionEvent) UpdateEntityDecisions(decisions []EntityDecision) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		panic(ErrAlreadyCompleted)
	}

	d.params.EntityDecisions = decisions
}

// Success marks the audit event with the final decision and logs it immediately.
func (d *GetDecisionEvent) Success(ctx context.Context, decision DecisionResult) {
	d.params.Decision = decision
	d.markSuccess(ctx)
}

// Failure marks the audit event as failed (logs with deny decision)
func (d *GetDecisionEvent) Failure(ctx context.Context) {
	d.markFailure(ctx)
}

// Log should be called in a defer statement. If neither Success() nor Failure()
// was called, it will log with a deny decision.
func (d *GetDecisionEvent) Log(ctx context.Context) {
	d.log(ctx)
}

// DecisionV2 creates a deferred GetDecisionV2 audit event.
// The event will be logged with a deny decision unless Success() is called with the actual decision.
// Usage:
//
//	auditEvent := logger.Audit.DecisionV2(ctx, entityID, actionName)
//	defer auditEvent.Log(ctx)
//	// ... perform operation, enriching with UpdateEntitlements/UpdateResourceDecisions/UpdateObligations ...
//	auditEvent.Success(ctx, decision)
func (a *Logger) DecisionV2(ctx context.Context, entityID string, actionName string) *GetDecisionV2Event {
	if _, ok := ctx.Value(contextKey{}).(*auditTransaction); !ok {
		panic("audit transaction missing from context in DecisionV2")
	}

	params := GetDecisionV2EventParams{
		EntityID:                       entityID,
		ActionName:                     actionName,
		Decision:                       GetDecisionResultDeny, // Default to deny on cancellation
		Entitlements:                   make(map[string][]*policy.Action),
		FulfillableObligationValueFQNs: []string{},
		ObligationsSatisfied:           false,
		ResourceDecisions:              nil,
	}

	return &GetDecisionV2Event{
		deferred: &deferred[GetDecisionV2EventParams]{
			params: params,
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
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		panic(ErrAlreadyCompleted)
	}

	d.params.Entitlements = entitlements
}

// UpdateResourceDecisions updates the resource decisions as they are computed
func (d *GetDecisionV2Event) UpdateResourceDecisions(resourceDecisions any) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		panic(ErrAlreadyCompleted)
	}

	d.params.ResourceDecisions = resourceDecisions
}

// UpdateObligations updates the obligation information as it is computed
func (d *GetDecisionV2Event) UpdateObligations(fulfillable []string, satisfied bool) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		panic(ErrAlreadyCompleted)
	}

	d.params.FulfillableObligationValueFQNs = fulfillable
	d.params.ObligationsSatisfied = satisfied
}

func (d *GetDecisionV2Event) UpdateDecisionResult(_ context.Context, decision DecisionResult) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.completed {
		panic(ErrAlreadyCompleted)
	}

	d.params.Decision = decision
}

// Success marks the audit event as successful with the final decision and logs it immediately.
func (d *GetDecisionV2Event) Success(ctx context.Context, decision DecisionResult) {
	d.UpdateDecisionResult(ctx, decision)
	d.markSuccess(ctx)
}

// Failure marks the audit event as failed (logs with deny decision)
func (d *GetDecisionV2Event) Failure(ctx context.Context) {
	d.markFailure(ctx)
}

// Log should be called in a defer statement. If neither Success() nor Failure()
// was called, it will log with a deny decision.
func (d *GetDecisionV2Event) Log(ctx context.Context) {
	d.log(ctx)
}
