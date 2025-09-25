package authorization

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/logger"
)

var (
	ErrFailedToRollupDecision    = errors.New("failed to rollup decision")
	ErrResponseSafeInternalError = errors.New("an unexpected error occurred")
	ErrNoDecisions               = errors.New("no decisions returned")
	ErrDecisionCannotBeNil       = errors.New("decision cannot be nil")
	ErrDecisionMustHaveResults   = errors.New("decision must have results")
)

// rollupMultiResourceDecisions creates a standardized response for multi-resource decisions
// by processing the decisions returned from the PDP.
func rollupMultiResourceDecisions(
	decisions []*access.Decision,
) ([]*authzV2.ResourceDecision, error) {
	if len(decisions) == 0 {
		return nil, errors.Join(ErrFailedToRollupDecision, ErrNoDecisions)
	}

	var resourceDecisions []*authzV2.ResourceDecision

	for idx, decision := range decisions {
		if decision == nil {
			return nil, errors.Join(ErrFailedToRollupDecision, fmt.Errorf("%w: index %d", ErrDecisionCannotBeNil, idx))
		}
		if len(decision.Results) == 0 {
			return nil, errors.Join(ErrFailedToRollupDecision, fmt.Errorf("%w: %+v", ErrDecisionMustHaveResults, decision))
		}
		for _, result := range decision.Results {
			access := authzV2.Decision_DECISION_DENY
			if result.Passed {
				access = authzV2.Decision_DECISION_PERMIT
			}
			resourceDecision := &authzV2.ResourceDecision{
				Decision:            access,
				EphemeralResourceId: result.ResourceID,
			}
			resourceDecisions = append(resourceDecisions, resourceDecision)
		}
	}

	return resourceDecisions, nil
}

// rollupSingleResourceDecision creates a standardized response for a single resource decision
// by processing the decision returned from the PDP.
func rollupSingleResourceDecision(
	permitted bool,
	decisions []*access.Decision,
) (*authzV2.GetDecisionResponse, error) {
	if len(decisions) == 0 {
		return nil, errors.Join(ErrFailedToRollupDecision, ErrNoDecisions)
	}

	decision := decisions[0]
	if decision == nil {
		return nil, errors.Join(ErrFailedToRollupDecision, ErrDecisionCannotBeNil)
	}

	if len(decision.Results) == 0 {
		return nil, errors.Join(ErrFailedToRollupDecision, fmt.Errorf("%w: %+v", ErrDecisionMustHaveResults, decision))
	}

	result := decision.Results[0]
	access := authzV2.Decision_DECISION_DENY
	if permitted {
		access = authzV2.Decision_DECISION_PERMIT
	}
	resourceDecision := &authzV2.ResourceDecision{
		Decision:            access,
		EphemeralResourceId: result.ResourceID,
	}
	return &authzV2.GetDecisionResponse{
		Decision: resourceDecision,
	}, nil
}

// Checks for known error types and returns standardized error codes and messages
func statusifyError(ctx context.Context, l *logger.Logger, err error, logs ...any) error {
	l = l.With("error", err.Error())
	if errors.Is(err, access.ErrFQNNotFound) {
		l.ErrorContext(ctx, "FQN not found", logs...)
		return connect.NewError(connect.CodeNotFound, err)
	}
	if errors.Is(err, access.ErrDefinitionNotFound) {
		l.ErrorContext(ctx, "definition not found", logs...)
		return connect.NewError(connect.CodeNotFound, err)
	}
	l.ErrorContext(ctx, "unexpected error", logs...)

	// Ensure error response is safe and does not leak internal information
	return connect.NewError(connect.CodeInternal, ErrResponseSafeInternalError)
}
