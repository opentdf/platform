package authorization

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"connectrpc.com/connect"
	authzV2 "github.com/opentdf/platform/protocol/go/authorization/v2"
	"github.com/opentdf/platform/service/internal/access/v2"
	"github.com/opentdf/platform/service/logger"
)

var (
	ErrFailedToRollupDecision    = errors.New("failed to rollup decision")
	ErrResponseSafeInternalError = errors.New("an unexpected error occurred")
	ErrDecisionCannotBeNil       = errors.New("decision cannot be nil")
	ErrDecisionMustHaveResults   = errors.New("decision must have results")
)

// rollupResourceDecisions creates a standardized response for multi-resource decisions
// by processing the decision returned from the PDP.
func rollupResourceDecisions(
	decision *access.Decision,
) ([]*authzV2.ResourceDecision, error) {
	if decision == nil {
		return nil, errors.Join(ErrFailedToRollupDecision, ErrDecisionCannotBeNil)
	}
	if len(decision.Results) == 0 {
		return nil, errors.Join(ErrFailedToRollupDecision, fmt.Errorf("%w: %+v", ErrDecisionMustHaveResults, decision))
	}

	resourceDecisions := make([]*authzV2.ResourceDecision, len(decision.Results))
	for idx, result := range decision.Results {
		access := authzV2.Decision_DECISION_DENY
		if result.Passed {
			access = authzV2.Decision_DECISION_PERMIT
		}
		resourceDecision := &authzV2.ResourceDecision{
			Decision:            access,
			EphemeralResourceId: result.ResourceID,
			RequiredObligations: result.RequiredObligationValueFQNs,
		}
		resourceDecisions[idx] = resourceDecision
	}

	return resourceDecisions, nil
}

// Checks for known error types and returns standardized error codes and messages
func statusifyError(ctx context.Context, l *logger.Logger, err error, logs ...any) error {
	logs = append(logs, slog.Any("error", err))
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
