package access

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/policy"
	otdf "github.com/opentdf/platform/sdk"
	"github.com/opentdf/platform/service/logger"
)

const (
	ErrPolicyDissemInvalid     = Error("policy dissem invalid")
	ErrDecisionUnexpected      = Error("authorization decision unexpected")
	ErrDecisionCountUnexpected = Error("authorization decision count unexpected")
)

func canAccess(ctx context.Context, token *authorization.Token, policy Policy, sdk *otdf.SDK, logger logger.Logger) (bool, error) {
	if len(policy.Body.Dissem) > 0 {
		// TODO: Move dissems check to the getdecisions endpoint
		logger.Error("Dissems check is not enabled in v2 platform kas")
	}
	if policy.Body.DataAttributes != nil {
		attrAccess, err := checkAttributes(ctx, policy.Body.DataAttributes, token, sdk, logger)
		if err != nil {
			return false, err
		}
		return attrAccess, nil
	}
	// if no dissem and no attributes then allow
	return true, nil
}

func parseTemporalAttribute(attribute string) (string, []string, error) {
	// e.g. "temporal/value/after::2024-11-05T12:00:00Z"
	const minParts = 2
	parts := strings.Split(attribute, "::")
	if len(parts) < minParts {
		return "", nil, fmt.Errorf("invalid temporal attribute format")
	}
	operator := parts[0]
	operands := parts[1:]
	return operator, operands, nil
}

/*
If the temporal attribute is provided, validates the operators and their corresponding dates.
Each operator checks specific conditions using ISO 8601 formatted datetime strings,
such as "2024-11-05T12:00:00Z".

Expects attributes in the form `/temporal/value/<operator>::<operand1>::<operand2>...`

- 'after': Checks that the current time is after the provided datetime.

- 'before': Checks that the current time is before the provided datetime.

- 'duration': Checks that the current time falls within a duration starting at a specific datetime.

- 'contains': Verifies that the current time is within a specific start and end datetime window.
*/
func checkTemporalConditions(ctx context.Context, attributes []string, logger logger.Logger) (bool, error) {
	layout := time.RFC3339 // Support ISO 8601 datetime strings, e.g. "2024-11-05T12:00:00Z"
	currentTime := time.Now().UTC()

	for _, attr := range attributes {
		operator, operands, err := parseTemporalAttribute(attr)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to parse temporal attribute", "attribute", attr, "err", err)
			return false, err
		}

		switch operator {
		case "after": // temporal/value/after::2024-11-05T12:00:00Z
			if len(operands) != 1 {
				return false, fmt.Errorf("invalid operands for 'after'")
			}

			afterTime, err := time.Parse(layout, operands[0])
			if err != nil {
				logger.ErrorContext(ctx, "invalid 'after' datetime format", "value", operands[0])
				return false, err
			}
			if currentTime.Before(afterTime) {
				logger.InfoContext(ctx, "Access denied: current time is before allowed 'after' time", "notBefore", afterTime)
				return false, nil // Access denied
			}

		case "before": // temporal/value/before::2024-11-05T12:00:00Z
			if len(operands) != 1 {
				return false, fmt.Errorf("invalid operands for 'before'")
			}
			beforeTime, err := time.Parse(layout, operands[0])
			if err != nil {
				logger.InfoContext(ctx, "invalid 'before' datetime format", "value", operands[0])
				return false, err
			}
			if currentTime.After(beforeTime) {
				logger.InfoContext(ctx, "Access denied: current time is after allowed 'before' time", "notAfter", beforeTime)
				return false, nil // Access denied
			}
		case "duration": // temporal/value/duration::2024-11-05T12:00:00Z::3600 (3600 seconds = 1 hour duration)
			if len(operands) != 2 {
				return false, fmt.Errorf("invalid operands for 'duration'")
			}

			startTime, err := time.Parse(layout, operands[0])
			if err != nil {
				logger.ErrorContext(ctx, "Invalid 'duration' start time format", "startTime", operands[0])
				return false, err
			}
			durationSeconds, err := strconv.ParseInt(operands[1], 10, 64)
			if err != nil {
				logger.ErrorContext(ctx, "Invalid 'duration' seconds format", "durationSeconds", operands[1])
				return false, err
			}
			endTime := startTime.Add(time.Duration(durationSeconds) * time.Second)
			if currentTime.Before(startTime) || currentTime.After(endTime) {
				logger.InfoContext(ctx, "Access denied: current time not within duration", "start", startTime, "end", endTime)
				return false, nil // Access denied
			}
		case "contains": // temporal/value/contains::2024-11-04T12:00:00Z::2024-11-05T12:00:00Z
			if len(operands) != 2 {
				return false, fmt.Errorf("invalid operands for 'contains'")
			}
			startTime, err := time.Parse(layout, operands[0])
			if err != nil {
				logger.ErrorContext(ctx, "Invalid 'contains' start time format", "startTime", operands[0])
				return false, err
			}
			endTime, err := time.Parse(layout, operands[1])
			if err != nil {
				logger.ErrorContext(ctx, "Invalid 'contains' end time format", "endTime", operands[1])
				return false, err
			}
			if currentTime.Before(startTime) || currentTime.After(endTime) {
				logger.InfoContext(ctx, "Access denied: current time not contained within time window", "start", startTime, "end", endTime)
				return false, nil
			}

		default:
			return false, fmt.Errorf("unknown operator: %s", operator)
		}
	}
	// Conditions satisfied, access granted
	logger.InfoContext(ctx, "Access granted: all temporal conditions met")
	return true, nil
}

func isTemporalAttribute(uri string) bool {
	const TemporalAttrURI = "/temporal/value/"
	return strings.HasPrefix(uri, TemporalAttrURI)
}

func checkAttributes(ctx context.Context, dataAttrs []Attribute, ent *authorization.Token, sdk *otdf.SDK, logger logger.Logger) (bool, error) {
	var temporalAttributes []string
	ras := []*authorization.ResourceAttribute{{
		AttributeValueFqns: make([]string, 0),
	}}

	for _, attr := range dataAttrs {
		// Check for /temporal attribute and validate
		if isTemporalAttribute(attr.URI) {
			temporalAttributes = append(temporalAttributes, attr.URI)
		} else {
			ras[0].AttributeValueFqns = append(ras[0].GetAttributeValueFqns(), attr.URI)
		}
	}
	if len(temporalAttributes) > 0 {
		isValid, err := checkTemporalConditions(ctx, temporalAttributes, logger)
		if err != nil {
			return false, err
		}
		if !isValid {
			return false, nil
		}
	}

	in := authorization.GetDecisionsByTokenRequest{
		DecisionRequests: []*authorization.TokenDecisionRequest{
			{
				Actions: []*policy.Action{
					{Value: &policy.Action_Standard{Standard: policy.Action_STANDARD_ACTION_DECRYPT}},
				},
				Tokens:             []*authorization.Token{ent},
				ResourceAttributes: ras,
			},
		},
	}
	dr, err := sdk.Authorization.GetDecisionsByToken(ctx, &in)
	if err != nil {
		logger.ErrorContext(ctx, "Error received from GetDecisionsByToken", "err", err)
		return false, errors.Join(ErrDecisionUnexpected, err)
	}
	if len(dr.GetDecisionResponses()) != 1 {
		logger.ErrorContext(ctx, ErrDecisionCountUnexpected.Error(), "count", len(dr.GetDecisionResponses()))
		return false, ErrDecisionCountUnexpected
	}
	if dr.GetDecisionResponses()[0].GetDecision() == authorization.DecisionResponse_DECISION_PERMIT {
		return true, nil
	}
	return false, nil
}
