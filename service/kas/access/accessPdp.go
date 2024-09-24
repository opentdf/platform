package access

import (
	"context"
	"errors"
	"fmt"
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
Temporal Attribute:
The access pdp validates the temporal operator and their provided operands.
Each operand is a RFC 3339 formatted datetime string, such as "2024-11-05T12:00:00Z", or a duration in seconds.

Expected temporal attribute format: `/temporal/value/<operator>::<operand>::<...operand>`

  - 'after': Checks that the current time is after the provided datetime.
    ex: temporal/value/after::2024-11-05T12:00:00Z

  - 'before': Checks that the current time is before the provided datetime.
    ex: temporal/value/before::2024-11-05T12:00:00Z

  - 'duration': Checks that the current time is within the provided duration, starting at the provided datetime.
    ex: temporal/value/duration::2024-11-05T12:00:00Z::1h

  - 'between': Checks that the current time is between the provided start datetime and end datetime.
    ex: temporal/value/between::2024-11-04T12:00:00Z::2024-11-05T12:00:00Z
*/
func checkTemporalConditions(ctx context.Context, attributes []string, logger logger.Logger) (bool, error) {
	layout := time.RFC3339
	currentTime := time.Now().UTC()

	const (
		oneOperand  int = 1
		twoOperands int = 2
	)

	for _, attr := range attributes {
		operator, operands, err := parseTemporalAttribute(attr)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to parse temporal attribute", "attribute", attr, "err", err)
			return false, err
		}

		switch operator {
		case "after": // temporal/value/after::2024-11-05T12:00:00Z
			if len(operands) != oneOperand {
				return false, fmt.Errorf("temporal/after: invalid number of operands; operator expects one operand, %d received", len(operands))
			}
			afterTime, err := time.Parse(layout, operands[0])
			if err != nil {
				logger.ErrorContext(ctx, "temporal/after: invalid RFC3339 datetime format", "value", operands[0])
				return false, err
			}
			if currentTime.Compare(afterTime) >= 0 {
				logger.InfoContext(ctx, "temporal/after: access denied; current time is before 'after' time", "afterTime", afterTime)
				return false, nil // Access denied
			}

		case "before": // temporal/value/before::2024-11-05T12:00:00Z
			if len(operands) != oneOperand {
				return false, fmt.Errorf("temporal/before: invalid number of operands; operator expects one operand, %d received", len(operands))
			}
			beforeTime, err := time.Parse(layout, operands[0])
			if err != nil {
				logger.InfoContext(ctx, "temporal/before: invalid RFC3339 datetime format", "value", operands[0])
				return false, err
			}
			if currentTime.Compare(beforeTime) < 0 {
				logger.InfoContext(ctx, "temporal/before: access denied; current time is after 'before' time", "beforeTime", beforeTime)
				return false, nil // Access denied
			}

		case "duration": // temporal/value/duration::2024-11-05T12:00:00Z::1h
			if len(operands) != twoOperands {
				return false, fmt.Errorf("temporal/duration: invalid number of operands; operator expects two operands, %d received", len(operands))
			}
			startTime, err := time.Parse(layout, operands[0])
			if err != nil {
				logger.ErrorContext(ctx, "temporal/duration: invalid RFC3339 datetime format", "value", operands[0])
				return false, err
			}
			duration, err := time.ParseDuration(operands[1])
			if err != nil {
				logger.ErrorContext(ctx, "temporal/duration: invalid duration format", "value", operands[1])
				return false, err
			}
			endTime := startTime.Add(duration)
			if currentTime.Compare(startTime) >= 0 && currentTime.Compare(endTime) < 0 {
				logger.InfoContext(ctx, "temporal/duration: access denied; current time is not within the time window", "start", startTime, "end", endTime)
				return false, nil // Access denied
			}

		case "between": // temporal/value/between::2024-11-04T12:00:00Z::2024-11-05T12:00:00Z
			if len(operands) != twoOperands {
				return false, fmt.Errorf("temporal/between: invalid number of operands; operator expects two operands, %d received", len(operands))
			}
			startTime, err := time.Parse(layout, operands[0])
			if err != nil {
				logger.ErrorContext(ctx, "temporal/between: invalid RFC3339 datetime format", "startTime", operands[0])
				return false, err
			}
			endTime, err := time.Parse(layout, operands[1])
			if err != nil {
				logger.ErrorContext(ctx, "temporal/between: invalid RFC3339 datetime format", "endTime", operands[1])
				return false, err
			}
			if currentTime.Compare(startTime) >= 0 && currentTime.Compare(endTime) < 0 {
				logger.InfoContext(ctx, "temporal/between: access denied; current time is not within the time window", "start", startTime, "end", endTime)
				return false, nil
			}

		default:
			return false, fmt.Errorf("unknown temporal operator: %s", operator)
		}
	}
	// Conditions satisfied, access granted
	logger.InfoContext(ctx, "Access granted: all temporal conditions met")
	return true, nil
}

func isTemporalAttribute(uri string) bool {
	return strings.HasPrefix(uri, "/temporal/value/")
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
