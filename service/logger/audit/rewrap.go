package audit

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type KasPolicy struct {
	UUID uuid.UUID
	Body KasPolicyBody
}
type KasPolicyBody struct {
	DataAttributes []KasAttribute
	Dissem         []string
}
type KasAttribute struct {
	URI string
}

type RewrapAuditEventParams struct {
	Policy   KasPolicy
	PolicyID string

	// IsSuccess is retained for callers of CreateRewrapAuditEvent.
	//
	// Deprecated: use Logger.Rewrap or one of the Logger rewrap helpers.
	IsSuccess       bool
	FailureReason   string
	SuspectedTamper bool
	PolicyVerified  bool
	KAOID           string
	TDFFormat       string
	Algorithm       string
	PolicyBinding   string
	KeyID           string
	SessionKeyType  string
	isDenied        bool
}

// CreateRewrapAuditEvent retains the legacy IsSuccess/isDenied result mapping.
func CreateRewrapAuditEvent(ctx context.Context, params RewrapAuditEventParams) (*EventObject, error) {
	result := ActionResultError
	switch {
	case params.IsSuccess:
		result = ActionResultSuccess
	case params.isDenied:
		result = ActionResultFailure
	}
	return createRewrapAuditEvent(ctx, result, params)
}

func createRewrapAuditEvent(ctx context.Context, result ActionResult, params RewrapAuditEventParams) (*EventObject, error) {
	auditDataFromContext := GetAuditDataFromContext(ctx)

	objectID := params.PolicyID
	if params.Policy.UUID != uuid.Nil {
		objectID = params.Policy.UUID.String()
	}

	attrFQNS := make([]string, 0)
	if params.PolicyVerified {
		attrFQNS = make([]string, len(params.Policy.Body.DataAttributes))
		for i, attr := range params.Policy.Body.DataAttributes {
			attrFQNS[i] = attr.URI
		}
	}

	eventMetadata := auditEventMetadata{
		"keyID":            params.KeyID,
		"policyBinding":    params.PolicyBinding,
		"tdfFormat":        params.TDFFormat,
		"algorithm":        params.Algorithm,
		"sessionKeyType":   params.SessionKeyType,
		"policy_verified":  params.PolicyVerified,
		"suspected_tamper": params.SuspectedTamper,
	}
	if params.FailureReason != "" {
		eventMetadata["failure_reason"] = params.FailureReason
	}
	if params.KAOID != "" {
		eventMetadata["kao_id"] = params.KAOID
	}

	return &EventObject{
		Object: auditEventObject{
			Type: ObjectTypeKeyObject,
			ID:   objectID,
			Attributes: eventObjectAttributes{
				EventObjectAttributes: EventObjectAttributes{
					Assertions:  []string{}, // Assertions aren't passed in the rewrap policy body
					Attrs:       attrFQNS,
					Permissions: []string{}, // Currently always empty
				},
			},
		},
		Action: eventAction{
			EventObjectAction: EventObjectAction{
				Type:   ActionTypeRewrap,
				Result: result,
			},
		},
		Actor: auditEventActor{
			EventObjectActor: EventObjectActor{
				ID:         auditDataFromContext.ActorID,
				Attributes: make([]any, 0),
			},
		},
		EventMetaData: eventMetadata,
		ClientInfo: eventClientInfo{
			EventClientInfo: EventClientInfo{
				Platform:  "kas",
				UserAgent: auditDataFromContext.UserAgent,
				RequestIP: auditDataFromContext.RequestIP,
			},
		},
		RequestID: auditDataFromContext.RequestID,
		Timestamp: time.Now().Format(time.RFC3339),
	}, nil
}
