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
	Policy        KasPolicy
	IsSuccess     bool
	TDFFormat     string
	Algorithm     string
	PolicyBinding string
	KeyID         string
}

func CreateRewrapAuditEvent(ctx context.Context, params RewrapAuditEventParams) (*EventObject, error) {
	auditDataFromContext := GetAuditDataFromContext(ctx)

	// Assign action result
	auditEventActionResult := ActionResultError
	if params.IsSuccess {
		auditEventActionResult = ActionResultSuccess
	}

	attrFQNS := make([]string, len(params.Policy.Body.DataAttributes))
	for i, attr := range params.Policy.Body.DataAttributes {
		attrFQNS[i] = attr.URI
	}

	return &EventObject{
		Object: auditEventObject{
			Type: ObjectTypeKeyObject,
			ID:   params.Policy.UUID.String(),
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
				Result: auditEventActionResult,
			},
		},
		Actor: auditEventActor{
			EventObjectActor: EventObjectActor{
				ID:         auditDataFromContext.ActorID,
				Attributes: make([]any, 0),
			},
		},
		EventMetaData: auditEventMetadata{
			"keyID":         params.KeyID,
			"policyBinding": params.PolicyBinding,
			"tdfFormat":     params.TDFFormat,
			"algorithm":     params.Algorithm,
		},
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
