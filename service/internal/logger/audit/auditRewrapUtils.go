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
}

func CreateRewrapAuditEvent(ctx context.Context, params RewrapAuditEventParams) (*AuditEvent, error) {
	auditDataFromContext := GetAuditDataFromContext(ctx)

	// Assign action result
	auditEventActionResult := ActionResultError
	if params.IsSuccess {
		auditEventActionResult = ActionResultSuccess
	}

	return &AuditEvent{
		Object: auditEventObject{
			Type: "key_object",
			ID:   params.Policy.UUID.String(),
			Attributes: auditEventObjectAttributes{
				Assertions:  []string{},
				Attrs:       []string{},
				Permissions: []string{},
			},
		},
		Action: auditEventAction{
			Type:   "rewrap",
			Result: auditEventActionResult,
		},
		Owner: CreateNilOwner(),
		Actor: auditEventActor{
			ID:         auditDataFromContext.ActorID,
			Attributes: map[string]string{},
		},
		EventMetaData: map[string]string{
			"keyID":         "", // TODO: keyID once implemented
			"policyBinding": params.PolicyBinding,
			"tdfFormat":     params.TDFFormat,
			"algorithm":     params.Algorithm,
		},
		ClientInfo: auditEventClientInfo{
			Platform:  "kas",
			UserAgent: auditDataFromContext.UserAgent,
			RequestIP: auditDataFromContext.RequestIP,
		},
		RequestID: auditDataFromContext.RequestID,
		Timestamp: time.Now().Format(time.RFC3339),
	}, nil
}
