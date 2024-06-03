package logger

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/realip"
	"github.com/lestrrat-go/jwx/v2/jwt"
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
	EntityToken   string
	TDFFormat     string
	Algorithm     string
	PolicyBinding string
}

func CreateRewrapAuditEvent(ctx context.Context, params RewrapAuditEventParams) (*AuditEvent, error) {
	// Extract the request ID from context
	requestID, requestIDOk := ctx.Value("request-id").(uuid.UUID)
	if !requestIDOk {
		requestID = uuid.Nil
	}

	// Extract header values from context
	userAgent, uaOk := ctx.Value("user-agent").(string)
	if !uaOk {
		userAgent = "None"
	}

	// Extract request IP from context
	requestIPString := "None"
	requestIP, ipOK := realip.FromContext(ctx)
	if ipOK {
		requestIPString = requestIP.String()
	}

	// Assign action result
	auditEventActionResult := "failure"
	if params.IsSuccess {
		auditEventActionResult = "success"
	}

	// Extract sub from valid token
	entityTokenJWT, parseError := jwt.Parse([]byte(params.EntityToken), jwt.WithVerify(false))
	if parseError != nil {
		return nil, parseError
	}
	entityTokenSub := entityTokenJWT.Subject()

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
		Owner: auditEventOwner{
			ID:    uuid.Nil,
			OrgID: uuid.Nil,
		},
		Actor: auditEventActor{
			ID:         entityTokenSub,
			Attributes: map[string]string{},
		},
		// TODO: keyID once implemented
		EventMetaData: map[string]string{
			"keyID":         "",
			"policyBinding": params.PolicyBinding,
			"tdfFormat":     params.TDFFormat,
			"algorithm":     params.Algorithm,
		},
		ClientInfo: auditEventClientInfo{
			Platform:  "kas",
			UserAgent: userAgent,
			RequestIP: requestIPString,
		},
		RequestID: requestID,
		Timestamp: time.Now().Format(time.RFC3339),
	}, nil
}
