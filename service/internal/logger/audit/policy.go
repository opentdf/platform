package audit

import (
	"context"
	"encoding/json"
	"time"
)

type PolicyEventParams struct {
	ActionType ActionType
	ObjectID   string
	ObjectType ObjectType

	Original interface{}
	Updated  interface{}
}

func CreatePolicyEvent(ctx context.Context, isSuccess bool, params PolicyEventParams) (*EventObject, error) {
	auditDataFromContext := GetAuditDataFromContext(ctx)

	auditEventActionResult := ActionResultError
	if isSuccess {
		auditEventActionResult = ActionResultSuccess
	}

	// Calculate the diff for update events
	var diff []DiffEntry
	if params.ActionType == ActionTypeUpdate && isSuccess {
		// marshal interface to byte string
		original, err := json.Marshal(params.Original)
		if err != nil {
			return nil, err
		}

		updated, err := json.Marshal(params.Updated)
		if err != nil {
			return nil, err
		}

		patchDiff, err := createJSONPatchDiff(original, updated)
		if err != nil {
			return nil, err
		}
		diff = patchDiff
	}

	return &EventObject{
		Object: auditEventObject{
			Type: params.ObjectType,
			ID:   params.ObjectID,
		},
		Action: eventAction{
			Type:   params.ActionType,
			Result: auditEventActionResult,
		},
		Actor: auditEventActor{
			ID:         auditDataFromContext.ActorID,
			Attributes: map[string]string{},
		},
		Owner: CreateNilOwner(),
		Diff:  diff,

		ClientInfo: eventClientInfo{
			Platform:  "policy",
			UserAgent: auditDataFromContext.UserAgent,
			RequestIP: auditDataFromContext.RequestIP,
		},
		RequestID: auditDataFromContext.RequestID,
		Timestamp: time.Now().Format(time.RFC3339),
	}, nil
}
