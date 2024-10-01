package audit

import (
	"context"
	"encoding/json"
	"maps"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type PolicyEventParams struct {
	ActionType ActionType
	ObjectID   string
	ObjectType ObjectType

	Original proto.Message
	Updated  proto.Message
}

/*
	 TODO: Changes to oneOf proto properties are not yet audited correctly with the existing code.

		The Updated event object will contain both the original and updated oneOf properties due to
		the logic for merging maps within this function.  We will need to find a way to support them
		correctly in the near future.
*/
func CreatePolicyEvent(ctx context.Context, isSuccess bool, params PolicyEventParams) (*EventObject, error) {
	auditDataFromContext := GetAuditDataFromContext(ctx)

	auditEventActionResult := ActionResultError
	if isSuccess {
		auditEventActionResult = ActionResultSuccess
	}

	auditEvent := &EventObject{
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
			Attributes: make([]interface{}, 0),
		},
		ClientInfo: eventClientInfo{
			Platform:  "policy",
			UserAgent: auditDataFromContext.UserAgent,
			RequestIP: auditDataFromContext.RequestIP,
		},
		RequestID: auditDataFromContext.RequestID,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	if params.Original != nil {
		auditEventOriginal, err := marshallProtoToAuditObject(params.Original)
		if err != nil {
			return nil, err
		}
		auditEvent.Original = auditEventOriginal

		if params.Updated != nil {
			auditEventUpdated, err := marshallProtoToAuditObject(params.Updated)
			if err != nil {
				return nil, err
			}
			// copy original state
			auditEvent.Updated = maps.Clone(auditEvent.Original)
			// merge changes from PolicyEventParams, overwriting properties existing in Updated object
			maps.Copy(auditEvent.Updated, auditEventUpdated)
		}
	}

	return auditEvent, nil
}

func marshallProtoToAuditObject(protoMessage proto.Message) (map[string]interface{}, error) {
	jsonData, err := protojson.Marshal(protoMessage)
	if err != nil {
		return nil, err
	}

	data := make(map[string]interface{})
	err = json.Unmarshal(jsonData, &data)
	if err != nil {
		return nil, err
	}

	// remove metadata fields we don't care about for audit
	if _, ok := data["metadata"]; ok {
		metadata := data["metadata"].(map[string]interface{})

		delete(metadata, "createdAt")
		delete(metadata, "updatedAt")

		// remove metadata entirely if created and updated at were the only fields
		if len(metadata) == 0 {
			delete(data, "metadata")
		}
	}

	return data, nil
}
