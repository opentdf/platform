package entitlements

import (
	"github.com/opentdf/platform/protocol/go/entityresolution"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"google.golang.org/protobuf/encoding/protojson"
)

func OpaInput(sms map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, ersResponse *entityresolution.ResolveEntitiesResponse) (map[string]interface{}, error) {
	// OPA wants this as a generic map[string]interface{} and will not handle
	// deserializing to concrete structs
	inputUnstructured := make(map[string]interface{})

	// SubjectMapping
	// convert sms to json string
	smsJSON := make(map[string]string)
	for k, v := range sms {
		attrDefBytes, err := protojson.Marshal(v)
		if err != nil {
			return nil, err
		}
		smsJSON[k] = string(attrDefBytes)
	}
	inputUnstructured["attribute_mappings"] = smsJSON

	ersRespBytes, err := protojson.Marshal(ersResponse)
	if err != nil {
		return nil, err
	}
	inputUnstructured["ers_response"] = string(ersRespBytes)

	return inputUnstructured, nil
}
