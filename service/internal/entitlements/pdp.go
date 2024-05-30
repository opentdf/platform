package entitlements

import (
	"encoding/json"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"google.golang.org/protobuf/encoding/protojson"
)

func OpaInput(entity *authorization.Entity, sms map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, ersURL string, authToken string) (map[string]interface{}, error) {
	// OPA wants this as a generic map[string]interface{} and will not handle
	// deserializing to concrete structs
	inputUnstructured := make(map[string]interface{})
	// SubjectMapping
	// convert sms to json string
	smsJson := make(map[string]string)
	for k, v := range sms {
		attrDefBytes, err := protojson.Marshal(v)
		if err != nil {
			return nil, err
		}
		smsJson[k] = string(attrDefBytes)
	}
	inputUnstructured["attribute_mappings"] = smsJson

	// Entity
	// convert entity to map[string]string
	eaJson, err := protojson.Marshal(entity)
	if err != nil {
		return nil, err
	}
	var eaMap map[string]string
	err = json.Unmarshal(eaJson, &eaMap)
	if err != nil {
		return nil, err
	}

	inputUnstructured["entity"] = eaMap
	inputUnstructured["ers_url"] = ersURL
	inputUnstructured["auth_token"] = authToken

	return inputUnstructured, nil
}
