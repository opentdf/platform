package entitlements

import (
	"github.com/arkavo-org/opentdf-platform/protocol/go/authorization"
	"github.com/arkavo-org/opentdf-platform/protocol/go/policy/attributes"
)

func OpaInput(entity *authorization.Entity, sms map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue, config map[string]interface{}) (map[string]interface{}, error) {
	// OPA wants this as a generic map[string]interface{} and will not handle
	// deserializing to concrete structs
	inputUnstructured := make(map[string]interface{})
	// SubjectMapping
	inputUnstructured["attribute_mappings"] = sms
	// Entity
	ea := make(map[string]interface{})
	ea["id"] = entity.GetId()
	switch entity.GetEntityType().(type) {
	case *authorization.Entity_ClientId:
		ea["client_id"] = entity.GetClientId()
	case *authorization.Entity_EmailAddress:
		ea["email_address"] = entity.GetEmailAddress()
	case *authorization.Entity_Jwt:
		ea["jwt"] = entity.GetJwt()
	}
	inputUnstructured["entity"] = ea

	inputUnstructured["idp"] = config
	return inputUnstructured, nil
}
