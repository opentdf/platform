package entitlements

import (
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
)

func OpaInput(entity *authorization.Entity, sms map[string]*attributes.GetAttributeValuesByFqnsResponse_AttributeAndValue) (map[string]interface{}, error) {
	// OPA wants this as a generic map[string]interface{} and will not handle
	// deserializing to concrete structs
	inputUnstructured := make(map[string]interface{})
	// SubjectMapping
	inputUnstructured["attribute_mappings"] = sms
	// Entity
	ea := make(map[string]interface{})
	ea["id"] = entity.Id
	ea["email_address"] = entity.GetEmailAddress()
	inputUnstructured["entity"] = ea
	// idp plugin KeyCloakConfig
	idp := make(map[string]interface{})
	idp["url"] = "http://localhost:8888"
	idp["client"] = "tdf-entity-resolution-service"
	idp["secret"] = "5Byk7Hh6l0E1hJDZfF8CQbG9vqh2FeIe"
	idp["realm"] = "tdf"
	idp["legacy"] = true
	inputUnstructured["idp"] = idp
	return inputUnstructured, nil
}
