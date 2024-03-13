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
	ea := make(map[string]interface{})
	ea["id"] = entity.Id
	//ea["claims"] = []string{"CoolTool", "RadService", "ShinyThing"}
	inputUnstructured["entity"] = ea
	// idp plugin
	es := make(map[string]interface{})
	es["entities"] = []interface{}{entity}
	//ir := authorization.IdpPluginRequest{
	//	Entities: make([]*authorization.Entity, 1),
	//}
	//ir.Entities[0] = entity
	//inputUnstructured["req"] = ir
	//inputUnstructured["config"] = idpplugin.KeyCloakConfg{
	//	Url:            "https://platform.virtru.us",
	//	ClientId:       "tdf-entity-resolution-service",
	//	ClientSecret:   "123-456",
	//	Realm:          "tdf",
	//	LegacyKeycloak: true,
	//}
	return inputUnstructured, nil
}
