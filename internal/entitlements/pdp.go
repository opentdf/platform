package entitlements

import (
	"github.com/opentdf/platform/protocol/go/authorization"
	"strings"
)

func OpaInput(entity *authorization.Entity) (map[string]interface{}, error) {
	// OPA wants this as a generic map[string]interface{} and will not handle
	// deserializing to concrete structs
	inputUnstructured := make(map[string]interface{})
	// assumes format email_address:\"a@a.co\"
	ea := make(map[string]interface{})
	ea["id"] = entity.String()
	colonIndex := strings.IndexByte(entity.String(), ':')
	ea[entity.String()[:colonIndex]] = entity.String()[colonIndex+2 : len(entity.String())-1]
	ea["claims"] = []string{"svA", "sv2", "sv3"}
	inputUnstructured["entity"] = ea
	return inputUnstructured, nil
}
