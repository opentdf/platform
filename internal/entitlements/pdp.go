package entitlements

import (
	"strings"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
)

func OpaInput(entity *authorization.Entity, ss *subjectmapping.SubjectSet) (map[string]interface{}, error) {
	// OPA wants this as a generic map[string]interface{} and will not handle
	// deserializing to concrete structs
	inputUnstructured := make(map[string]interface{})
	// SubjectSet
	inputUnstructured["subjectset"] = ss
	// FIXME assumes format email_address:\"a@a.af\"
	ea := make(map[string]interface{})
	ea["id"] = entity.Id
	colonIndex := strings.IndexByte(entity.String(), ':')
	ea[entity.String()[:colonIndex]] = entity.String()[colonIndex+2 : len(entity.String())-1]
	ea["claims"] = []string{"ec11", "ec12", "ec13"}
	inputUnstructured["entity"] = ea
	return inputUnstructured, nil
}
