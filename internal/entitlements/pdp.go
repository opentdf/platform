package entitlements

import (
	"errors"

	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
)

func OpaInput(entity *authorization.Entity, ss *subjectmapping.SubjectSet) (map[string]interface{}, error) {
	// OPA wants this as a generic map[string]interface{} and will not handle
	// deserializing to concrete structs
	inputUnstructured := make(map[string]interface{})
	// SubjectSet
	inputUnstructured["subjectset"] = ss
	ea := make(map[string]interface{})
	ea["id"] = entity.Id
	switch v := entity.EntityType.(type) {
	case *authorization.Entity_EmailAddress:
		ea["email_address"] = v.EmailAddress
	case *authorization.Entity_Jwt:
		ea["jwt"] = v.Jwt
	case *authorization.Entity_Claims:
		ea["claims"] = v.Claims
	case *authorization.Entity_RemoteClaimsUrl:
		ea["remote_claims_url"] = v.RemoteClaimsUrl
	case *authorization.Entity_UserName:
		ea["user_name"] = v.UserName
	case *authorization.Entity_Custom:
		ea["custom"] = v.Custom
	default:
		return nil, errors.New("entity malformed")
	}
	ea["claims"] = []string{"ec11", "ec12", "ec13"}
	inputUnstructured["entity"] = ea
	return inputUnstructured, nil
}
