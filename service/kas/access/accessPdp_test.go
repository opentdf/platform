package access

import (
	"testing"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/authorization"
)

// ######## Dissem tests ################

func TestDissemSuccess(t *testing.T) {
	var entityID = "email2@example.com"

	testPolicy := Policy{
		UUID: uuid.New(), //nolint:govet // policy has uuid
		Body: PolicyBody{
			DataAttributes: []Attribute{},
			Dissem: []string{"email1@example.com",
				"email2@example.com",
				"email3@example.com"},
		},
	}
	entity := &authorization.Entity{
		Id:         "0",
		EntityType: &authorization.Entity_EmailAddress{EmailAddress: entityID},
	}
	output, err := checkDissems(testPolicy.Body.Dissem, entity)
	if err != nil {
		t.Error(err)
	}
	if !output {
		t.Errorf("Output %v not equal to expected %v", output, true)
	}
}

func TestDissemFailure(t *testing.T) {
	var entityID = "email2@example.com"

	testPolicy := Policy{
		UUID: uuid.New(), //nolint:govet // policy has uuid
		Body: PolicyBody{
			DataAttributes: []Attribute{},
			Dissem: []string{"email1@example.com",
				"email3@example.com"},
		},
	}
	entity := &authorization.Entity{
		Id:         "0",
		EntityType: &authorization.Entity_EmailAddress{EmailAddress: entityID},
	}
	output, err := checkDissems(testPolicy.Body.Dissem, entity)
	if err != nil {
		t.Error(err)
	}
	if output {
		t.Errorf("Output %v not equal to expected %v", output, false)
	}
}
