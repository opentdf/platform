package access

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/authorization"
	"github.com/opentdf/platform/sdk"
)

var c = context.Background()

var osdk, _ = sdk.New("", sdk.WithClientCredentials("myid", "mysecret", nil))

// ######## Dissem tests ################

func TestDissemSuccess(t *testing.T) {
	var entityID string = "email2@example.com"

	testPolicy := Policy{
		UUID: uuid.New(),
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
	output, err := canAccess(c, entity, testPolicy, osdk)
	if err != nil {
		t.Error(err)
	}
	if !output {
		t.Errorf("Output %v not equal to expected %v", output, true)
	}
}

func TestDissemFailure(t *testing.T) {
	var entityID string = "email2@example.com"

	testPolicy := Policy{
		UUID: uuid.New(),
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
	output, err := canAccess(c, entity, testPolicy, osdk)
	if err != nil {
		t.Error(err)
	}
	if output {
		t.Errorf("Output %v not equal to expected %v", output, false)
	}
}
