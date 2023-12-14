package attributes

import (
	"context"
	"errors"
	"testing"

	attributesv1 "github.com/opentdf/opentdf-v2-poc/gen/attributes/v1"
	commonv1 "github.com/opentdf/opentdf-v2-poc/gen/common/v1"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var definition = &attributesv1.CreateAttributeRequest{
	Definition: &attributesv1.AttributeDefinition{
		Name: "relto",
		Rule: attributesv1.AttributeDefinition_ATTRIBUTE_RULE_TYPE_ANY_OF,
		Values: []*attributesv1.AttributeDefinitionValue{
			{
				Value: "USA",
			},
		},
		Descriptor_: &commonv1.ResourceDescriptor{
			Version:   1,
			Name:      "example attribute",
			Namespace: "demo.com",
			Fqn:       "http://demo.com/attr/relto",
			Labels: map[string]string{
				"origin": "Country of Origin",
			},
			Description: "The relto attribute is used to describe the relationship of the resource to the country of origin.",
			Type:        commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION,
		},
	},
}

func Test_CreateAttribute_Returns_InternalError_When_InsertIssue(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(definition.Definition.Descriptor_.Name,
			definition.Definition.Descriptor_.Namespace,
			definition.Definition.Descriptor_.Version,
			definition.Definition.Descriptor_.Fqn,
			definition.Definition.Descriptor_.Labels,
			definition.Definition.Descriptor_.Description,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String(),
			definition.Definition,
		).
		WillReturnError(errors.New("error inserting resource"))

	attrServer := &Attributes{
		dbClient: &db.Client{
			PgxIface: mock,
		},
	}
	_, err = attrServer.CreateAttribute(context.Background(), definition)
	if assert.Error(t, err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(t, codes.Internal, grpcStatus.Code())

		assert.Contains(t, grpcStatus.Message(), "error inserting resource")

	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
	}

}
