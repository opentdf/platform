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
	"google.golang.org/protobuf/encoding/protojson"
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
			Version:     "1",
			Namespace:   "demo.com",
			Fqn:         "http://demo.com/attr/relto",
			Label:       "Country of Origin",
			Description: "The relto attribute is used to describe the relationship of the resource to the country of origin.",
		},
	},
}

func Test_CreateAttribute_Returns_InternalError_When_InsertIssue(t *testing.T) {
	mock, err := pgxmock.NewPool()
	if err != nil {
		t.Fatal(err)
	}
	defer mock.Close()

	jsonDefinition, err := protojson.Marshal(definition.Definition)
	if err != nil {
		t.Errorf("marshal error was not expected: %s", err.Error())
	}

	mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(definition.Definition.Descriptor_.Namespace,
			definition.Definition.Descriptor_.Version,
			definition.Definition.Descriptor_.Fqn,
			definition.Definition.Descriptor_.Label,
			definition.Definition.Descriptor_.Description,
			"attribute",
			jsonDefinition,
		).
		WillReturnError(errors.New("error inserting resource"))

	attrServer := &attributesServer{
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
