package tests

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	attributesv1 "github.com/opentdf/opentdf-v2-poc/gen/attributes/v1"
	commonv1 "github.com/opentdf/opentdf-v2-poc/gen/common/v1"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

const (
	definitionsTestData = "testdata/attributes/attribute_definitions.json"
)

type AttributesSuite struct {
	suite.Suite
	conn   *grpc.ClientConn
	client attributesv1.AttributesServiceClient
}

func (suite *AttributesSuite) SetupSuite() {
	ctx := context.Background()
	conn, err := grpc.Dial("localhost:9000", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		slog.Error("could not connect", slog.String("error", err.Error()))
		suite.T().Fatal(err)
	}
	suite.conn = conn

	suite.client = attributesv1.NewAttributesServiceClient(conn)

	testData, err := os.ReadFile(definitionsTestData)
	if err != nil {
		slog.Error("could not read attributes.json", slog.String("error", err.Error()))
		suite.T().Fatal(err)
	}

	var attributes = make([]*attributesv1.AttributeDefinition, 0)

	err = json.Unmarshal(testData, &attributes)

	if err != nil {
		slog.Error("could not unmarshal attributes.json", slog.String("error", err.Error()))
		suite.T().Fatal(err)
	}

	for _, attr := range attributes {
		_, err = suite.client.CreateAttribute(ctx, &attributesv1.CreateAttributeRequest{
			Definition: attr,
		})
		if err != nil {
			slog.Error("could not create attribute", slog.String("error", err.Error()))
			suite.T().Fatal(err)
		}
	}
	slog.Info("loaded attributes test data")

}

func (suite *AttributesSuite) TearDownSuite() {
	slog.Info("tearing down attributes test suite")
	defer suite.conn.Close()
}

func TestAttributeSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping attributes integration tests")
	}
	suite.Run(t, new(AttributesSuite))
}

func (suite *AttributesSuite) Test_CreateAttribute_Returns_Success_When_Valid_Definition() {

	definition := attributesv1.AttributeDefinition{
		Name: "relto",
		Rule: attributesv1.AttributeDefinition_ATTRIBUTE_RULE_TYPE_ANY_OF,
		Values: []*attributesv1.AttributeDefinitionValue{
			{
				Value: "USA",
			},
			{
				Value: "GBR",
			},
		},
		Descriptor_: &commonv1.ResourceDescriptor{
			Version:   1,
			Namespace: "virtru.com",
			Name:      "relto",
			Type:      commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION,
		},
	}

	_, err := suite.client.CreateAttribute(context.Background(), &attributesv1.CreateAttributeRequest{
		Definition: &definition,
	})

	assert.Nil(suite.T(), err)
}

func (suite *AttributesSuite) Test_CreateAttribute_Returns_BadRequest_When_InvalidRuleType() {
	definition := attributesv1.AttributeDefinition{
		Name: "relto",
		Rule: 543,
		Values: []*attributesv1.AttributeDefinitionValue{
			{
				Value: "USA",
			},
			{
				Value: "GBR",
			},
		},
		Descriptor_: &commonv1.ResourceDescriptor{
			Version:   1,
			Namespace: "virtru.com",
			Name:      "relto",
			Type:      commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION,
		},
	}

	_, err := suite.client.CreateAttribute(context.Background(), &attributesv1.CreateAttributeRequest{
		Definition: &definition,
	})

	if assert.Error(suite.T(), err) {
		st, _ := status.FromError(err)
		assert.Equal(suite.T(), codes.InvalidArgument, st.Code())
		assert.Equal(suite.T(), st.Message(), "validation error:\n - definition.rule: value must be one of the defined enum values [enum.defined_only]")
	}

}

func (suite *AttributesSuite) Test_CreateAttribute_Returns_BadRequest_When_InvalidNamespace() {
	definition := attributesv1.AttributeDefinition{
		Name: "relto",
		Rule: attributesv1.AttributeDefinition_ATTRIBUTE_RULE_TYPE_ANY_OF,
		Values: []*attributesv1.AttributeDefinitionValue{
			{
				Value: "USA",
			},
			{
				Value: "GBR",
			},
		},
		Descriptor_: &commonv1.ResourceDescriptor{
			Version:   1,
			Namespace: "virtru",
			Name:      "relto",
			Type:      commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION,
		},
	}

	_, err := suite.client.CreateAttribute(context.Background(), &attributesv1.CreateAttributeRequest{
		Definition: &definition,
	})

	if assert.Error(suite.T(), err) {
		st, _ := status.FromError(err)
		assert.Equal(suite.T(), codes.InvalidArgument, st.Code())
		assert.Equal(suite.T(), st.Message(), "validation error:\n - definition.descriptor.namespace: Namespace must be a valid hostname. It should include at least one dot, with each segment (label) starting and ending with an alphanumeric character. Each label must be 1 to 63 characters long, allowing hyphens but not as the first or last character. The top-level domain (the last segment after the final dot) must consist of at least two alphabetic characters. [namespace_format]")
	}

}

func (suite *AttributesSuite) Test_GetAttribute_Returns_NotFound_When_ID_Does_Not_Exist() {
	definition, err := suite.client.GetAttribute(context.Background(), &attributesv1.GetAttributeRequest{
		Id: 10000,
	})
	assert.Nil(suite.T(), definition)
	assert.NotNil(suite.T(), err)

	if assert.Error(suite.T(), err) {
		st, _ := status.FromError(err)
		assert.Equal(suite.T(), codes.NotFound, st.Code())
		assert.Equal(suite.T(), st.Message(), "attribute not found")
	}
}
