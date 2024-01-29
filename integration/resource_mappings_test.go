package integration

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/opentdf/opentdf-v2-poc/sdk/common"
	resourcemapping "github.com/opentdf/opentdf-v2-poc/sdk/resourcemapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var nonexistentAttributeValueUuid = "78909865-8888-9999-9999-000000000000"

type ResourceMappingsSuite struct {
	suite.Suite
	schema string
	f      Fixtures
	db     DBInterface
	ctx    context.Context
}

func (s *ResourceMappingsSuite) SetupSuite() {
	slog.Info("setting up db.ResourceMappings test suite")
	s.ctx = context.Background()
	s.schema = "test_opentdf_resource_mappings"
	s.db = NewDBInterface(s.schema)
	s.f = NewFixture(s.db)
	s.f.Provision()
}

func (s *ResourceMappingsSuite) TearDownSuite() {
	slog.Info("tearing down db.ResourceMappings test suite")
	s.f.TearDown()
}

func getResourceMappingFixtures() []FixtureDataResourceMapping {
	return []FixtureDataResourceMapping{
		fixtures.GetResourceMappingKey("resource_mapping_to_attribute_value1"),
		fixtures.GetResourceMappingKey("resource_mapping_to_attribute_value2"),
		fixtures.GetResourceMappingKey("resource_mapping_to_attribute_value3"),
	}
}

func (s *ResourceMappingsSuite) Test_CreateResourceMapping() {
	metadata := &common.MetadataMutable{
		Labels: map[string]string{
			"name": "this is the test name of my resource mapping",
		},
		Description: "test create resource mapping description",
	}

	attrValue := fixtures.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	mapping := &resourcemapping.ResourceMappingCreateUpdate{
		AttributeValueId: attrValue.Id,
		Metadata:         metadata,
		Terms:            []string{"term1", "term2"},
	}
	createdMapping, err := s.db.Client.CreateResourceMapping(s.ctx, mapping)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdMapping)
}

func (s *ResourceMappingsSuite) Test_CreateResourceMappingWithUnknownAttributeValueFails() {
	metadata := &common.MetadataMutable{}

	mapping := &resourcemapping.ResourceMappingCreateUpdate{
		AttributeValueId: nonexistentAttributeValueUuid,
		Metadata:         metadata,
		Terms:            []string{"term1", "term2"},
	}
	createdMapping, err := s.db.Client.CreateResourceMapping(s.ctx, mapping)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), createdMapping)
}

func (s *ResourceMappingsSuite) Test_CreateResourceMappingWithEmptyTermsSucceeds() {
	metadata := &common.MetadataMutable{}

	attrValue := fixtures.GetAttributeValueKey("example.com/attr/attr2/value/value2")
	mapping := &resourcemapping.ResourceMappingCreateUpdate{
		AttributeValueId: attrValue.Id,
		Metadata:         metadata,
		Terms:            []string{},
	}
	createdMapping, err := s.db.Client.CreateResourceMapping(s.ctx, mapping)
	// TODO: verify this test & behavior is correct. Terms are not required?
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdMapping)
}

func (s *ResourceMappingsSuite) Test_ListResourceMappings() {
	// make sure we can get all fixtures
	testData := getResourceMappingFixtures()
	mappings, err := s.db.Client.ListResourceMappings(s.ctx)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), mappings)
	for _, testMapping := range testData {
		found := false
		for _, mapping := range mappings {
			if testMapping.Id == mapping.Id {
				found = true
				break
			}
		}
		assert.True(s.T(), found, fmt.Sprintf("expected to find mapping %s", testMapping.Id))
	}
}

func (s *ResourceMappingsSuite) Test_GetResourceMapping() {
	// make sure we can get all fixtures
	// testData := getResourceMappingFixtures()
	// for _, testMapping := range testData {
	// 	mapping, err := s.db.Client.GetResourceMapping(s.ctx, testMapping.Id)
	// 	fmt.Println("here", mapping, err)
	// 	assert.Nil(s.T(), err)
	// 	assert.NotNil(s.T(), mapping)
	// assert.Equal(s.T(), testMapping.Id, mapping.Id)
	// assert.Equal(s.T(), testMapping.AttributeValueId, mapping.AttributeValue.Id)
	// assert.Equal(s.T(), testMapping.Terms, mapping.Terms)
	// }
}

func TestResourceMappingsSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping resource mappings integration tests")
	}
	suite.Run(t, new(ResourceMappingsSuite))
}
