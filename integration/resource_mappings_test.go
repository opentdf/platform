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

var nonExistentResourceMappingUUID = "45674556-8888-9999-9999-000001230000"

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
		AttributeValueId: nonExistentAttributeValueUuid,
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
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdMapping)
	assert.NotNil(s.T(), createdMapping.Terms)
	assert.Equal(s.T(), len(createdMapping.Terms), 0)
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
	testData := getResourceMappingFixtures()
	for _, testMapping := range testData {
		mapping, err := s.db.Client.GetResourceMapping(s.ctx, testMapping.Id)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), mapping)
		assert.Equal(s.T(), testMapping.Id, mapping.Id)
		assert.Equal(s.T(), testMapping.AttributeValueId, mapping.AttributeValue.Id)
		assert.Equal(s.T(), testMapping.Terms, mapping.Terms)
	}
}

func (s *ResourceMappingsSuite) Test_GetResourceMappingWithUnknownIdFails() {
	mapping, err := s.db.Client.GetResourceMapping(s.ctx, nonExistentResourceMappingUUID)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), mapping)
}

func (s *ResourceMappingsSuite) Test_GetResourceMappingOfCreatedSucceeds() {
	metadata := &common.MetadataMutable{}

	attrValue := fixtures.GetAttributeValueKey("example.com/attr/attr1/value/value2")
	mapping := &resourcemapping.ResourceMappingCreateUpdate{
		AttributeValueId: attrValue.Id,
		Metadata:         metadata,
		Terms:            []string{"term1", "term2"},
	}
	createdMapping, err := s.db.Client.CreateResourceMapping(s.ctx, mapping)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdMapping)

	got, err := s.db.Client.GetResourceMapping(s.ctx, createdMapping.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), mapping)
	assert.Equal(s.T(), createdMapping.Id, got.Id)
	assert.Equal(s.T(), createdMapping.AttributeValue.Id, got.AttributeValue.Id)
	assert.Equal(s.T(), createdMapping.Terms, mapping.Terms)
}

func (s *ResourceMappingsSuite) Test_UpdateResourceMapping() {
	metadata := &common.MetadataMutable{
		Labels: map[string]string{
			"name": "some test resource mapping name",
		},
		Description: "some description",
	}

	attrValue := fixtures.GetAttributeValueKey("example.com/attr/attr2/value/value2")
	mapping := &resourcemapping.ResourceMappingCreateUpdate{
		AttributeValueId: attrValue.Id,
		Metadata:         metadata,
		Terms:            []string{"some term", "other term"},
	}
	createdMapping, err := s.db.Client.CreateResourceMapping(s.ctx, mapping)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdMapping)

	updatedMetadata := &common.MetadataMutable{
		Labels: map[string]string{
			"name": "new name",
		},
		Description: "new description",
	}

	// update the created with new metadata and terms
	updatedMapping := &resourcemapping.ResourceMappingCreateUpdate{
		AttributeValueId: createdMapping.AttributeValue.Id,
		Metadata:         updatedMetadata,
		Terms:            []string{"updated term1", "updated term 2"},
	}
	updated, err := s.db.Client.UpdateResourceMapping(s.ctx, createdMapping.Id, updatedMapping)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updated)

	// get after update to verify db reflects changes made
	got, err := s.db.Client.GetResourceMapping(s.ctx, createdMapping.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), createdMapping.Id, got.Id)
	assert.Equal(s.T(), createdMapping.AttributeValue.Id, got.AttributeValue.Id)
	assert.Equal(s.T(), updatedMapping.Terms, got.Terms)
	assert.Equal(s.T(), updatedMetadata.Description, got.Metadata.Description)
	assert.EqualValues(s.T(), updatedMetadata.Labels, got.Metadata.Labels)
}

func (s *ResourceMappingsSuite) Test_UpdateResourceMappingWithUnknownIdFails() {
	attrValue := fixtures.GetAttributeValueKey("example.com/attr/attr2/value/value2")
	mapping := &resourcemapping.ResourceMappingCreateUpdate{
		AttributeValueId: attrValue.Id,
		Terms:            []string{"asdf qwerty"},
	}
	createdMapping, err := s.db.Client.CreateResourceMapping(s.ctx, mapping)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdMapping)

	// update the created with new metadata and terms
	updatedMapping := &resourcemapping.ResourceMappingCreateUpdate{
		AttributeValueId: createdMapping.AttributeValue.Id,
		Terms:            []string{"asdf updated term1"},
	}
	updated, err := s.db.Client.UpdateResourceMapping(s.ctx, nonExistentResourceMappingUUID, updatedMapping)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), updated)
}

func (s *ResourceMappingsSuite) Test_UpdateResourceMappingWithUnknownAttributeValueIdFails() {
	attrValue := fixtures.GetAttributeValueKey("example.com/attr/attr2/value/value2")
	mapping := &resourcemapping.ResourceMappingCreateUpdate{
		AttributeValueId: attrValue.Id,
		Terms:            []string{"testing"},
	}
	createdMapping, err := s.db.Client.CreateResourceMapping(s.ctx, mapping)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdMapping)

	// update the created with new metadata and terms
	updatedMapping := &resourcemapping.ResourceMappingCreateUpdate{
		AttributeValueId: nonExistentAttributeValueUuid,
		Terms:            []string{"testing-2"},
	}
	updated, err := s.db.Client.UpdateResourceMapping(s.ctx, createdMapping.Id, updatedMapping)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), updated)
}

func (s *ResourceMappingsSuite) Test_DeleteResourceMapping() {
	attrValue := fixtures.GetAttributeValueKey("example.net/attr/attr1/value/value1")
	mapping := &resourcemapping.ResourceMappingCreateUpdate{
		AttributeValueId: attrValue.Id,
		Terms:            []string{"term1", "term2"},
	}
	createdMapping, err := s.db.Client.CreateResourceMapping(s.ctx, mapping)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdMapping)

	deleted, err := s.db.Client.DeleteResourceMapping(s.ctx, createdMapping.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), deleted)

	deletedMapping, err := s.db.Client.GetResourceMapping(s.ctx, createdMapping.Id)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), deletedMapping)
}

func (s *ResourceMappingsSuite) Test_DeleteResourceMappingWithUnknownIdFails() {
	deleted, err := s.db.Client.DeleteResourceMapping(s.ctx, nonExistentResourceMappingUUID)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), deleted)
}

func TestResourceMappingsSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping resource mappings integration tests")
	}
	suite.Run(t, new(ResourceMappingsSuite))
}
