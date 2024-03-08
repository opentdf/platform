package integration

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/internal/fixtures"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var nonExistentResourceMappingUUID = "45674556-8888-9999-9999-000001230000"

type ResourceMappingsSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context
}

func (s *ResourceMappingsSuite) SetupSuite() {
	slog.Info("setting up db.ResourceMappings test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_resource_mappings"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
}

func (s *ResourceMappingsSuite) TearDownSuite() {
	slog.Info("tearing down db.ResourceMappings test suite")
	s.f.TearDown()
}

func (s *ResourceMappingsSuite) getResourceMappingFixtures() []fixtures.FixtureDataResourceMapping {
	return []fixtures.FixtureDataResourceMapping{
		s.f.GetResourceMappingKey("resource_mapping_to_attribute_value1"),
		s.f.GetResourceMappingKey("resource_mapping_to_attribute_value2"),
		s.f.GetResourceMappingKey("resource_mapping_to_attribute_value3"),
	}
}

func (s *ResourceMappingsSuite) Test_CreateResourceMapping() {
	metadata := &common.MetadataMutable{
		Labels: map[string]string{
			"name": "this is the test name of my resource mapping",
		},
	}

	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.Id,
		Metadata:         metadata,
		Terms:            []string{"term1", "term2"},
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdMapping)
}

func (s *ResourceMappingsSuite) Test_CreateResourceMappingWithUnknownAttributeValueFails() {
	metadata := &common.MetadataMutable{}

	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: nonExistentAttributeValueUuid,
		Metadata:         metadata,
		Terms:            []string{"term1", "term2"},
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), createdMapping)
	assert.ErrorIs(s.T(), err, db.ErrForeignKeyViolation)
}

func (s *ResourceMappingsSuite) Test_CreateResourceMappingWithEmptyTermsSucceeds() {
	metadata := &common.MetadataMutable{}

	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value2")
	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.Id,
		Metadata:         metadata,
		Terms:            []string{},
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdMapping)
	assert.NotNil(s.T(), createdMapping.Terms)
	assert.Equal(s.T(), len(createdMapping.Terms), 0)
}

func (s *ResourceMappingsSuite) Test_ListResourceMappings() {
	// make sure we can get all fixtures
	testData := s.getResourceMappingFixtures()
	mappings, err := s.db.PolicyClient.ListResourceMappings(s.ctx)
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
	testData := s.getResourceMappingFixtures()
	for _, testMapping := range testData {
		mapping, err := s.db.PolicyClient.GetResourceMapping(s.ctx, testMapping.Id)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), mapping)
		assert.Equal(s.T(), testMapping.Id, mapping.Id)
		assert.Equal(s.T(), testMapping.AttributeValueId, mapping.AttributeValue.Id)
		assert.Equal(s.T(), testMapping.Terms, mapping.Terms)
	}
}

func (s *ResourceMappingsSuite) Test_GetResourceMappingWithUnknownIdFails() {
	mapping, err := s.db.PolicyClient.GetResourceMapping(s.ctx, nonExistentResourceMappingUUID)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), mapping)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *ResourceMappingsSuite) Test_GetResourceMappingOfCreatedSucceeds() {
	metadata := &common.MetadataMutable{}

	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value2")
	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.Id,
		Metadata:         metadata,
		Terms:            []string{"term1", "term2"},
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdMapping)

	got, err := s.db.PolicyClient.GetResourceMapping(s.ctx, createdMapping.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), mapping)
	assert.Equal(s.T(), createdMapping.Id, got.Id)
	assert.Equal(s.T(), createdMapping.AttributeValue.Id, got.AttributeValue.Id)
	assert.Equal(s.T(), createdMapping.Terms, mapping.Terms)
}

func (s *ResourceMappingsSuite) Test_UpdateResourceMapping() {
	fixedLabel := "fixed label"
	updateLabel := "update label"
	updatedLabel := "true"
	newLabel := "new label"

	labels := map[string]string{
		"fixed":  fixedLabel,
		"update": updateLabel,
	}
	updateLabels := map[string]string{
		"update": updatedLabel,
		"new":    newLabel,
	}
	expectedLabels := map[string]string{
		"fixed":  fixedLabel,
		"update": updatedLabel,
		"new":    newLabel,
	}

	terms := []string{"some term", "other term"}
	updateTerms := []string{"updated term1", "updated term 2"}

	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value2")
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.Id,
		Metadata: &common.MetadataMutable{
			Labels: labels,
		},
		Terms: terms,
	})
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdMapping)

	if v, err := s.db.PolicyClient.GetResourceMapping(s.ctx, createdMapping.Id); err != nil {
		assert.Nil(s.T(), err)
	} else {
		assert.NotNil(s.T(), v)
		assert.Equal(s.T(), createdMapping.Id, v.Id)
		assert.Equal(s.T(), createdMapping.AttributeValue.Id, v.AttributeValue.Id)
		assert.Equal(s.T(), createdMapping.Terms, v.Terms)
	}

	updateWithoutChange, err := s.db.PolicyClient.UpdateResourceMapping(s.ctx, createdMapping.Id, &resourcemapping.UpdateResourceMappingRequest{})
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updateWithoutChange)
	assert.Equal(s.T(), createdMapping.Id, updateWithoutChange.Id)

	// update the created with new metadata and terms
	updateWithChange, err := s.db.PolicyClient.UpdateResourceMapping(s.ctx, createdMapping.Id, &resourcemapping.UpdateResourceMappingRequest{
		AttributeValueId: createdMapping.AttributeValue.Id,
		Terms:            updateTerms,
		Metadata: &common.MetadataMutable{
			Labels: updateLabels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updateWithChange)
	assert.Equal(s.T(), createdMapping.Id, updateWithChange.Id)

	// get after update to verify db reflects changes made
	got, err := s.db.PolicyClient.GetResourceMapping(s.ctx, createdMapping.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), createdMapping.Id, got.Id)
	assert.Equal(s.T(), createdMapping.AttributeValue.Id, got.AttributeValue.Id)
	assert.Equal(s.T(), updateTerms, got.Terms)
	assert.EqualValues(s.T(), expectedLabels, got.Metadata.GetLabels())
}

func (s *ResourceMappingsSuite) Test_UpdateResourceMappingWithUnknownIdFails() {
	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value2")
	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.Id,
		Terms:            []string{"asdf qwerty"},
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdMapping)

	// update the created with new metadata and terms
	updatedMapping := &resourcemapping.UpdateResourceMappingRequest{
		AttributeValueId: createdMapping.AttributeValue.Id,
		Terms:            []string{"asdf updated term1"},
	}
	updated, err := s.db.PolicyClient.UpdateResourceMapping(s.ctx, nonExistentResourceMappingUUID, updatedMapping)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), updated)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *ResourceMappingsSuite) Test_UpdateResourceMappingWithUnknownAttributeValueIdFails() {
	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value2")
	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.Id,
		Terms:            []string{"testing"},
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdMapping)

	m, err := s.db.PolicyClient.GetResourceMapping(s.ctx, createdMapping.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), m)
	assert.Equal(s.T(), createdMapping.Id, m.Id)

	// update the created with new metadata and terms
	updatedMapping := &resourcemapping.UpdateResourceMappingRequest{
		AttributeValueId: nonExistentAttributeValueUuid,
		Terms:            []string{"testing-2"},
	}
	updated, err := s.db.PolicyClient.UpdateResourceMapping(s.ctx, createdMapping.Id, updatedMapping)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), updated)
	assert.ErrorIs(s.T(), err, db.ErrForeignKeyViolation)
}

func (s *ResourceMappingsSuite) Test_DeleteResourceMapping() {
	attrValue := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value1")
	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.Id,
		Terms:            []string{"term1", "term2"},
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdMapping)

	deleted, err := s.db.PolicyClient.DeleteResourceMapping(s.ctx, createdMapping.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), deleted)

	deletedMapping, err := s.db.PolicyClient.GetResourceMapping(s.ctx, createdMapping.Id)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), deletedMapping)
}

func (s *ResourceMappingsSuite) Test_DeleteResourceMappingWithUnknownIdFails() {
	deleted, err := s.db.PolicyClient.DeleteResourceMapping(s.ctx, nonExistentResourceMappingUUID)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), deleted)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func TestResourceMappingsSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping resource mappings integration tests")
	}
	suite.Run(t, new(ResourceMappingsSuite))
}
