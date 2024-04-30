package integration

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
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
		s.f.GetResourceMappingKey("resource_mapping_to_attribute_value4"),
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
	s.NoError(err)
	s.NotNil(createdMapping)
}

func (s *ResourceMappingsSuite) Test_CreateResourceMappingWithUnknownAttributeValueFails() {
	metadata := &common.MetadataMutable{}

	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: nonExistentAttributeValueUuid,
		Metadata:         metadata,
		Terms:            []string{"term1", "term2"},
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	s.NotNil(err)
	s.Nil(createdMapping)
	s.ErrorIs(err, db.ErrForeignKeyViolation)
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
	s.NoError(err)
	s.NotNil(createdMapping)
	s.NotNil(createdMapping.GetTerms())
	s.Equal(len(createdMapping.GetTerms()), 0)
}

func (s *ResourceMappingsSuite) Test_ListResourceMappings() {
	// make sure we can get all fixtures
	testData := s.getResourceMappingFixtures()
	mappings, err := s.db.PolicyClient.ListResourceMappings(s.ctx)
	s.NoError(err)
	s.NotNil(mappings)
	for _, testMapping := range testData {
		found := false
		for _, mapping := range mappings {
			if testMapping.Id == mapping.GetId() {
				found = true
				break
			}
		}
		s.True(found, fmt.Sprintf("expected to find mapping %s", testMapping.Id))
	}
}

func (s *ResourceMappingsSuite) Test_GetResourceMapping() {
	// make sure we can get all fixtures
	testData := s.getResourceMappingFixtures()
	testedMembers := false
	for idx, testMapping := range testData {
		mapping, err := s.db.PolicyClient.GetResourceMapping(s.ctx, testMapping.Id)
		s.NoError(err)
		s.NotNil(mapping)
		s.Equal(testMapping.Id, mapping.GetId())
		s.Equal(testMapping.AttributeValueId, mapping.GetAttributeValue().GetId())
		s.Equal(testMapping.Terms, mapping.GetTerms())
		av, err := s.db.PolicyClient.GetAttributeValue(s.ctx, testMapping.AttributeValueId)
		s.NoError(err)
		if len(av.GetMembers()) > 0 {
			testedMembers = true
		}
		if idx == len(testData)-1 {
			s.True(testedMembers, "expected to test at least one attribute value member")
		}
		equalMembers(s.T(), av, mapping.GetAttributeValue(), false)
		metadata := mapping.GetMetadata()
		createdAt := metadata.GetCreatedAt()
		updatedAt := metadata.GetUpdatedAt()
		s.True(createdAt.IsValid() && createdAt.AsTime().Unix() > 0)
		s.True(updatedAt.IsValid() && updatedAt.AsTime().Unix() > 0)
	}
}

func (s *ResourceMappingsSuite) Test_GetResourceMappingWithUnknownIdFails() {
	mapping, err := s.db.PolicyClient.GetResourceMapping(s.ctx, nonExistentResourceMappingUUID)
	s.NotNil(err)
	s.Nil(mapping)
	s.ErrorIs(err, db.ErrNotFound)
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
	s.NoError(err)
	s.NotNil(createdMapping)

	got, err := s.db.PolicyClient.GetResourceMapping(s.ctx, createdMapping.GetId())
	s.NoError(err)
	s.NotNil(mapping)
	s.Equal(createdMapping.GetId(), got.GetId())
	s.Equal(createdMapping.GetAttributeValue().GetId(), got.GetAttributeValue().GetId())
	s.Equal(createdMapping.GetTerms(), mapping.GetTerms())
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
	start := time.Now().Add(-time.Second)
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.Id,
		Metadata: &common.MetadataMutable{
			Labels: labels,
		},
		Terms: terms,
	})
	end := time.Now().Add(time.Second)
	metadata := createdMapping.GetMetadata()
	updatedAt := metadata.GetUpdatedAt()
	createdAt := metadata.GetCreatedAt()
	s.True(createdAt.AsTime().After(start))
	s.True(createdAt.AsTime().Before(end))
	s.NoError(err)
	s.NotNil(createdMapping)

	if v, err := s.db.PolicyClient.GetResourceMapping(s.ctx, createdMapping.GetId()); err != nil {
		s.NoError(err)
	} else {
		s.NotNil(v)
		s.Equal(createdMapping.GetId(), v.GetId())
		s.Equal(createdMapping.GetAttributeValue().GetId(), v.GetAttributeValue().GetId())
		s.Equal(createdMapping.GetTerms(), v.GetTerms())
	}

	updateWithoutChange, err := s.db.PolicyClient.UpdateResourceMapping(s.ctx, createdMapping.GetId(), &resourcemapping.UpdateResourceMappingRequest{})
	s.NoError(err)
	s.NotNil(updateWithoutChange)
	s.Equal(createdMapping.GetId(), updateWithoutChange.GetId())

	// update the created with new metadata and terms
	updateWithChange, err := s.db.PolicyClient.UpdateResourceMapping(s.ctx, createdMapping.GetId(), &resourcemapping.UpdateResourceMappingRequest{
		AttributeValueId: createdMapping.GetAttributeValue().GetId(),
		Terms:            updateTerms,
		Metadata: &common.MetadataMutable{
			Labels: updateLabels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	s.NoError(err)
	s.NotNil(updateWithChange)
	s.Equal(createdMapping.GetId(), updateWithChange.GetId())

	// get after update to verify db reflects changes made
	got, err := s.db.PolicyClient.GetResourceMapping(s.ctx, createdMapping.GetId())
	s.NoError(err)
	s.NotNil(got)
	s.Equal(createdMapping.GetId(), got.GetId())
	s.Equal(createdMapping.GetAttributeValue().GetId(), got.GetAttributeValue().GetId())
	s.Equal(updateTerms, got.GetTerms())
	s.EqualValues(expectedLabels, got.GetMetadata().GetLabels())
	s.True(got.GetMetadata().GetUpdatedAt().AsTime().After(updatedAt.AsTime()))
}

func (s *ResourceMappingsSuite) Test_UpdateResourceMappingWithUnknownIdFails() {
	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value2")
	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.Id,
		Terms:            []string{"asdf qwerty"},
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	s.NoError(err)
	s.NotNil(createdMapping)

	// update the created with new metadata and terms
	updatedMapping := &resourcemapping.UpdateResourceMappingRequest{
		AttributeValueId: createdMapping.GetAttributeValue().GetId(),
		Terms:            []string{"asdf updated term1"},
	}
	updated, err := s.db.PolicyClient.UpdateResourceMapping(s.ctx, nonExistentResourceMappingUUID, updatedMapping)
	s.NotNil(err)
	s.Nil(updated)
	s.ErrorIs(err, db.ErrNotFound)
}

func (s *ResourceMappingsSuite) Test_UpdateResourceMappingWithUnknownAttributeValueIdFails() {
	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value2")
	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.Id,
		Terms:            []string{"testing"},
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	s.NoError(err)
	s.NotNil(createdMapping)

	m, err := s.db.PolicyClient.GetResourceMapping(s.ctx, createdMapping.GetId())
	s.NoError(err)
	s.NotNil(m)
	s.Equal(createdMapping.GetId(), m.GetId())

	// update the created with new metadata and terms
	updatedMapping := &resourcemapping.UpdateResourceMappingRequest{
		AttributeValueId: nonExistentAttributeValueUuid,
		Terms:            []string{"testing-2"},
	}
	updated, err := s.db.PolicyClient.UpdateResourceMapping(s.ctx, createdMapping.GetId(), updatedMapping)
	s.NotNil(err)
	s.Nil(updated)
	s.ErrorIs(err, db.ErrForeignKeyViolation)
}

func (s *ResourceMappingsSuite) Test_DeleteResourceMapping() {
	attrValue := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value1")
	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.Id,
		Terms:            []string{"term1", "term2"},
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	s.NoError(err)
	s.NotNil(createdMapping)

	deleted, err := s.db.PolicyClient.DeleteResourceMapping(s.ctx, createdMapping.GetId())
	s.NoError(err)
	s.NotNil(deleted)

	deletedMapping, err := s.db.PolicyClient.GetResourceMapping(s.ctx, createdMapping.GetId())
	s.NotNil(err)
	s.Nil(deletedMapping)
}

func (s *ResourceMappingsSuite) Test_DeleteResourceMappingWithUnknownIdFails() {
	deleted, err := s.db.PolicyClient.DeleteResourceMapping(s.ctx, nonExistentResourceMappingUUID)
	s.NotNil(err)
	s.Nil(deleted)
	s.ErrorIs(err, db.ErrNotFound)
}

func TestResourceMappingsSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping resource mappings integration tests")
	}
	suite.Run(t, new(ResourceMappingsSuite))
}
