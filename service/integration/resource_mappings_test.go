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

var unknownNamespaceID = "64257d69-c007-4893-931a-434f1819a4f7"
var unknownResourceMappingGroupID = "c70cad07-21b4-4cb1-9095-bce54615536a"
var unknownResourceMappingID = "45674556-8888-9999-9999-000001230000"

type ResourceMappingsSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context //nolint:containedctx // context is used in the test suite
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

func (s *ResourceMappingsSuite) getExampleDotComNamespace() *fixtures.FixtureDataNamespace {
	namespace := s.f.GetNamespaceKey("example.com")
	return &namespace
}

func (s *ResourceMappingsSuite) getScenarioDotComNamespace() *fixtures.FixtureDataNamespace {
	namespace := s.f.GetNamespaceKey("scenario.com")
	return &namespace
}

func (s *ResourceMappingsSuite) getResourceMappingGroupFixtures() []fixtures.FixtureDataResourceMappingGroup {
	return []fixtures.FixtureDataResourceMappingGroup{
		s.f.GetResourceMappingGroupKey("example.com_ns_group_1"),
		s.f.GetResourceMappingGroupKey("example.com_ns_group_2"),
		s.f.GetResourceMappingGroupKey("scenario.com_ns_group_1"),
	}
}

func (s *ResourceMappingsSuite) getResourceMappingFixtures() []fixtures.FixtureDataResourceMapping {
	return []fixtures.FixtureDataResourceMapping{
		s.f.GetResourceMappingKey("resource_mapping_to_attribute_value1"),
		s.f.GetResourceMappingKey("resource_mapping_to_attribute_value2"),
		s.f.GetResourceMappingKey("resource_mapping_to_attribute_value3"),
	}
}

/*
 Resource Mapping Groups
*/

func (s *ResourceMappingsSuite) Test_ListResourceMappingGroups() {
	testData := s.getResourceMappingGroupFixtures()
	rmGroups, err := s.db.PolicyClient.ListResourceMappingGroups(s.ctx, &resourcemapping.ListResourceMappingGroupsRequest{})
	s.Require().NoError(err)
	s.NotNil(rmGroups)
	for _, testRmGroup := range testData {
		found := false
		for _, rmGroup := range rmGroups {
			if testRmGroup.ID == rmGroup.GetId() {
				found = true
				break
			}
		}
		s.True(found, fmt.Sprintf("expected to find resource mapping group %s", testRmGroup.ID))
	}
}

func (s *ResourceMappingsSuite) Test_ListResourceMappingGroupsWithNamespaceIdSucceeds() {
	scenarioDotComRmGroup := s.f.GetResourceMappingGroupKey("scenario.com_ns_group_1")
	rmGroups, err := s.db.PolicyClient.ListResourceMappingGroups(s.ctx, &resourcemapping.ListResourceMappingGroupsRequest{
		NamespaceId: scenarioDotComRmGroup.NamespaceID,
	})
	s.Require().NoError(err)
	s.NotNil(rmGroups)
	s.Len(rmGroups, 1)
	s.Equal(scenarioDotComRmGroup.ID, rmGroups[0].GetId())
	s.Equal(scenarioDotComRmGroup.NamespaceID, rmGroups[0].GetNamespaceId())
	s.Equal(scenarioDotComRmGroup.Name, rmGroups[0].GetName())
}

func (s *ResourceMappingsSuite) Test_ListResourceMappingGroupsByFqns() {
	exampleDotComNs := s.getExampleDotComNamespace()
	exampleDotComRmGroup1 := s.f.GetResourceMappingGroupKey("example.com_ns_group_1")
	exampleDotComRmGroup2 := s.f.GetResourceMappingGroupKey("example.com_ns_group_2")

	group1Fqn := fmt.Sprintf("https://%s/resm/%s", exampleDotComNs.Name, exampleDotComRmGroup1.Name)
	group2Fqn := fmt.Sprintf("https://%s/resm/%s", exampleDotComNs.Name, exampleDotComRmGroup2.Name)

	fqnRmGroupMap, err := s.db.PolicyClient.ListResourceMappingGroupsByFqns(s.ctx, []string{group1Fqn, group2Fqn})
	s.Require().NoError(err)
	s.NotNil(fqnRmGroupMap)

	group1Resp, ok := fqnRmGroupMap[group1Fqn]
	s.True(ok)
	s.NotNil(group1Resp)
	s.Equal(exampleDotComRmGroup1.ID, group1Resp.GetId())
	s.Equal(exampleDotComNs.ID, group1Resp.GetNamespaceId())
	s.Equal(exampleDotComRmGroup1.Name, group1Resp.GetName())

	group2Resp, ok := fqnRmGroupMap[group2Fqn]
	s.True(ok)
	s.NotNil(group2Resp)
	s.Equal(exampleDotComRmGroup2.ID, group2Resp.GetId())
	s.Equal(exampleDotComNs.ID, group2Resp.GetNamespaceId())
	s.Equal(exampleDotComRmGroup2.Name, group2Resp.GetName())
}

func (s *ResourceMappingsSuite) Test_ListResourceMappingGroupsByFqnsWithEmptyOrNilFqnsFails() {
	fqnRmGroupMap, err := s.db.PolicyClient.ListResourceMappingGroupsByFqns(s.ctx, nil)
	s.Require().Error(err)
	s.Nil(fqnRmGroupMap)

	fqnRmGroupMap, err = s.db.PolicyClient.ListResourceMappingGroupsByFqns(s.ctx, []string{})
	s.Require().Error(err)
	s.Nil(fqnRmGroupMap)
}

func (s *ResourceMappingsSuite) Test_ListResourceMappingGroupsByFqnsWithInvalidFqnsFails() {
	fqnRmGroupMap, err := s.db.PolicyClient.ListResourceMappingGroupsByFqns(s.ctx, []string{"invalid_fqn"})
	s.Require().Error(err)
	s.Nil(fqnRmGroupMap)
}

func (s *ResourceMappingsSuite) Test_ListResourceMappingGroupsByFqnsWithUnknownFqnsFails() {
	unknownFqn := "https://unknown.com/resm/unknown_group"
	fqnRmGroupMap, err := s.db.PolicyClient.ListResourceMappingGroupsByFqns(s.ctx, []string{unknownFqn})
	s.Require().Error(err)
	s.Nil(fqnRmGroupMap)
}

func (s *ResourceMappingsSuite) Test_ListResourceMappingGroupsByFqnsWithKnownAndUnknownFqnsSucceeds() {
	exampleDotComNs := s.getExampleDotComNamespace()
	exampleDotComRmGroup1 := s.f.GetResourceMappingGroupKey("example.com_ns_group_1")

	group1Fqn := fmt.Sprintf("https://%s/resm/%s", exampleDotComNs.Name, exampleDotComRmGroup1.Name)
	unknownFqn := "https://unknown.com/resm/unknown_group"

	fqnRmGroupMap, err := s.db.PolicyClient.ListResourceMappingGroupsByFqns(s.ctx, []string{group1Fqn, unknownFqn})
	s.Require().NoError(err)
	s.NotNil(fqnRmGroupMap)

	group1Resp, ok := fqnRmGroupMap[group1Fqn]
	s.True(ok)
	s.NotNil(group1Resp)
	s.Equal(exampleDotComRmGroup1.ID, group1Resp.GetId())
	s.Equal(exampleDotComNs.ID, group1Resp.GetNamespaceId())
	s.Equal(exampleDotComRmGroup1.Name, group1Resp.GetName())

	unknownResp, ok := fqnRmGroupMap[unknownFqn]
	s.True(ok)
	s.Nil(unknownResp)
}

func (s *ResourceMappingsSuite) Test_ListResourceMappingGroupsByFqnsWithKnownAndInvalidFqnsSucceeds() {
	exampleDotComNs := s.getExampleDotComNamespace()
	exampleDotComRmGroup1 := s.f.GetResourceMappingGroupKey("example.com_ns_group_1")

	group1Fqn := fmt.Sprintf("https://%s/resm/%s", exampleDotComNs.Name, exampleDotComRmGroup1.Name)
	invalidFqn := "invalid_fqn"

	fqnRmGroupMap, err := s.db.PolicyClient.ListResourceMappingGroupsByFqns(s.ctx, []string{group1Fqn, invalidFqn})
	s.Require().NoError(err)
	s.NotNil(fqnRmGroupMap)

	group1Resp, ok := fqnRmGroupMap[group1Fqn]
	s.True(ok)
	s.NotNil(group1Resp)
	s.Equal(exampleDotComRmGroup1.ID, group1Resp.GetId())
	s.Equal(exampleDotComNs.ID, group1Resp.GetNamespaceId())
	s.Equal(exampleDotComRmGroup1.Name, group1Resp.GetName())

	unknownResp, ok := fqnRmGroupMap[invalidFqn]
	s.False(ok)
	s.Nil(unknownResp)
}

func (s *ResourceMappingsSuite) Test_GetResourceMappingGroup() {
	testRmGroup := s.f.GetResourceMappingGroupKey("example.com_ns_group_1")
	rmGroup, err := s.db.PolicyClient.GetResourceMappingGroup(s.ctx, testRmGroup.ID)
	s.Require().NoError(err)
	s.NotNil(rmGroup)
	s.Equal(testRmGroup.ID, rmGroup.GetId())
	s.Equal(testRmGroup.NamespaceID, rmGroup.GetNamespaceId())
	s.Equal(testRmGroup.Name, rmGroup.GetName())
}

func (s *ResourceMappingsSuite) Test_GetResourceMappingGroupWithUnknownIdFails() {
	rmGroup, err := s.db.PolicyClient.GetResourceMappingGroup(s.ctx, unknownResourceMappingGroupID)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(rmGroup)
}

func (s *ResourceMappingsSuite) Test_CreateResourceMappingGroup() {
	req := &resourcemapping.CreateResourceMappingGroupRequest{
		NamespaceId: s.getExampleDotComNamespace().ID,
		Name:        "example.com_ns_new_group",
	}
	rmGroup, err := s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(rmGroup)
}

func (s *ResourceMappingsSuite) Test_CreateResourceMappingGroupWithUnknownNamespaceIdFails() {
	req := &resourcemapping.CreateResourceMappingGroupRequest{
		NamespaceId: unknownNamespaceID,
		Name:        "unknown_ns_new_group",
	}
	rmGroup, err := s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, req)
	s.Require().Error(err)
	s.Nil(rmGroup)
}

func (s *ResourceMappingsSuite) Test_CreateResourceMappingGroupWithDuplicateNamespaceIdAndNameComboFails() {
	name := "example.com_ns_dupe_group"
	req := &resourcemapping.CreateResourceMappingGroupRequest{
		NamespaceId: s.getExampleDotComNamespace().ID,
		Name:        name,
	}
	rmGroup, err := s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(rmGroup)

	rmGroup, err = s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, req)
	s.Require().Error(err)
	s.Nil(rmGroup)
}

func (s *ResourceMappingsSuite) Test_UpdateResourceMappingGroup() {
	req := &resourcemapping.CreateResourceMappingGroupRequest{
		NamespaceId: s.getExampleDotComNamespace().ID,
		Name:        "example.com_ns_group_created",
	}
	rmGroup, err := s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(rmGroup)

	updateReq := &resourcemapping.UpdateResourceMappingGroupRequest{
		Id:          rmGroup.GetId(),
		NamespaceId: s.getScenarioDotComNamespace().ID,
		Name:        "example.com_ns_group_updated",
	}
	updatedRmGroup, err := s.db.PolicyClient.UpdateResourceMappingGroup(s.ctx, rmGroup.GetId(), updateReq)
	s.Require().NoError(err)
	s.NotNil(updatedRmGroup)

	// get after update to verify db reflects changes made
	gotUpdatedRmGroup, err := s.db.PolicyClient.GetResourceMappingGroup(s.ctx, updatedRmGroup.GetId())
	s.Require().NoError(err)
	s.NotNil(gotUpdatedRmGroup)
	s.Equal(updateReq.GetNamespaceId(), gotUpdatedRmGroup.GetNamespaceId())
	s.Equal(updateReq.GetName(), gotUpdatedRmGroup.GetName())
}

func (s *ResourceMappingsSuite) Test_UpdateResourceMappingGroupWithUnknownIdFails() {
	req := &resourcemapping.CreateResourceMappingGroupRequest{
		NamespaceId: s.getExampleDotComNamespace().ID,
		Name:        "example.com_ns_group_created",
	}
	rmGroup, err := s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(rmGroup)

	updateReq := &resourcemapping.UpdateResourceMappingGroupRequest{
		Id:          rmGroup.GetId(),
		NamespaceId: unknownNamespaceID,
		Name:        "example.com_ns_group_updated",
	}
	updatedRmGroup, err := s.db.PolicyClient.UpdateResourceMappingGroup(s.ctx, rmGroup.GetId(), updateReq)
	s.Require().Error(err)
	s.Nil(updatedRmGroup)
}

func (s *ResourceMappingsSuite) Test_UpdateResourceMappingGroupWithNamespaceIdOnlySucceeds() {
	req := &resourcemapping.CreateResourceMappingGroupRequest{
		NamespaceId: s.getExampleDotComNamespace().ID,
		Name:        "example.com_ns_group_created",
	}
	rmGroup, err := s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(rmGroup)

	updateReq := &resourcemapping.UpdateResourceMappingGroupRequest{
		Id:          rmGroup.GetId(),
		NamespaceId: s.getScenarioDotComNamespace().ID,
	}
	updatedRmGroup, err := s.db.PolicyClient.UpdateResourceMappingGroup(s.ctx, rmGroup.GetId(), updateReq)
	s.Require().NoError(err)
	s.NotNil(updatedRmGroup)

	// get after update to verify ONLY namespace id is updated
	gotUpdatedRmGroup, err := s.db.PolicyClient.GetResourceMappingGroup(s.ctx, updatedRmGroup.GetId())
	s.Require().NoError(err)
	s.NotNil(gotUpdatedRmGroup)
	s.Equal(updateReq.GetNamespaceId(), gotUpdatedRmGroup.GetNamespaceId())
	s.Equal(req.GetName(), gotUpdatedRmGroup.GetName())
}

func (s *ResourceMappingsSuite) Test_UpdateResourceMappingGroupWithNameOnlySucceeds() {
	req := &resourcemapping.CreateResourceMappingGroupRequest{
		NamespaceId: s.getExampleDotComNamespace().ID,
		Name:        "example.com_ns_group_created",
	}
	rmGroup, err := s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(rmGroup)

	updateReq := &resourcemapping.UpdateResourceMappingGroupRequest{
		Id:   rmGroup.GetId(),
		Name: "example.com_ns_group_updated",
	}
	updatedRmGroup, err := s.db.PolicyClient.UpdateResourceMappingGroup(s.ctx, rmGroup.GetId(), updateReq)
	s.Require().NoError(err)
	s.NotNil(updatedRmGroup)

	// get after update to verify ONLY name is updated
	gotUpdatedRmGroup, err := s.db.PolicyClient.GetResourceMappingGroup(s.ctx, updatedRmGroup.GetId())
	s.Require().NoError(err)
	s.NotNil(gotUpdatedRmGroup)
	s.Equal(req.GetNamespaceId(), gotUpdatedRmGroup.GetNamespaceId())
	s.Equal(updateReq.GetName(), gotUpdatedRmGroup.GetName())
}

func (s *ResourceMappingsSuite) Test_DeleteResourceMappingGroup() {
	// create a group
	group := &resourcemapping.CreateResourceMappingGroupRequest{
		NamespaceId: s.getExampleDotComNamespace().ID,
		Name:        "example.com_ns_group_to_delete",
	}
	createdGroup, err := s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, group)
	s.Require().NoError(err)
	s.NotNil(createdGroup)

	// create a mapping with the group
	metadata := &common.MetadataMutable{}
	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.ID,
		Metadata:         metadata,
		Terms:            []string{},
		GroupId:          createdGroup.GetId(),
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	s.Require().NoError(err)
	s.NotNil(createdMapping)

	// delete the group
	deletedGroup, err := s.db.PolicyClient.DeleteResourceMappingGroup(s.ctx, createdGroup.GetId())
	s.Require().NoError(err)
	s.NotNil(deletedGroup)
	s.Equal(createdGroup.GetId(), deletedGroup.GetId())

	// get the mapping to verify group id is cascade set to null
	gotMapping, err := s.db.PolicyClient.GetResourceMapping(s.ctx, createdMapping.GetId())
	s.Require().NoError(err)
	s.NotNil(gotMapping)
	s.Nil(gotMapping.GetGroup())
}

/*
 Resource Mappings
*/

func (s *ResourceMappingsSuite) Test_CreateResourceMapping() {
	metadata := &common.MetadataMutable{
		Labels: map[string]string{
			"name": "this is the test name of my resource mapping",
		},
	}

	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.ID,
		Metadata:         metadata,
		Terms:            []string{"term1", "term2"},
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	s.Require().NoError(err)
	s.NotNil(createdMapping)
	s.Equal(mapping.GetAttributeValueId(), createdMapping.GetAttributeValue().GetId())
	s.Equal(mapping.GetMetadata().GetLabels()["name"], createdMapping.GetMetadata().GetLabels()["name"])
	s.Equal(mapping.GetTerms(), createdMapping.GetTerms())
	s.Nil(createdMapping.GetGroup())
}

func (s *ResourceMappingsSuite) Test_CreateResourceMappingWithUnknownAttributeValueFails() {
	metadata := &common.MetadataMutable{}

	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: absentAttributeValueUUID,
		Metadata:         metadata,
		Terms:            []string{"term1", "term2"},
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	s.Require().Error(err)
	s.Nil(createdMapping)
	s.Require().ErrorIs(err, db.ErrForeignKeyViolation)
}

func (s *ResourceMappingsSuite) Test_CreateResourceMappingWithEmptyTermsSucceeds() {
	metadata := &common.MetadataMutable{}

	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value2")
	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.ID,
		Metadata:         metadata,
		Terms:            []string{},
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	s.Require().NoError(err)
	s.NotNil(createdMapping)
	s.NotNil(createdMapping.GetTerms())
	s.Empty(createdMapping.GetTerms())
}

func (s *ResourceMappingsSuite) Test_CreateResourceMappingWithGroupIdSucceeds() {
	metadata := &common.MetadataMutable{}

	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	rmGroup := s.getResourceMappingGroupFixtures()[0]
	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.ID,
		Metadata:         metadata,
		Terms:            []string{},
		GroupId:          rmGroup.ID,
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	s.Require().NoError(err)
	s.NotNil(createdMapping)
	s.Equal(rmGroup.ID, createdMapping.GetGroup().GetId())
}

func (s *ResourceMappingsSuite) Test_CreateResourceMappingWithUnknownGroupIdFails() {
	metadata := &common.MetadataMutable{}

	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.ID,
		Metadata:         metadata,
		Terms:            []string{},
		GroupId:          unknownResourceMappingGroupID,
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	s.Require().Error(err)
	s.Nil(createdMapping)
}

func (s *ResourceMappingsSuite) Test_ListResourceMappings() {
	// make sure we can get all fixtures
	testData := s.getResourceMappingFixtures()
	mappings, err := s.db.PolicyClient.ListResourceMappings(s.ctx)
	s.Require().NoError(err)
	s.NotNil(mappings)
	for _, testMapping := range testData {
		found := false
		for _, mapping := range mappings {
			if testMapping.ID == mapping.GetId() {
				found = true
				break
			}
		}
		s.True(found, fmt.Sprintf("expected to find mapping %s", testMapping.ID))
	}
}

func (s *ResourceMappingsSuite) Test_GetResourceMapping() {
	// make sure we can get all fixtures
	testData := s.getResourceMappingFixtures()
	for _, testMapping := range testData {
		mapping, err := s.db.PolicyClient.GetResourceMapping(s.ctx, testMapping.ID)
		s.Require().NoError(err)
		s.NotNil(mapping)
		s.Equal(testMapping.ID, mapping.GetId())
		s.Equal(testMapping.AttributeValueID, mapping.GetAttributeValue().GetId())
		s.Equal(testMapping.Terms, mapping.GetTerms())
		s.Equal(testMapping.GroupID, mapping.GetGroup().GetId())
		metadata := mapping.GetMetadata()
		createdAt := metadata.GetCreatedAt()
		updatedAt := metadata.GetUpdatedAt()
		s.True(createdAt.IsValid() && createdAt.AsTime().Unix() > 0)
		s.True(updatedAt.IsValid() && updatedAt.AsTime().Unix() > 0)
	}
}

func (s *ResourceMappingsSuite) Test_GetResourceMappingWithUnknownIdFails() {
	mapping, err := s.db.PolicyClient.GetResourceMapping(s.ctx, unknownResourceMappingID)
	s.Require().Error(err)
	s.Nil(mapping)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *ResourceMappingsSuite) Test_GetResourceMappingOfCreatedSucceeds() {
	metadata := &common.MetadataMutable{}

	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value2")
	rmGroup := s.getResourceMappingGroupFixtures()[0]
	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.ID,
		Metadata:         metadata,
		Terms:            []string{"term1", "term2"},
		GroupId:          rmGroup.ID,
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	s.Require().NoError(err)
	s.NotNil(createdMapping)

	got, err := s.db.PolicyClient.GetResourceMapping(s.ctx, createdMapping.GetId())
	s.Require().NoError(err)
	s.NotNil(mapping)
	s.Equal(createdMapping.GetId(), got.GetId())
	s.Equal(createdMapping.GetAttributeValue().GetId(), got.GetAttributeValue().GetId())
	s.Equal(createdMapping.GetTerms(), mapping.GetTerms())
	s.Equal(createdMapping.GetGroup().GetId(), got.GetGroup().GetId())
}

func (s *ResourceMappingsSuite) Test_UpdateResourceMapping() {
	fixedLabel := "fixed label"
	updateLabel := "update label"
	updatedLabel := "true"
	newLabel := "new label"

	rmGroup := s.getResourceMappingGroupFixtures()[0]

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
		AttributeValueId: attrValue.ID,
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
	s.Require().NoError(err)
	s.NotNil(createdMapping)

	if v, err := s.db.PolicyClient.GetResourceMapping(s.ctx, createdMapping.GetId()); err != nil {
		s.Require().NoError(err)
	} else {
		s.NotNil(v)
		s.Equal(createdMapping.GetId(), v.GetId())
		s.Equal(createdMapping.GetAttributeValue().GetId(), v.GetAttributeValue().GetId())
		s.Equal(createdMapping.GetTerms(), v.GetTerms())
	}

	updateWithoutChange, err := s.db.PolicyClient.UpdateResourceMapping(s.ctx, createdMapping.GetId(), &resourcemapping.UpdateResourceMappingRequest{})
	s.Require().NoError(err)
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
		GroupId:                rmGroup.ID,
	})
	s.Require().NoError(err)
	s.NotNil(updateWithChange)
	s.Equal(createdMapping.GetId(), updateWithChange.GetId())

	// get after update to verify db reflects changes made
	got, err := s.db.PolicyClient.GetResourceMapping(s.ctx, createdMapping.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(createdMapping.GetId(), got.GetId())
	s.Equal(createdMapping.GetAttributeValue().GetId(), got.GetAttributeValue().GetId())
	s.Equal(updateTerms, got.GetTerms())
	s.EqualValues(expectedLabels, got.GetMetadata().GetLabels())
	s.True(got.GetMetadata().GetUpdatedAt().AsTime().After(updatedAt.AsTime()))
	s.Equal(rmGroup.ID, got.GetGroup().GetId())
}

func (s *ResourceMappingsSuite) Test_UpdateResourceMappingWithUnknownIdFails() {
	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value2")
	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.ID,
		Terms:            []string{"asdf qwerty"},
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	s.Require().NoError(err)
	s.NotNil(createdMapping)

	// update the created with new metadata and terms
	updatedMapping := &resourcemapping.UpdateResourceMappingRequest{
		AttributeValueId: createdMapping.GetAttributeValue().GetId(),
		Terms:            []string{"asdf updated term1"},
	}
	updated, err := s.db.PolicyClient.UpdateResourceMapping(s.ctx, unknownResourceMappingID, updatedMapping)
	s.Require().Error(err)
	s.Nil(updated)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *ResourceMappingsSuite) Test_UpdateResourceMappingWithUnknownAttributeValueIdFails() {
	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value2")
	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.ID,
		Terms:            []string{"testing"},
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	s.Require().NoError(err)
	s.NotNil(createdMapping)

	m, err := s.db.PolicyClient.GetResourceMapping(s.ctx, createdMapping.GetId())
	s.Require().NoError(err)
	s.NotNil(m)
	s.Equal(createdMapping.GetId(), m.GetId())

	// update the created with new metadata and terms
	updatedMapping := &resourcemapping.UpdateResourceMappingRequest{
		AttributeValueId: absentAttributeValueUUID,
		Terms:            []string{"testing-2"},
	}
	updated, err := s.db.PolicyClient.UpdateResourceMapping(s.ctx, createdMapping.GetId(), updatedMapping)
	s.Require().Error(err)
	s.Nil(updated)
	s.Require().ErrorIs(err, db.ErrForeignKeyViolation)
}

func (s *ResourceMappingsSuite) Test_UpdateResourceMappingWithUnknownGroupIdFails() {
	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value2")
	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.ID,
		Terms:            []string{"asdf qwerty"},
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	s.Require().NoError(err)
	s.NotNil(createdMapping)

	// update the created with new metadata, terms and unknown group ID
	updatedMapping := &resourcemapping.UpdateResourceMappingRequest{
		AttributeValueId: createdMapping.GetAttributeValue().GetId(),
		Terms:            []string{"asdf updated term1"},
		GroupId:          unknownResourceMappingGroupID,
	}
	updated, err := s.db.PolicyClient.UpdateResourceMapping(s.ctx, unknownResourceMappingID, updatedMapping)
	s.Require().Error(err)
	s.Nil(updated)
}

func (s *ResourceMappingsSuite) Test_DeleteResourceMapping() {
	attrValue := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value1")
	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.ID,
		Terms:            []string{"term1", "term2"},
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	s.Require().NoError(err)
	s.NotNil(createdMapping)

	deleted, err := s.db.PolicyClient.DeleteResourceMapping(s.ctx, createdMapping.GetId())
	s.Require().NoError(err)
	s.NotNil(deleted)

	deletedMapping, err := s.db.PolicyClient.GetResourceMapping(s.ctx, createdMapping.GetId())
	s.Require().Error(err)
	s.Nil(deletedMapping)
}

func (s *ResourceMappingsSuite) Test_DeleteResourceMappingWithUnknownIdFails() {
	deleted, err := s.db.PolicyClient.DeleteResourceMapping(s.ctx, unknownResourceMappingID)
	s.Require().Error(err)
	s.Nil(deleted)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func TestResourceMappingsSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping resource mappings integration tests")
	}
	suite.Run(t, new(ResourceMappingsSuite))
}
