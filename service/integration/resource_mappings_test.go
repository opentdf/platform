package integration

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/proto"
)

const (
	unknownNamespaceID            = "64257d69-c007-4893-931a-434f1819a4f7"
	unknownResourceMappingGroupID = "c70cad07-21b4-4cb1-9095-bce54615536a"
	unknownResourceMappingID      = "45674556-8888-9999-9999-000001230000"
)

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
	}
}

// these are the attribute values that are used in the getResourceMappingFixtures method above
func (s *ResourceMappingsSuite) getResourceMappingAttributeValueFixtures() []fixtures.FixtureDataAttributeValue {
	return []fixtures.FixtureDataAttributeValue{
		s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1"),
		s.f.GetAttributeValueKey("example.com/attr/attr1/value/value2"),
	}
}

/*
 Resource Mapping Groups
*/

func (s *ResourceMappingsSuite) Test_ListResourceMappingGroups_NoPagination_Succeeds() {
	testData := s.getResourceMappingGroupFixtures()
	listRmGroupsRsp, err := s.db.PolicyClient.ListResourceMappingGroups(s.ctx, &resourcemapping.ListResourceMappingGroupsRequest{})
	s.Require().NoError(err)
	s.NotNil(listRmGroupsRsp)
	listed := listRmGroupsRsp.GetResourceMappingGroups()
	for _, testRmGroup := range testData {
		found := false
		for _, rmGroup := range listed {
			if testRmGroup.ID == rmGroup.GetId() {
				found = true
				break
			}
		}
		s.True(found, fmt.Sprintf("expected to find resource mapping group %s", testRmGroup.ID))
	}
}

func (s *ResourceMappingsSuite) Test_ListResourceMappingGroups_Limit_Succeeds() {
	var limit int32 = 2
	listRsp, err := s.db.PolicyClient.ListResourceMappingGroups(s.ctx, &resourcemapping.ListResourceMappingGroupsRequest{
		Pagination: &policy.PageRequest{
			Limit: limit,
		},
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)
	listed := listRsp.GetResourceMappingGroups()
	s.Equal(len(listed), int(limit))

	for _, rmg := range listed {
		s.NotEmpty(rmg.GetNamespaceId())
		s.NotEmpty(rmg.GetId())
		s.NotEmpty(rmg.GetName())
	}
}

func (s *NamespacesSuite) Test_ListResourceMappingGroups_Limit_TooLarge_Fails() {
	listRsp, err := s.db.PolicyClient.ListResourceMappingGroups(s.ctx, &resourcemapping.ListResourceMappingGroupsRequest{
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax + 1,
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrListLimitTooLarge)
	s.Nil(listRsp)
}

func (s *ResourceMappingsSuite) Test_ListResourceMappingGroups_Offset_Succeeds() {
	req := &resourcemapping.ListResourceMappingGroupsRequest{}
	// make initial list request to compare against
	listRsp, err := s.db.PolicyClient.ListResourceMappingGroups(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(listRsp)
	listed := listRsp.GetResourceMappingGroups()

	// set the offset pagination
	offset := 2
	req.Pagination = &policy.PageRequest{
		Offset: int32(offset),
	}
	offsetListRsp, err := s.db.PolicyClient.ListResourceMappingGroups(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(offsetListRsp)
	offsetListed := offsetListRsp.GetResourceMappingGroups()

	// length is reduced by the offset amount
	s.Equal(len(offsetListed), len(listed)-offset)

	// objects are equal between offset and original list beginning at offset index
	for i, val := range offsetListed {
		s.True(proto.Equal(val, listed[i+offset]))
	}
}

func (s *ResourceMappingsSuite) Test_ListResourceMappingGroups_WithNamespaceId_Succeeds() {
	scenarioDotComRmGroup := s.f.GetResourceMappingGroupKey("scenario.com_ns_group_1")
	rmGroupsRsp, err := s.db.PolicyClient.ListResourceMappingGroups(s.ctx, &resourcemapping.ListResourceMappingGroupsRequest{
		NamespaceId: scenarioDotComRmGroup.NamespaceID,
	})
	s.Require().NoError(err)
	s.NotNil(rmGroupsRsp)
	list := rmGroupsRsp.GetResourceMappingGroups()
	s.Len(list, 1)
	s.Equal(scenarioDotComRmGroup.ID, list[0].GetId())
	s.Equal(scenarioDotComRmGroup.NamespaceID, list[0].GetNamespaceId())
	s.Equal(scenarioDotComRmGroup.Name, list[0].GetName())
}

func (s *ResourceMappingsSuite) Test_GetResourceMappingGroup() {
	testData := s.getResourceMappingGroupFixtures()
	for _, testRmGroup := range testData {
		rmGroup, err := s.db.PolicyClient.GetResourceMappingGroup(s.ctx, testRmGroup.ID)
		s.Require().NoError(err)
		s.NotNil(rmGroup)
		s.Equal(testRmGroup.ID, rmGroup.GetId())
		s.Equal(testRmGroup.NamespaceID, rmGroup.GetNamespaceId())
		s.Equal(testRmGroup.Name, rmGroup.GetName())
		metadata := rmGroup.GetMetadata()
		createdAt := metadata.GetCreatedAt()
		updatedAt := metadata.GetUpdatedAt()
		s.True(createdAt.IsValid() && createdAt.AsTime().Unix() > 0)
		s.True(updatedAt.IsValid() && updatedAt.AsTime().Unix() > 0)
	}
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

	createdGroup, err := s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, &resourcemapping.CreateResourceMappingGroupRequest{
		NamespaceId: s.getExampleDotComNamespace().ID,
		Name:        "example.com_ns_group_created",
		Metadata: &common.MetadataMutable{
			Labels: labels,
		},
	})
	s.Require().NoError(err)
	s.NotNil(createdGroup)

	updateReq := &resourcemapping.UpdateResourceMappingGroupRequest{
		NamespaceId: s.getScenarioDotComNamespace().ID,
		Name:        "example.com_ns_group_updated",
		Metadata: &common.MetadataMutable{
			Labels: updateLabels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	}
	updatedGroup, err := s.db.PolicyClient.UpdateResourceMappingGroup(s.ctx, createdGroup.GetId(), updateReq)
	s.Require().NoError(err)
	s.NotNil(updatedGroup)
	s.Equal(createdGroup.GetId(), updatedGroup.GetId())

	gotGroup, err := s.db.PolicyClient.GetResourceMappingGroup(s.ctx, createdGroup.GetId())
	s.Require().NoError(err)
	s.NotNil(gotGroup)

	s.Equal(createdGroup.GetId(), gotGroup.GetId())
	s.Equal(updateReq.GetNamespaceId(), gotGroup.GetNamespaceId())
	s.Equal(updateReq.GetName(), gotGroup.GetName())
	metadata := gotGroup.GetMetadata()
	createdAt := metadata.GetCreatedAt()
	updatedAt := metadata.GetUpdatedAt()
	s.False(createdAt.AsTime().IsZero())
	s.False(updatedAt.AsTime().IsZero())
	s.True(updatedAt.AsTime().After(createdAt.AsTime()))
	s.Equal(expectedLabels, metadata.GetLabels())
}

func (s *ResourceMappingsSuite) Test_UpdateResourceMappingGroupWithUnknownIdFails() {
	req := &resourcemapping.CreateResourceMappingGroupRequest{
		NamespaceId: s.getExampleDotComNamespace().ID,
		Name:        "example.com_ns_group_unknownidfails",
	}
	rmGroup, err := s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(rmGroup)

	updateReq := &resourcemapping.UpdateResourceMappingGroupRequest{
		Id:          rmGroup.GetId(),
		NamespaceId: unknownNamespaceID,
		Name:        "example.com_ns_group_unknownidfails_updated",
	}
	updatedRmGroup, err := s.db.PolicyClient.UpdateResourceMappingGroup(s.ctx, rmGroup.GetId(), updateReq)
	s.Require().Error(err)
	s.Nil(updatedRmGroup)
}

func (s *ResourceMappingsSuite) Test_UpdateResourceMappingGroupWithNamespaceIdOnlySucceeds() {
	req := &resourcemapping.CreateResourceMappingGroupRequest{
		NamespaceId: s.getExampleDotComNamespace().ID,
		Name:        "example.com_ns_group_created_nsidonly",
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
		Name:        "example.com_ns_group_created_nameonly",
	}
	rmGroup, err := s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(rmGroup)

	updateReq := &resourcemapping.UpdateResourceMappingGroupRequest{
		Id:   rmGroup.GetId(),
		Name: "example.com_ns_group_created_nameonly_updated",
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

func (s *ResourceMappingsSuite) Test_ListResourceMappings_NoPagination_Succeeds() {
	testMappings := make(map[string]fixtures.FixtureDataResourceMapping)
	for _, testMapping := range s.getResourceMappingFixtures() {
		testMappings[testMapping.ID] = testMapping
	}

	testValues := make(map[string]fixtures.FixtureDataAttributeValue)
	for _, testValue := range s.getResourceMappingAttributeValueFixtures() {
		testValues[testValue.ID] = testValue
	}

	listRsp, err := s.db.PolicyClient.ListResourceMappings(s.ctx, &resourcemapping.ListResourceMappingsRequest{})
	s.Require().NoError(err)
	s.NotNil(listRsp)

	list := listRsp.GetResourceMappings()
	s.NotEmpty(list)

	testMappingCount := len(testMappings)
	foundCount := 0

	for _, mapping := range list {
		testMapping, ok := testMappings[mapping.GetId()]
		if !ok {
			// only validating presence of all fixtures within the list response
			continue
		}
		foundCount++

		s.Equal(testMapping.Terms, mapping.GetTerms())
		s.Equal(testMapping.GroupID, mapping.GetGroup().GetId())
		metadata := mapping.GetMetadata()
		createdAt := metadata.GetCreatedAt()
		updatedAt := metadata.GetUpdatedAt()
		s.False(createdAt.AsTime().IsZero())
		s.False(updatedAt.AsTime().IsZero())
		s.True(updatedAt.AsTime().Equal(createdAt.AsTime()))

		value := mapping.GetAttributeValue()
		testValue, ok := testValues[value.GetId()]
		s.True(ok, "expected value %s", value.GetId())
		s.Equal(testValue.Value, value.GetValue())
		s.Equal(fmt.Sprintf("https://example.com/attr/attr1/value/%s", value.GetValue()), value.GetFqn())
	}

	s.Equal(testMappingCount, foundCount)
}

func (s *ResourceMappingsSuite) Test_ListResourceMappings_Limit_Succeeds() {
	var limit int32 = 4
	listRsp, err := s.db.PolicyClient.ListResourceMappings(s.ctx, &resourcemapping.ListResourceMappingsRequest{
		Pagination: &policy.PageRequest{
			Limit: limit,
		},
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)

	listed := listRsp.GetResourceMappings()
	s.Equal(len(listed), int(limit))

	for _, rm := range listed {
		s.NotEmpty(rm.GetId())
		s.NotEmpty(rm.GetAttributeValue())
	}
}

func (s *NamespacesSuite) Test_ListResourceMappings_Limit_TooLarge_Fails() {
	listRsp, err := s.db.PolicyClient.ListResourceMappings(s.ctx, &resourcemapping.ListResourceMappingsRequest{
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax + 1,
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrListLimitTooLarge)
	s.Nil(listRsp)
}

func (s *ResourceMappingsSuite) Test_ListResourceMappings_Offset_Succeeds() {
	req := &resourcemapping.ListResourceMappingsRequest{}
	// make initial list request to compare against
	listRsp, err := s.db.PolicyClient.ListResourceMappings(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(listRsp)
	listed := listRsp.GetResourceMappings()

	// set the offset pagination
	offset := 2
	req.Pagination = &policy.PageRequest{
		Offset: int32(offset),
	}
	offsetListRsp, err := s.db.PolicyClient.ListResourceMappings(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(offsetListRsp)
	offsetListed := offsetListRsp.GetResourceMappings()

	// length is reduced by the offset amount
	s.Equal(len(offsetListed), len(listed)-offset)

	// objects are equal between offset and original list beginning at offset index
	for i, rm := range offsetListed {
		s.True(proto.Equal(rm, listed[i+offset]))
	}
}

func (s *ResourceMappingsSuite) Test_ListResourceMappings_ByGroupId_Succeeds() {
	req := &resourcemapping.ListResourceMappingsRequest{
		GroupId: s.getResourceMappingGroupFixtures()[0].ID,
	}
	listRsp, err := s.db.PolicyClient.ListResourceMappings(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(listRsp)
	mappings := listRsp.GetResourceMappings()
	for _, mapping := range mappings {
		expectedGroupID := req.GetGroupId()
		actualGroupID := mapping.GetGroup().GetId()
		s.Equal(expectedGroupID, actualGroupID,
			fmt.Sprintf("expected group id %s, got %s", expectedGroupID, actualGroupID))
	}
}

func (s *ResourceMappingsSuite) Test_ListResourceMappings_ByGroupFqns_Succeeds() {
	scenarioDotComNs := s.getScenarioDotComNamespace()
	scenarioDotComGroup := s.f.GetResourceMappingGroupKey("scenario.com_ns_group_1")
	scenarioDotComGroupMapping := s.f.GetResourceMappingKey("resource_mapping_to_attribute_value3")
	scenarioDotComAttrValue := s.f.GetAttributeValueKey("scenario.com/attr/working_group/value/blue")

	groupFqn := fmt.Sprintf("https://%s/resm/%s", scenarioDotComNs.Name, scenarioDotComGroup.Name)

	fqnRmGroupMap, err := s.db.PolicyClient.ListResourceMappingsByGroupFqns(s.ctx, []string{groupFqn})
	s.Require().NoError(err)
	s.NotNil(fqnRmGroupMap)

	mappingsByGroup, ok := fqnRmGroupMap[groupFqn]
	s.True(ok)
	s.NotNil(mappingsByGroup)
	group := mappingsByGroup.GetGroup()
	s.Equal(scenarioDotComGroup.ID, group.GetId())
	s.Equal(scenarioDotComGroup.NamespaceID, group.GetNamespaceId())
	s.Equal(scenarioDotComGroup.Name, group.GetName())
	groupMetadata := group.GetMetadata()
	createdAt := groupMetadata.GetCreatedAt()
	updatedAt := groupMetadata.GetUpdatedAt()
	s.False(createdAt.AsTime().IsZero())
	s.False(updatedAt.AsTime().IsZero())
	s.True(updatedAt.AsTime().Equal(createdAt.AsTime()))

	s.Len(mappingsByGroup.GetMappings(), 1, "expected 1 mapping")
	mapping := mappingsByGroup.GetMappings()[0]
	s.Equal(scenarioDotComGroupMapping.ID, mapping.GetId())
	s.Equal(scenarioDotComGroupMapping.Terms, mapping.GetTerms())
	mappingMetadata := mapping.GetMetadata()
	createdAt = mappingMetadata.GetCreatedAt()
	updatedAt = mappingMetadata.GetUpdatedAt()
	s.False(createdAt.AsTime().IsZero())
	s.False(updatedAt.AsTime().IsZero())
	s.True(updatedAt.AsTime().Equal(createdAt.AsTime()))
	value := mapping.GetAttributeValue()
	s.Equal(scenarioDotComAttrValue.ID, value.GetId())
	s.Equal(scenarioDotComAttrValue.Value, value.GetValue())
	s.Equal("https://scenario.com/attr/working_group/value/blue", value.GetFqn())
}

func (s *ResourceMappingsSuite) Test_ListResourceMappings_ByGroupFqns_WithEmptyOrNilFqns_Fails() {
	fqnRmGroupMap, err := s.db.PolicyClient.ListResourceMappingsByGroupFqns(s.ctx, nil)
	s.Require().Error(err)
	s.Nil(fqnRmGroupMap)

	fqnRmGroupMap, err = s.db.PolicyClient.ListResourceMappingsByGroupFqns(s.ctx, []string{})
	s.Require().Error(err)
	s.Nil(fqnRmGroupMap)
}

func (s *ResourceMappingsSuite) Test_ListResourceMappings_ByGroupFqns_WithInvalidFqns_Fails() {
	fqnRmGroupMap, err := s.db.PolicyClient.ListResourceMappingsByGroupFqns(s.ctx, []string{"invalid_fqn"})
	s.Require().Error(err)
	s.Nil(fqnRmGroupMap)
}

func (s *ResourceMappingsSuite) Test_ListResourceMappings_ByGroupFqns_WithUnknownFqns_Fails() {
	unknownFqn := "https://unknown.com/resm/unknown_group"
	fqnRmGroupMap, err := s.db.PolicyClient.ListResourceMappingsByGroupFqns(s.ctx, []string{unknownFqn})
	s.Require().Error(err)
	s.Nil(fqnRmGroupMap)
}

func (s *ResourceMappingsSuite) Test_ListResourceMappings_ByGroupFqns_WithKnownAndUnknownFqns_Succeeds() {
	exampleDotComNs := s.getExampleDotComNamespace()
	exampleDotComRmGroup1 := s.f.GetResourceMappingGroupKey("example.com_ns_group_1")

	group1Fqn := fmt.Sprintf("https://%s/resm/%s", exampleDotComNs.Name, exampleDotComRmGroup1.Name)
	unknownFqn := "https://unknown.com/resm/unknown_group"

	fqnRmGroupMap, err := s.db.PolicyClient.ListResourceMappingsByGroupFqns(s.ctx, []string{group1Fqn, unknownFqn})
	s.Require().NoError(err)
	s.NotNil(fqnRmGroupMap)

	group1Resp, ok := fqnRmGroupMap[group1Fqn]
	s.True(ok)
	s.NotNil(group1Resp)

	unknownResp, ok := fqnRmGroupMap[unknownFqn]
	s.False(ok)
	s.Nil(unknownResp)
}

func (s *ResourceMappingsSuite) Test_ListResourceMappingsByGroupFqns_WithKnownAndInvalidFqns_Succeeds() {
	exampleDotComNs := s.getExampleDotComNamespace()
	exampleDotComRmGroup1 := s.f.GetResourceMappingGroupKey("example.com_ns_group_1")

	group1Fqn := fmt.Sprintf("https://%s/resm/%s", exampleDotComNs.Name, exampleDotComRmGroup1.Name)
	invalidFqn := "invalid_fqn"

	fqnRmGroupMap, err := s.db.PolicyClient.ListResourceMappingsByGroupFqns(s.ctx, []string{group1Fqn, invalidFqn})
	s.Require().NoError(err)
	s.NotNil(fqnRmGroupMap)

	group1Resp, ok := fqnRmGroupMap[group1Fqn]
	s.True(ok)
	s.NotNil(group1Resp)

	unknownResp, ok := fqnRmGroupMap[invalidFqn]
	s.False(ok)
	s.Nil(unknownResp)
}

func (s *ResourceMappingsSuite) Test_GetResourceMapping() {
	testValue := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	testMapping := s.f.GetResourceMappingKey("resource_mapping_to_attribute_value1")

	mapping, err := s.db.PolicyClient.GetResourceMapping(s.ctx, testMapping.ID)
	s.Require().NoError(err)
	s.NotNil(mapping)
	s.Equal(testMapping.ID, mapping.GetId())
	s.Equal(testMapping.Terms, mapping.GetTerms())
	s.Equal(testMapping.GroupID, mapping.GetGroup().GetId())
	metadata := mapping.GetMetadata()
	createdAt := metadata.GetCreatedAt()
	updatedAt := metadata.GetUpdatedAt()
	s.False(createdAt.AsTime().IsZero())
	s.False(updatedAt.AsTime().IsZero())
	s.True(updatedAt.AsTime().Equal(createdAt.AsTime()))

	value := mapping.GetAttributeValue()
	s.Equal(testValue.ID, value.GetId())
	s.Equal(testValue.Value, value.GetValue())
	s.Equal("https://example.com/attr/attr1/value/value1", value.GetFqn())
}

func (s *ResourceMappingsSuite) Test_GetResourceMappingWithUnknownIdFails() {
	mapping, err := s.db.PolicyClient.GetResourceMapping(s.ctx, unknownResourceMappingID)
	s.Require().Error(err)
	s.Nil(mapping)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *ResourceMappingsSuite) Test_GetResourceMappingOfCreatedSucceeds() {
	testValue := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value2")
	testGroup := s.getResourceMappingGroupFixtures()[0]

	mapping := &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: testValue.ID,
		Metadata:         &common.MetadataMutable{},
		Terms:            []string{"term1", "term2"},
		GroupId:          testGroup.ID,
	}
	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, mapping)
	s.Require().NoError(err)
	s.NotNil(createdMapping)

	got, err := s.db.PolicyClient.GetResourceMapping(s.ctx, createdMapping.GetId())
	s.Require().NoError(err)
	s.NotNil(mapping)
	s.Equal(createdMapping.GetId(), got.GetId())
	s.Equal(createdMapping.GetTerms(), mapping.GetTerms())
	s.Equal(createdMapping.GetGroup().GetId(), got.GetGroup().GetId())

	gotValue := got.GetAttributeValue()
	s.Equal(testValue.ID, gotValue.GetId())
	s.Equal(testValue.Value, gotValue.GetValue())
	s.Equal("https://example.com/attr/attr1/value/value2", gotValue.GetFqn())
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

	createdMapping, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: attrValue.ID,
		Metadata: &common.MetadataMutable{
			Labels: labels,
		},
		Terms:   terms,
		GroupId: rmGroup.ID,
	})
	s.Require().NoError(err)
	s.NotNil(createdMapping)

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
		GroupId:                createdMapping.GetGroup().GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(updateWithChange)
	s.Equal(createdMapping.GetId(), updateWithChange.GetId())
	s.Equal(createdMapping.GetAttributeValue().GetId(), updateWithChange.GetAttributeValue().GetId())
	s.Equal(updateTerms, updateWithChange.GetTerms())
	s.EqualValues(expectedLabels, updateWithChange.GetMetadata().GetLabels())
	s.Equal(createdMapping.GetGroup().GetId(), updateWithChange.GetGroup().GetId())

	// get after update to verify db reflects changes made
	got, err := s.db.PolicyClient.GetResourceMapping(s.ctx, createdMapping.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(createdMapping.GetId(), got.GetId())
	s.Equal(createdMapping.GetAttributeValue().GetId(), got.GetAttributeValue().GetId())
	s.Equal(updateTerms, got.GetTerms())
	s.EqualValues(expectedLabels, got.GetMetadata().GetLabels())
	metadata := got.GetMetadata()
	createdAt := metadata.GetCreatedAt()
	updatedAt := metadata.GetUpdatedAt()
	s.False(createdAt.AsTime().IsZero())
	s.False(updatedAt.AsTime().IsZero())
	s.True(updatedAt.AsTime().After(createdAt.AsTime()))
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
