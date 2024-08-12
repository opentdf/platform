package integration

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/policy/resourcemappinggroup"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/stretchr/testify/suite"
)

type ResourceMappingGroupsSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context //nolint:containedctx // context is used in the test suite
}

func (s *ResourceMappingGroupsSuite) SetupSuite() {
	slog.Info("setting up db.ResourceMappingGroups test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_resource_mapping_groups"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
}

func (s *ResourceMappingGroupsSuite) TearDownSuite() {
	slog.Info("tearing down db.ResourceMappingGroups test suite")
	s.f.TearDown()
}

func (s *ResourceMappingGroupsSuite) getResourceMappingGroupFixtures() []fixtures.FixtureDataResourceMappingGroup {
	return []fixtures.FixtureDataResourceMappingGroup{
		s.f.GetResourceMappingGroupKey("example.com_ns_group_1"),
		s.f.GetResourceMappingGroupKey("example.com_ns_group_2"),
		s.f.GetResourceMappingGroupKey("example.com_ns_group_3"),
	}
}

func (s *ResourceMappingGroupsSuite) getExampleNamespace() *fixtures.FixtureDataNamespace {
	namespace := s.f.GetNamespaceKey("example.com")
	return &namespace
}

/* test cases
- list
- get
- create
- create with invalid namespace_id
- create with duplicate namespace_id and name combo
- update
- update with invalid namespace_id
- update with duplicate namespace_id and name combo
- delete
*/

func (s *ResourceMappingGroupsSuite) Test_ListResourceMappings() {
	testData := s.getResourceMappingGroupFixtures()
	rmGroups, err := s.db.PolicyClient.ListResourceMappingGroups(s.ctx)
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

func (s *ResourceMappingGroupsSuite) Test_GetResourceMappingGroup() {
	testRmGroup := s.f.GetResourceMappingGroupKey("example.com_ns_group_1")
	rmGroup, err := s.db.PolicyClient.GetResourceMappingGroup(s.ctx, testRmGroup.ID)
	s.Require().NoError(err)
	s.NotNil(rmGroup)
	s.Equal(testRmGroup.ID, rmGroup.GetId())
	s.Equal(testRmGroup.NamespaceID, rmGroup.GetNamespaceId())
	s.Equal(testRmGroup.Name, rmGroup.GetName())
}

func (s *ResourceMappingGroupsSuite) Test_CreateResourceMappingGroup() {
	req := &resourcemappinggroup.CreateResourceMappingGroupRequest{
		NamespaceId: s.getExampleNamespace().ID,
		Name:        "example.com_ns_new_group",
	}
	rmGroup, err := s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(rmGroup)
}

func (s *ResourceMappingGroupsSuite) Test_CreateResourceMappingGroupWithInvalidNamespaceFails() {
	req := &resourcemappinggroup.CreateResourceMappingGroupRequest{
		NamespaceId: uuid.NewString(),
		Name:        "invalid_ns_new_group",
	}
	rmGroup, err := s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, req)
	s.Require().Error(err)
	s.Nil(rmGroup)
}

func (s *ResourceMappingGroupsSuite) Test_CreateResourceMappingGroupWithDuplicateNamespaceAndNameComboFails() {
	name := "example.com_ns_dupe_group"
	req := &resourcemappinggroup.CreateResourceMappingGroupRequest{
		NamespaceId: s.getExampleNamespace().ID,
		Name:        name,
	}
	rmGroup, err := s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(rmGroup)
	s.NotNil(rmGroup.GetId())
	rmGroup, err = s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, req)
	s.Require().Error(err)
	s.Nil(rmGroup)
}

func (s *ResourceMappingGroupsSuite) Test_UpdateResourceMappingGroup() {
	req := &resourcemappinggroup.CreateResourceMappingGroupRequest{
		NamespaceId: s.getExampleNamespace().ID,
		Name:        "example.com_ns_group_created",
	}
	rmGroup, err := s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(rmGroup)

	updateReq := &resourcemappinggroup.UpdateResourceMappingGroupRequest{
		Id:          rmGroup.GetId(),
		NamespaceId: s.getExampleNamespace().ID,
		Name:        "example.com_ns_group_updated",
	}
	updatedRmGroup, err := s.db.PolicyClient.UpdateResourceMappingGroup(s.ctx, rmGroup.GetId(), updateReq)
	s.Require().NoError(err)
	s.NotNil(updatedRmGroup)
	s.Equal(rmGroup.GetId(), updatedRmGroup.GetId())
	s.Equal(updateReq.GetNamespaceId(), updatedRmGroup.GetNamespaceId())
	s.Equal(updateReq.GetName(), updatedRmGroup.GetName())
}

func (s *ResourceMappingGroupsSuite) Test_DeleteResourceMappingGroup() {
	req := &resourcemappinggroup.CreateResourceMappingGroupRequest{
		NamespaceId: s.getExampleNamespace().ID,
		Name:        "example.com_ns_group_to_delete",
	}
	rmGroup, err := s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(rmGroup)

	deletedRmGroup, err := s.db.PolicyClient.DeleteResourceMappingGroup(s.ctx, rmGroup.GetId())
	s.Require().NoError(err)
	s.NotNil(deletedRmGroup)
	s.Equal(rmGroup.GetId(), deletedRmGroup.GetId())

	expectedNilRmGroup, err := s.db.PolicyClient.GetResourceMappingGroup(s.ctx, deletedRmGroup.GetId())
	s.Require().NoError(err)
	s.Nil(expectedNilRmGroup)
}
