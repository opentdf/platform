package integration

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/proto"
)

type RegisteredResourcesSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context //nolint:containedctx // context is used in the test suite
}

func (s *RegisteredResourcesSuite) SetupSuite() {
	slog.Info("setting up db.RegisteredResources test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_registered_resources"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
}

func (s *RegisteredResourcesSuite) TearDownSuite() {
	slog.Info("tearing down db.RegisteredResources test suite")
	s.f.TearDown()
}

func TestRegisteredResourcesSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping registered resources integration test")
	}
	suite.Run(t, new(RegisteredResourcesSuite))
}

const invalidID = "00000000-0000-0000-0000-000000000000"

///
/// Registered Resources
///

// Create

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResource_Succeeds() {
	req := &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_create_res",
	}

	created, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(created)
}

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResource_NormalizedName_Succeeds() {
	req := &registeredresources.CreateRegisteredResourceRequest{
		Name: "TeST_CrEaTe_RES_NorMa-LiZeD",
	}

	created, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(created)
	s.Equal(strings.ToLower(req.GetName()), created.GetName())
}

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResource_WithValues_Succeeds() {
	values := []string{
		"test_create_res_values__value1",
		"test_create_res_values__value2",
	}
	req := &registeredresources.CreateRegisteredResourceRequest{
		Name:   "test_create_res_values",
		Values: values,
	}

	created, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(created)
	createdVals := created.GetValues()
	s.Require().Len(createdVals, 2)
	s.Equal(values[0], createdVals[0].GetValue())
	s.Equal(values[1], createdVals[1].GetValue())
}

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResource_WithMetadata_Succeeds() {
	req := &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_create_res_metadata",
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		},
	}

	created, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(created)
	s.Require().Len(created.GetMetadata().GetLabels(), 2)
}

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResource_WithNonUniqueName_Fails() {
	existing := s.f.GetRegisteredResourceKey("res_with_values")
	req := &registeredresources.CreateRegisteredResourceRequest{
		Name: existing.Name,
	}

	created, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, req)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
	s.Nil(created)
}

// Get

func (s *RegisteredResourcesSuite) Test_GetRegisteredResource_Succeeds() {
	existingRes := s.f.GetRegisteredResourceKey("res_only")

	got, err := s.db.PolicyClient.GetRegisteredResource(s.ctx, &registeredresources.GetRegisteredResourceRequest{
		Identifier: &registeredresources.GetRegisteredResourceRequest_ResourceId{
			ResourceId: existingRes.ID,
		},
	})
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(existingRes.Name, got.GetName())
	metadata := got.GetMetadata()
	s.False(metadata.GetCreatedAt().AsTime().IsZero())
	s.False(metadata.GetUpdatedAt().AsTime().IsZero())
	s.Empty(got.GetValues())
}

func (s *RegisteredResourcesSuite) Test_GetRegisteredResource_WithValues_Succeeds() {
	existingRes := s.f.GetRegisteredResourceKey("res_with_values")
	existingResValue1 := s.f.GetRegisteredResourceValueKey("res_with_values__value1")

	got, err := s.db.PolicyClient.GetRegisteredResource(s.ctx, &registeredresources.GetRegisteredResourceRequest{
		Identifier: &registeredresources.GetRegisteredResourceRequest_ResourceId{
			ResourceId: existingRes.ID,
		},
	})
	s.Require().NoError(err)
	s.NotNil(got)
	values := got.GetValues()
	s.Require().Len(values, 2)
	var found bool
	for _, v := range values {
		// check at least one of the expected values exists
		if existingResValue1.ID == v.GetId() {
			found = true
			s.Equal(existingResValue1.Value, v.GetValue())
			break
		}
	}
	s.True(found)
}

func (s *RegisteredResourcesSuite) Test_GetRegisteredResource_ByName_Succeeds() {
	existingRes := s.f.GetRegisteredResourceKey("res_only")

	got, err := s.db.PolicyClient.GetRegisteredResource(s.ctx, &registeredresources.GetRegisteredResourceRequest{
		Identifier: &registeredresources.GetRegisteredResourceRequest_Name{
			Name: existingRes.Name,
		},
	})
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(existingRes.ID, got.GetId())
}

func (s *RegisteredResourcesSuite) Test_GetRegisteredResource_InvalidID_Fails() {
	got, err := s.db.PolicyClient.GetRegisteredResource(s.ctx, &registeredresources.GetRegisteredResourceRequest{
		Identifier: &registeredresources.GetRegisteredResourceRequest_ResourceId{
			ResourceId: invalidID,
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(got)
}

// List

func (s *RegisteredResourcesSuite) Test_ListRegisteredResources_NoPagination_Succeeds() {
	existingRes := s.f.GetRegisteredResourceKey("res_with_values")
	existingResOnly := s.f.GetRegisteredResourceKey("res_only")

	list, err := s.db.PolicyClient.ListRegisteredResources(s.ctx, &registeredresources.ListRegisteredResourcesRequest{})
	s.Require().NoError(err)
	s.NotNil(list)

	foundCount := 0

	for _, r := range list.GetResources() {
		if r.GetId() == existingRes.ID {
			foundCount++
			s.Equal(existingRes.Name, r.GetName())
			values := r.GetValues()
			s.Require().Len(values, 2)
			metadata := r.GetMetadata()
			s.False(metadata.GetCreatedAt().AsTime().IsZero())
			s.False(metadata.GetUpdatedAt().AsTime().IsZero())
		}

		if r.GetId() == existingResOnly.ID {
			foundCount++
			s.Equal(existingResOnly.Name, r.GetName())
			s.Require().Empty(r.GetValues())
			metadata := r.GetMetadata()
			s.False(metadata.GetCreatedAt().AsTime().IsZero())
			s.False(metadata.GetUpdatedAt().AsTime().IsZero())
		}
	}

	s.Equal(2, foundCount)
}

func (s *RegisteredResourcesSuite) Test_ListRegisteredResources_Limit_Succeeds() {
	var limit int32 = 1
	list, err := s.db.PolicyClient.ListRegisteredResources(s.ctx, &registeredresources.ListRegisteredResourcesRequest{
		Pagination: &policy.PageRequest{
			Limit: limit,
		},
	})
	s.Require().NoError(err)
	s.NotNil(list)
	items := list.GetResources()
	s.Len(items, int(limit))

	// request with one below maximum
	list, err = s.db.PolicyClient.ListRegisteredResources(s.ctx, &registeredresources.ListRegisteredResourcesRequest{
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax - 1,
		},
	})
	s.Require().NoError(err)
	s.NotNil(list)

	// exactly maximum
	list, err = s.db.PolicyClient.ListRegisteredResources(s.ctx, &registeredresources.ListRegisteredResourcesRequest{
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax,
		},
	})
	s.Require().NoError(err)
	s.NotNil(list)
}

func (s *NamespacesSuite) Test_ListRegisteredResources_Limit_TooLarge_Fails() {
	listRsp, err := s.db.PolicyClient.ListRegisteredResources(s.ctx, &registeredresources.ListRegisteredResourcesRequest{
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax + 1,
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrListLimitTooLarge)
	s.Nil(listRsp)
}

func (s *AttributesSuite) Test_ListRegisteredResources_Offset_Succeeds() {
	req := &registeredresources.ListRegisteredResourcesRequest{}
	// make initial list request to compare against
	list, err := s.db.PolicyClient.ListRegisteredResources(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(list)
	items := list.GetResources()

	// set the offset pagination
	offset := 2
	req.Pagination = &policy.PageRequest{
		Offset: int32(offset),
	}
	offsetList, err := s.db.PolicyClient.ListRegisteredResources(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(offsetList)
	offsetItems := offsetList.GetResources()

	// length is reduced by the offset amount
	s.Len(offsetItems, len(items)-offset)

	// objects are equal between offset and original list beginning at offset index
	for i, attr := range offsetItems {
		s.True(proto.Equal(attr, items[i+offset]))
	}
}

// Update

func (s *RegisteredResourcesSuite) Test_UpdateRegisteredResource_Succeeds() {
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

	created, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_update_res",
		Metadata: &common.MetadataMutable{
			Labels: labels,
		},
	})
	s.Require().NoError(err)
	s.NotNil(created)

	// update with no changes
	updated, err := s.db.PolicyClient.UpdateRegisteredResource(s.ctx, &registeredresources.UpdateRegisteredResourceRequest{
		Id: created.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(updated)

	// verify resource not updated
	got, err := s.db.PolicyClient.GetRegisteredResource(s.ctx, &registeredresources.GetRegisteredResourceRequest{
		Identifier: &registeredresources.GetRegisteredResourceRequest_ResourceId{
			ResourceId: created.GetId(),
		},
	})
	s.Require().NoError(err)
	s.Require().NotNil(got)
	s.Equal(created.GetName(), got.GetName())
	s.EqualValues(labels, got.GetMetadata().GetLabels())

	// update with changes
	updated, err = s.db.PolicyClient.UpdateRegisteredResource(s.ctx, &registeredresources.UpdateRegisteredResourceRequest{
		Id:   created.GetId(),
		Name: "test_update_res__new_name",
		Metadata: &common.MetadataMutable{
			Labels: updateLabels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	s.Require().NoError(err)
	s.NotNil(updated)

	// verify resource updated
	got, err = s.db.PolicyClient.GetRegisteredResource(s.ctx, &registeredresources.GetRegisteredResourceRequest{
		Identifier: &registeredresources.GetRegisteredResourceRequest_ResourceId{
			ResourceId: created.GetId(),
		},
	})
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal("test_update_res__new_name", got.GetName())
	s.EqualValues(expectedLabels, got.GetMetadata().GetLabels())
	metadata := got.GetMetadata()
	createdAt := metadata.GetCreatedAt()
	updatedAt := metadata.GetUpdatedAt()
	s.False(createdAt.AsTime().IsZero())
	s.False(updatedAt.AsTime().IsZero())
	s.True(updatedAt.AsTime().After(createdAt.AsTime()))
}

func (s *RegisteredResourcesSuite) Test_UpdateRegisteredResource_NormalizedName_Succeeds() {
	created, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_update_res_normalized",
	})
	s.Require().NoError(err)
	s.NotNil(created)

	updated, err := s.db.PolicyClient.UpdateRegisteredResource(s.ctx, &registeredresources.UpdateRegisteredResourceRequest{
		Id:   created.GetId(),
		Name: "TeST_UpDaTe_RES_NorMa-LiZeD",
	})
	s.Require().NoError(err)
	s.NotNil(updated)

	// verify resource updated
	got, err := s.db.PolicyClient.GetRegisteredResource(s.ctx, &registeredresources.GetRegisteredResourceRequest{
		Identifier: &registeredresources.GetRegisteredResourceRequest_ResourceId{
			ResourceId: created.GetId(),
		},
	})
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal("test_update_res_norma-lized", got.GetName())
}

func (s *RegisteredResourcesSuite) Test_UpdateRegisteredResource_InvalidID_Fails() {
	updated, err := s.db.PolicyClient.UpdateRegisteredResource(s.ctx, &registeredresources.UpdateRegisteredResourceRequest{
		Id: invalidID,
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(updated)
}

func (s *RegisteredResourcesSuite) Test_UpdateRegisteredResource_NonUniqueName_Fails() {
	created, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_update_res_non_unique",
	})
	s.Require().NoError(err)
	s.NotNil(created)

	existingRes := s.f.GetRegisteredResourceKey("res_only")
	updated, err := s.db.PolicyClient.UpdateRegisteredResource(s.ctx, &registeredresources.UpdateRegisteredResourceRequest{
		Id:   created.GetId(),
		Name: existingRes.Name,
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
	s.Nil(updated)
}

// Delete

func (s *RegisteredResourcesSuite) Test_DeleteRegisteredResource_Succeeds() {
	created, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_delete_res",
		Values: []string{
			"test_delete_value1",
			"test_delete_value2",
		},
	})
	s.Require().NoError(err)

	deleted, err := s.db.PolicyClient.DeleteRegisteredResource(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.Require().Equal(created.GetId(), deleted.GetId())

	// verify resource deleted
	got, err := s.db.PolicyClient.GetRegisteredResource(s.ctx, &registeredresources.GetRegisteredResourceRequest{
		Identifier: &registeredresources.GetRegisteredResourceRequest_ResourceId{
			ResourceId: created.GetId(),
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(got)

	// verify resource values deleted
	gotValues := created.GetValues()

	gotValue1, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, &registeredresources.GetRegisteredResourceValueRequest{
		Identifier: &registeredresources.GetRegisteredResourceValueRequest_ValueId{
			ValueId: gotValues[0].GetId(),
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(gotValue1)

	gotValue2, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, &registeredresources.GetRegisteredResourceValueRequest{
		Identifier: &registeredresources.GetRegisteredResourceValueRequest_ValueId{
			ValueId: gotValues[1].GetId(),
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(gotValue2)
}

func (s *RegisteredResourcesSuite) Test_DeleteRegisteredResource_WithInvalidID_Fails() {
	deleted, err := s.db.PolicyClient.DeleteRegisteredResource(s.ctx, invalidID)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(deleted)
}

///
/// Registered Resource Values
///

// Create

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResourceValue_Succeeds() {
	res, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_create_res_value",
	})
	s.Require().NoError(err)
	s.NotNil(res)

	req := &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: res.GetId(),
		Value:      "value",
	}

	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(created)
}

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResourceValue_NormalizedName_Succeeds() {
	res, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_create_res_value_normalized",
	})
	s.Require().NoError(err)
	s.NotNil(res)

	req := &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: res.GetId(),
		Value:      "VaLuE_NorMa-LiZeD",
	}

	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(created)
	s.Equal(strings.ToLower(req.GetValue()), created.GetValue())
}

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResourceValue_WithMetadata_Succeeds() {
	res, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_create_res_value_metadata",
	})
	s.Require().NoError(err)
	s.NotNil(res)

	req := &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: res.GetId(),
		Value:      "test_create_res_value_metadata",
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		},
	}

	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(created)
	s.Require().Len(created.GetMetadata().GetLabels(), 2)
}

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResourceValue_WithInvalidResource_Fails() {
	req := &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: invalidID,
		Value:      "test_create_res_value__invalid_resource",
	}

	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, req)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrForeignKeyViolation)
	s.Nil(created)
}

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResourceValue_WithNonUniqueResourceAndValue_Fails() {
	existingRes := s.f.GetRegisteredResourceKey("res_with_values")
	existingResValue := s.f.GetRegisteredResourceValueKey("res_with_values__value1")

	req := &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: existingRes.ID,
		Value:      existingResValue.Value,
	}

	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, req)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
	s.Nil(created)
}

// Get

func (s *RegisteredResourcesSuite) Test_GetRegisteredResourceValue_Succeeds() {
	existingRes := s.f.GetRegisteredResourceKey("res_with_values")
	existingResValue1 := s.f.GetRegisteredResourceValueKey("res_with_values__value1")

	got, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, &registeredresources.GetRegisteredResourceValueRequest{
		Identifier: &registeredresources.GetRegisteredResourceValueRequest_ValueId{
			ValueId: existingResValue1.ID,
		},
	})
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(existingRes.ID, got.GetResource().GetId())
	s.Equal(existingResValue1.Value, got.GetValue())
	metadata := got.GetMetadata()
	s.False(metadata.GetCreatedAt().AsTime().IsZero())
	s.False(metadata.GetUpdatedAt().AsTime().IsZero())
}

func (s *RegisteredResourcesSuite) Test_GetRegisteredResourceValue_ByFQN_Succeeds() {
	existingRes := s.f.GetRegisteredResourceKey("res_with_values")
	existingResValue1 := s.f.GetRegisteredResourceValueKey("res_with_values__value1")
	fqn := fmt.Sprintf("https://reg_res/%s/value/%s", existingRes.Name, existingResValue1.Value)

	got, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, &registeredresources.GetRegisteredResourceValueRequest{
		Identifier: &registeredresources.GetRegisteredResourceValueRequest_Fqn{
			Fqn: fqn,
		},
	})
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(existingRes.ID, got.GetResource().GetId())
}

func (s *RegisteredResourcesSuite) Test_GetRegisteredResourceValue_InvalidID_Fails() {
	got, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, &registeredresources.GetRegisteredResourceValueRequest{
		Identifier: &registeredresources.GetRegisteredResourceValueRequest_ValueId{
			ValueId: invalidID,
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(got)
}

// List

func (s *RegisteredResourcesSuite) Test_ListRegisteredResourceValues_NoPagination_Succeeds() {
	existingRes := s.f.GetRegisteredResourceKey("res_with_values")
	existingResValue1 := s.f.GetRegisteredResourceValueKey("res_with_values__value1")
	existingResValue2 := s.f.GetRegisteredResourceValueKey("res_with_values__value2")

	list, err := s.db.PolicyClient.ListRegisteredResourceValues(s.ctx, &registeredresources.ListRegisteredResourceValuesRequest{})
	s.Require().NoError(err)
	s.NotNil(list)
	// should be more values than the 2 explicitly tested below
	s.Greater(len(list.GetValues()), 2)

	foundCount := 0

	for _, r := range list.GetValues() {
		if r.GetId() == existingResValue1.ID {
			foundCount++
			s.Equal(existingResValue1.Value, r.GetValue())
			s.Equal(existingRes.ID, r.GetResource().GetId())
			metadata := r.GetMetadata()
			s.False(metadata.GetCreatedAt().AsTime().IsZero())
			s.False(metadata.GetUpdatedAt().AsTime().IsZero())
		}

		if r.GetId() == existingResValue2.ID {
			foundCount++
			s.Equal(existingResValue2.Value, r.GetValue())
			s.Equal(existingRes.ID, r.GetResource().GetId())
			metadata := r.GetMetadata()
			s.False(metadata.GetCreatedAt().AsTime().IsZero())
			s.False(metadata.GetUpdatedAt().AsTime().IsZero())
		}
	}

	s.Equal(2, foundCount)
}

func (s *RegisteredResourcesSuite) Test_ListRegisteredResourceValues_Limit_Succeeds() {
	var limit int32 = 1
	list, err := s.db.PolicyClient.ListRegisteredResourceValues(s.ctx, &registeredresources.ListRegisteredResourceValuesRequest{
		Pagination: &policy.PageRequest{
			Limit: limit,
		},
	})
	s.Require().NoError(err)
	s.NotNil(list)
	items := list.GetValues()
	s.Len(items, int(limit))

	// request with one below maximum
	list, err = s.db.PolicyClient.ListRegisteredResourceValues(s.ctx, &registeredresources.ListRegisteredResourceValuesRequest{
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax - 1,
		},
	})
	s.Require().NoError(err)
	s.NotNil(list)

	// exactly maximum
	list, err = s.db.PolicyClient.ListRegisteredResourceValues(s.ctx, &registeredresources.ListRegisteredResourceValuesRequest{
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax,
		},
	})
	s.Require().NoError(err)
	s.NotNil(list)
}

func (s *NamespacesSuite) Test_ListRegisteredResourceValues_Limit_TooLarge_Fails() {
	listRsp, err := s.db.PolicyClient.ListRegisteredResourceValues(s.ctx, &registeredresources.ListRegisteredResourceValuesRequest{
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax + 1,
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrListLimitTooLarge)
	s.Nil(listRsp)
}

func (s *AttributesSuite) Test_ListRegisteredResourceValues_Offset_Succeeds() {
	req := &registeredresources.ListRegisteredResourceValuesRequest{}
	// make initial list request to compare against
	list, err := s.db.PolicyClient.ListRegisteredResourceValues(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(list)
	items := list.GetValues()

	// set the offset pagination
	offset := 2
	req.Pagination = &policy.PageRequest{
		Offset: int32(offset),
	}
	offsetList, err := s.db.PolicyClient.ListRegisteredResourceValues(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(offsetList)
	offsetItems := offsetList.GetValues()

	// length is reduced by the offset amount
	s.Len(offsetItems, len(items)-offset)

	// objects are equal between offset and original list beginning at offset index
	for i, attr := range offsetItems {
		s.True(proto.Equal(attr, items[i+offset]))
	}
}

func (s *RegisteredResourcesSuite) Test_ListRegisteredResourceValues_ByResourceID_Succeeds() {
	existingRes := s.f.GetRegisteredResourceKey("res_with_values")
	existingResValue1 := s.f.GetRegisteredResourceValueKey("res_with_values__value1")
	existingResValue2 := s.f.GetRegisteredResourceValueKey("res_with_values__value2")

	list, err := s.db.PolicyClient.ListRegisteredResourceValues(s.ctx, &registeredresources.ListRegisteredResourceValuesRequest{
		ResourceId: existingRes.ID,
	})
	s.Require().NoError(err)
	s.NotNil(list)
	// should only be the 2 values associated with the resource
	s.Len(list.GetValues(), 2)

	foundCount := 0

	for _, r := range list.GetValues() {
		if r.GetId() == existingResValue1.ID || r.GetId() == existingResValue2.ID {
			foundCount++
		}
	}

	s.Equal(2, foundCount)
}

// Update

func (s *RegisteredResourcesSuite) Test_UpdateRegisteredResourceValue_Succeeds() {
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

	res, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_update_res_value",
	})
	s.Require().NoError(err)
	s.NotNil(res)

	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: res.GetId(),
		Value:      "value",
		Metadata: &common.MetadataMutable{
			Labels: labels,
		},
	})
	s.Require().NoError(err)
	s.NotNil(created)

	// update with no changes
	updated, err := s.db.PolicyClient.UpdateRegisteredResourceValue(s.ctx, &registeredresources.UpdateRegisteredResourceValueRequest{
		Id: created.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(updated)

	// verify resource value not updated
	got, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, &registeredresources.GetRegisteredResourceValueRequest{
		Identifier: &registeredresources.GetRegisteredResourceValueRequest_ValueId{
			ValueId: created.GetId(),
		},
	})
	s.Require().NoError(err)
	s.Require().NotNil(got)
	s.Equal(created.GetValue(), got.GetValue())
	s.EqualValues(labels, got.GetMetadata().GetLabels())

	// update with changes
	updated, err = s.db.PolicyClient.UpdateRegisteredResourceValue(s.ctx, &registeredresources.UpdateRegisteredResourceValueRequest{
		Id:    created.GetId(),
		Value: "updated_value",
		Metadata: &common.MetadataMutable{
			Labels: updateLabels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	s.Require().NoError(err)
	s.NotNil(updated)

	// verify resource updated
	got, err = s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, &registeredresources.GetRegisteredResourceValueRequest{
		Identifier: &registeredresources.GetRegisteredResourceValueRequest_ValueId{
			ValueId: created.GetId(),
		},
	})
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal("updated_value", got.GetValue())
	s.EqualValues(expectedLabels, got.GetMetadata().GetLabels())
	metadata := got.GetMetadata()
	createdAt := metadata.GetCreatedAt()
	updatedAt := metadata.GetUpdatedAt()
	s.False(createdAt.AsTime().IsZero())
	s.False(updatedAt.AsTime().IsZero())
	s.True(updatedAt.AsTime().After(createdAt.AsTime()))
}

func (s *RegisteredResourcesSuite) Test_UpdateRegisteredResourceValue_NormalizedName_Succeeds() {
	res, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_update_res_value_normalized",
	})
	s.Require().NoError(err)
	s.NotNil(res)

	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: res.GetId(),
		Value:      "value_normalized",
	})
	s.Require().NoError(err)
	s.NotNil(created)

	updated, err := s.db.PolicyClient.UpdateRegisteredResourceValue(s.ctx, &registeredresources.UpdateRegisteredResourceValueRequest{
		Id:    created.GetId(),
		Value: "VaLuE_NorMa-LiZeD",
	})
	s.Require().NoError(err)
	s.NotNil(updated)

	// verify resource value updated
	got, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, &registeredresources.GetRegisteredResourceValueRequest{
		Identifier: &registeredresources.GetRegisteredResourceValueRequest_ValueId{
			ValueId: created.GetId(),
		},
	})
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal("value_norma-lized", got.GetValue())
}

func (s *RegisteredResourcesSuite) Test_UpdateRegisteredResourceValue_InvalidID_Fails() {
	updated, err := s.db.PolicyClient.UpdateRegisteredResourceValue(s.ctx, &registeredresources.UpdateRegisteredResourceValueRequest{
		Id: invalidID,
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(updated)
}

func (s *RegisteredResourcesSuite) Test_UpdateRegisteredResourceValue_NonUniqueResourceAndValue_Fails() {
	res, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_update_res_value_non_unique",
	})
	s.Require().NoError(err)
	s.NotNil(res)

	resVal1, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: res.GetId(),
		Value:      "value1",
	})
	s.Require().NoError(err)
	s.NotNil(resVal1)

	resVal2, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: res.GetId(),
		Value:      "value2",
	})
	s.Require().NoError(err)
	s.NotNil(resVal2)

	updated, err := s.db.PolicyClient.UpdateRegisteredResourceValue(s.ctx, &registeredresources.UpdateRegisteredResourceValueRequest{
		Id: resVal1.GetId(),
		// causes unique constraint violation attempting to update value1 to value2
		Value: resVal2.GetValue(),
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
	s.Nil(updated)
}

// Delete

func (s *RegisteredResourcesSuite) Test_DeleteRegisteredResourceValue_Succeeds() {
	res, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_delete_res_value",
	})
	s.Require().NoError(err)
	s.NotNil(res)

	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: res.GetId(),
		Value:      "value",
	})
	s.Require().NoError(err)

	deleted, err := s.db.PolicyClient.DeleteRegisteredResourceValue(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.Require().Equal(created.GetId(), deleted.GetId())

	// verify resource value deleted

	got, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, &registeredresources.GetRegisteredResourceValueRequest{
		Identifier: &registeredresources.GetRegisteredResourceValueRequest_ValueId{
			ValueId: created.GetId(),
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(got)
}

func (s *RegisteredResourcesSuite) Test_DeleteRegisteredResourceValue_WithInvalidID_Fails() {
	deleted, err := s.db.PolicyClient.DeleteRegisteredResourceValue(s.ctx, invalidID)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(deleted)
}
