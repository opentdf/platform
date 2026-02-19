package integration

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	pbActions "github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/opentdf/platform/service/policy/actions"
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
	s.db = fixtures.NewDBInterface(s.ctx, c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision(s.ctx)
}

func (s *RegisteredResourcesSuite) TearDownSuite() {
	slog.Info("tearing down db.RegisteredResources test suite")
	s.f.TearDown(s.ctx)
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

func (s *RegisteredResourcesSuite) Test_GetRegisteredResource_ByID_Succeeds() {
	existingRes := s.f.GetRegisteredResourceKey("res_only")

	got, err := s.db.PolicyClient.GetRegisteredResource(s.ctx, &registeredresources.GetRegisteredResourceRequest{
		Identifier: &registeredresources.GetRegisteredResourceRequest_Id{
			Id: existingRes.ID,
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
	metadata := got.GetMetadata()
	s.False(metadata.GetCreatedAt().AsTime().IsZero())
	s.False(metadata.GetUpdatedAt().AsTime().IsZero())
	s.Empty(got.GetValues())
}

func (s *RegisteredResourcesSuite) Test_GetRegisteredResource_WithValues_Succeeds() {
	existingRes := s.f.GetRegisteredResourceKey("res_with_values")
	existingResValue1 := s.f.GetRegisteredResourceValueKey("res_with_values__value1")

	got, err := s.db.PolicyClient.GetRegisteredResource(s.ctx, &registeredresources.GetRegisteredResourceRequest{
		Identifier: &registeredresources.GetRegisteredResourceRequest_Id{
			Id: existingRes.ID,
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

func (s *RegisteredResourcesSuite) Test_GetRegisteredResource_ByInvalidID_Fails() {
	got, err := s.db.PolicyClient.GetRegisteredResource(s.ctx, &registeredresources.GetRegisteredResourceRequest{
		Identifier: &registeredresources.GetRegisteredResourceRequest_Id{
			Id: invalidID,
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(got)
}

func (s *RegisteredResourcesSuite) Test_GetRegisteredResource_ByInvalidName_Fails() {
	got, err := s.db.PolicyClient.GetRegisteredResource(s.ctx, &registeredresources.GetRegisteredResourceRequest{
		Identifier: &registeredresources.GetRegisteredResourceRequest_Name{
			Name: "invalid_name",
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

func (s *RegisteredResourcesSuite) Test_ListRegisteredResources_OrdersByCreatedAt_Succeeds() {
	suffix := time.Now().UnixNano()
	create := func(i int) string {
		name := fmt.Sprintf("order-test-resource-%d-%d", i, suffix)
		created, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
			Name: name,
		})
		s.Require().NoError(err)
		s.Require().NotNil(created)
		return created.GetId()
	}

	firstID := create(1)
	time.Sleep(5 * time.Millisecond)
	secondID := create(2)
	time.Sleep(5 * time.Millisecond)
	thirdID := create(3)

	list, err := s.db.PolicyClient.ListRegisteredResources(s.ctx, &registeredresources.ListRegisteredResourcesRequest{})
	s.Require().NoError(err)
	s.NotNil(list)

	assertIDsInOrder(s.T(), list.GetResources(), func(r *policy.RegisteredResource) string { return r.GetId() }, firstID, secondID, thirdID)
}

func (s *RegisteredResourcesSuite) Test_ListRegisteredResources_RegResValuesContainActionAttributeValues() {
	// Create a registered resource with values that have action attribute values
	newRegRes, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_list_reg_res_with_action_attr_values",
	})
	s.Require().NoError(err)
	s.NotNil(newRegRes)
	regResID := newRegRes.GetId()

	val1, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: regResID,
		Value:      "test_value_1",
		ActionAttributeValues: []*registeredresources.ActionAttributeValue{
			{
				ActionIdentifier: &registeredresources.ActionAttributeValue_ActionName{
					ActionName: actions.ActionNameCreate,
				},
				AttributeValueIdentifier: &registeredresources.ActionAttributeValue_AttributeValueFqn{
					AttributeValueFqn: "https://example.com/attr/attr1/value/value1",
				},
			},
		},
	})
	s.Require().NoError(err)
	s.NotNil(val1)

	val2, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: regResID,
		Value:      "test_value_2",
		ActionAttributeValues: []*registeredresources.ActionAttributeValue{
			{
				ActionIdentifier: &registeredresources.ActionAttributeValue_ActionName{
					ActionName: actions.ActionNameUpdate,
				},
				AttributeValueIdentifier: &registeredresources.ActionAttributeValue_AttributeValueFqn{
					AttributeValueFqn: "https://example.com/attr/attr2/value/value2",
				},
			},
		},
	})
	s.Require().NoError(err)
	s.NotNil(val2)

	// List registered resources and check if values contain action attribute values
	list, err := s.db.PolicyClient.ListRegisteredResources(s.ctx, &registeredresources.ListRegisteredResourcesRequest{})
	s.Require().NoError(err)
	s.NotNil(list)

	foundRegRes := false
	foundVal1 := false
	foundVal2 := false
	for _, r := range list.GetResources() {
		if r.GetId() == regResID {
			s.Equal("test_list_reg_res_with_action_attr_values", r.GetName())
			values := r.GetValues()
			s.Require().Len(values, 2)
			foundRegRes = true

			// Check if action attribute values are present in the values
			for _, v := range values {
				if v.GetId() == val1.GetId() {
					foundVal1 = true
					actionAttrValues := v.GetActionAttributeValues()
					s.Require().NotEmpty(actionAttrValues)
					for _, aav := range actionAttrValues {
						s.NotNil(aav.GetAction())
						s.NotNil(aav.GetAttributeValue())
					}
				}
				if v.GetId() == val2.GetId() {
					foundVal2 = true
					actionAttrValues := v.GetActionAttributeValues()
					s.Require().NotEmpty(actionAttrValues)
					for _, aav := range actionAttrValues {
						s.NotNil(aav.GetAction())
						s.NotNil(aav.GetAttributeValue())
					}
				}
			}
		}
	}
	s.True(foundRegRes, "Registered resource not found in list")
	s.True(foundVal1, "Value 1 not found in registered resource values")
	s.True(foundVal2, "Value 2 not found in registered resource values")
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
		Identifier: &registeredresources.GetRegisteredResourceRequest_Id{
			Id: created.GetId(),
		},
	})
	s.Require().NoError(err)
	s.Require().NotNil(got)
	s.Equal(created.GetName(), got.GetName())
	s.Equal(labels, got.GetMetadata().GetLabels())

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
		Identifier: &registeredresources.GetRegisteredResourceRequest_Id{
			Id: created.GetId(),
		},
	})
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal("test_update_res__new_name", got.GetName())
	s.Equal(expectedLabels, got.GetMetadata().GetLabels())
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
		Identifier: &registeredresources.GetRegisteredResourceRequest_Id{
			Id: created.GetId(),
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
		Identifier: &registeredresources.GetRegisteredResourceRequest_Id{
			Id: created.GetId(),
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(got)

	// verify resource values deleted
	gotValues := created.GetValues()

	gotValue1, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, &registeredresources.GetRegisteredResourceValueRequest{
		Identifier: &registeredresources.GetRegisteredResourceValueRequest_Id{
			Id: gotValues[0].GetId(),
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(gotValue1)

	gotValue2, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, &registeredresources.GetRegisteredResourceValueRequest{
		Identifier: &registeredresources.GetRegisteredResourceValueRequest_Id{
			Id: gotValues[1].GetId(),
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

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResourceValue_With_ActionAttributeValues_Succeeds() {
	res, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_create_res_value_action_attr_values",
	})
	s.Require().NoError(err)
	s.NotNil(res)

	req := &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: res.GetId(),
		Value:      "test_create_res_value_action_attr_values",
		ActionAttributeValues: []*registeredresources.ActionAttributeValue{
			{
				ActionIdentifier: &registeredresources.ActionAttributeValue_ActionName{
					ActionName: actions.ActionNameCreate,
				},
				AttributeValueIdentifier: &registeredresources.ActionAttributeValue_AttributeValueFqn{
					AttributeValueFqn: "https://example.com/attr/attr1/value/value1",
				},
			},
			{
				ActionIdentifier: &registeredresources.ActionAttributeValue_ActionName{
					ActionName: "custom_action_1",
				},
				AttributeValueIdentifier: &registeredresources.ActionAttributeValue_AttributeValueFqn{
					AttributeValueFqn: "https://example.com/attr/attr2/value/value2",
				},
			},
		},
	}

	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(created)
	actionAttrValues := created.GetActionAttributeValues()
	s.Len(actionAttrValues, 2)

	foundCount := 0
	for _, aav := range actionAttrValues {
		actionName := aav.GetAction().GetName()
		attrVal := aav.GetAttributeValue()

		if actionName == actions.ActionNameCreate {
			foundCount++
			s.Equal("https://example.com/attr/attr1/value/value1", attrVal.GetFqn())
			s.Equal("value1", attrVal.GetValue())
		}

		if actionName == "custom_action_1" {
			foundCount++
			s.Equal("https://example.com/attr/attr2/value/value2", attrVal.GetFqn())
			s.Equal("value2", attrVal.GetValue())
		}
	}
	s.Equal(2, foundCount)
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

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResourceValue_WithInvalidActionAttributeValues_Fails() {
	res, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_create_res_value_invalid_action_attr_values",
	})
	s.Require().NoError(err)
	s.NotNil(res)

	testCases := []struct {
		name             string
		actionAttrValues []*registeredresources.ActionAttributeValue
		err              error
	}{
		{
			name: "Invalid Action ID",
			actionAttrValues: []*registeredresources.ActionAttributeValue{
				{
					ActionIdentifier: &registeredresources.ActionAttributeValue_ActionId{
						ActionId: invalidID,
					},
					AttributeValueIdentifier: &registeredresources.ActionAttributeValue_AttributeValueFqn{
						AttributeValueFqn: "https://example.com/attr/attr1/value/value1",
					},
				},
			},
			err: db.ErrForeignKeyViolation,
		},
		{
			name: "Invalid Action Name",
			actionAttrValues: []*registeredresources.ActionAttributeValue{
				{
					ActionIdentifier: &registeredresources.ActionAttributeValue_ActionName{
						ActionName: "invalid_action_name",
					},
					AttributeValueIdentifier: &registeredresources.ActionAttributeValue_AttributeValueFqn{
						AttributeValueFqn: "https://example.com/attr/attr1/value/value1",
					},
				},
			},
			err: db.ErrNotFound,
		},
		{
			name: "Invalid Attribute Value ID",
			actionAttrValues: []*registeredresources.ActionAttributeValue{
				{
					ActionIdentifier: &registeredresources.ActionAttributeValue_ActionName{
						ActionName: actions.ActionNameCreate,
					},
					AttributeValueIdentifier: &registeredresources.ActionAttributeValue_AttributeValueId{
						AttributeValueId: invalidID,
					},
				},
			},
			err: db.ErrForeignKeyViolation,
		},
		{
			name: "Invalid Attribute Value FQN",
			actionAttrValues: []*registeredresources.ActionAttributeValue{
				{
					ActionIdentifier: &registeredresources.ActionAttributeValue_ActionName{
						ActionName: actions.ActionNameCreate,
					},
					AttributeValueIdentifier: &registeredresources.ActionAttributeValue_AttributeValueFqn{
						AttributeValueFqn: "https://example.com/attr/does_not_exist/value/invalid",
					},
				},
			},
			err: db.ErrNotFound,
		},
	}

	for i, tc := range testCases {
		s.Run(tc.name, func() {
			req := &registeredresources.CreateRegisteredResourceValueRequest{
				ResourceId:            res.GetId(),
				Value:                 fmt.Sprintf("test_create_res_value_invalid_action_attr_values_%d", i),
				ActionAttributeValues: tc.actionAttrValues,
			}

			created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, req)
			s.Require().Error(err)
			s.Require().ErrorIs(err, tc.err)
			s.Nil(created)
		})
	}
}

// Get

func (s *RegisteredResourcesSuite) Test_GetRegisteredResourceValue_Valid_Succeeds() {
	existingRes := s.f.GetRegisteredResourceKey("res_with_values")
	existingResValue1 := s.f.GetRegisteredResourceValueKey("res_with_values__value1")

	testCases := []struct {
		name string
		req  *registeredresources.GetRegisteredResourceValueRequest
	}{
		{
			name: "By ID",
			req: &registeredresources.GetRegisteredResourceValueRequest{
				Identifier: &registeredresources.GetRegisteredResourceValueRequest_Id{
					Id: existingResValue1.ID,
				},
			},
		},
		{
			name: "By FQN",
			req: &registeredresources.GetRegisteredResourceValueRequest{
				Identifier: &registeredresources.GetRegisteredResourceValueRequest_Fqn{
					Fqn: fmt.Sprintf("https://reg_res/%s/value/%s", existingRes.Name, existingResValue1.Value),
				},
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			got, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, tc.req)
			s.Require().NoError(err)
			s.NotNil(got)
			s.Equal(existingResValue1.Value, got.GetValue())
			s.Equal(existingRes.ID, got.GetResource().GetId())

			actionAttrValues := got.GetActionAttributeValues()
			s.Require().Len(actionAttrValues, 2)
			foundCount := 0
			for _, aav := range actionAttrValues {
				actionName := aav.GetAction().GetName()
				fqn := aav.GetAttributeValue().GetFqn()

				if actionName == actions.ActionNameCreate {
					foundCount++
					s.Equal("https://example.com/attr/attr1/value/value1", fqn)
				}

				if actionName == "custom_action_1" {
					foundCount++
					s.Equal("https://example.com/attr/attr1/value/value2", fqn)
				}
			}
			s.Equal(2, foundCount)

			metadata := got.GetMetadata()
			s.False(metadata.GetCreatedAt().AsTime().IsZero())
			s.False(metadata.GetUpdatedAt().AsTime().IsZero())
		})
	}
}

func (s *RegisteredResourcesSuite) Test_GetRegisteredResourceValue_Invalid_Fails() {
	testCases := []struct {
		name string
		req  *registeredresources.GetRegisteredResourceValueRequest
	}{
		{
			name: "By Invalid ID",
			req: &registeredresources.GetRegisteredResourceValueRequest{
				Identifier: &registeredresources.GetRegisteredResourceValueRequest_Id{
					Id: invalidID,
				},
			},
		},
		{
			name: "By Invalid FQN",
			req: &registeredresources.GetRegisteredResourceValueRequest{
				Identifier: &registeredresources.GetRegisteredResourceValueRequest_Fqn{
					Fqn: "https://reg_res/does_not_exist/value/does_not_exist",
				},
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			got, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, tc.req)
			s.Require().Error(err)
			s.Require().ErrorIs(err, db.ErrNotFound)
			s.Nil(got)
		})
	}
}

// Get By FQNs

func (s *RegisteredResourcesSuite) TestGetRegisteredResourceValuesByFQNs_Valid_Succeeds() {
	existingRes := s.f.GetRegisteredResourceKey("res_with_values")
	existingResValue1 := s.f.GetRegisteredResourceValueKey("res_with_values__value1")
	existingResValue2 := s.f.GetRegisteredResourceValueKey("res_with_values__value2")
	fqns := []string{
		fmt.Sprintf("https://reg_res/%s/value/%s", existingRes.Name, existingResValue1.Value),
		fmt.Sprintf("https://reg_res/%s/value/%s", existingRes.Name, existingResValue2.Value),
	}

	got, err := s.db.PolicyClient.GetRegisteredResourceValuesByFQNs(s.ctx, &registeredresources.GetRegisteredResourceValuesByFQNsRequest{
		Fqns: fqns,
	})
	s.Require().NoError(err)
	s.NotNil(got)

	foundFQN1 := got[fqns[0]]
	s.NotNil(foundFQN1)
	s.Equal(existingResValue1.ID, foundFQN1.GetId())
	s.Equal(existingResValue1.Value, foundFQN1.GetValue())
	s.Equal(existingRes.ID, foundFQN1.GetResource().GetId())
	s.Len(foundFQN1.GetActionAttributeValues(), 2)

	foundFQN2 := got[fqns[1]]
	s.NotNil(foundFQN2)
	s.Equal(existingResValue2.ID, foundFQN2.GetId())
	s.Equal(existingResValue2.Value, foundFQN2.GetValue())
	s.Equal(existingRes.ID, foundFQN2.GetResource().GetId())
	s.Empty(foundFQN2.GetActionAttributeValues())
}

func (s *RegisteredResourcesSuite) TestGetRegisteredResourceValuesByFQNs_SomeInvalid_Fails() {
	existingRes := s.f.GetRegisteredResourceKey("res_with_values")
	existingResValue1 := s.f.GetRegisteredResourceValueKey("res_with_values__value1")
	fqns := []string{
		fmt.Sprintf("https://reg_res/%s/value/%s", existingRes.Name, existingResValue1.Value),
		"https://reg_res/does_not_exist/value/does_not_exist",
	}

	got, err := s.db.PolicyClient.GetRegisteredResourceValuesByFQNs(s.ctx, &registeredresources.GetRegisteredResourceValuesByFQNsRequest{
		Fqns: fqns,
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(got)
}

func (s *RegisteredResourcesSuite) TestGetRegisteredResourceValuesByFQNs_AllInvalid_Fails() {
	fqns := []string{
		"https://reg_res/does_not_exist/value/does_not_exist",
		"https://reg_res/does_not_exist/value/does_not_exist2",
	}

	got, err := s.db.PolicyClient.GetRegisteredResourceValuesByFQNs(s.ctx, &registeredresources.GetRegisteredResourceValuesByFQNsRequest{
		Fqns: fqns,
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
			s.Len(r.GetActionAttributeValues(), 2)
		}

		if r.GetId() == existingResValue2.ID {
			foundCount++
			s.Equal(existingResValue2.Value, r.GetValue())
			s.Equal(existingRes.ID, r.GetResource().GetId())
			metadata := r.GetMetadata()
			s.False(metadata.GetCreatedAt().AsTime().IsZero())
			s.False(metadata.GetUpdatedAt().AsTime().IsZero())
			s.Empty(r.GetActionAttributeValues())
		}
	}

	s.Equal(2, foundCount)
}

func (s *RegisteredResourcesSuite) Test_ListRegisteredResourceValues_OrdersByCreatedAt_Succeeds() {
	suffix := time.Now().UnixNano()
	resource, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		Name: fmt.Sprintf("order-test-res-%d", suffix),
	})
	s.Require().NoError(err)
	s.Require().NotNil(resource)

	create := func(i int) string {
		val := fmt.Sprintf("order-test-val-%d-%d", i, suffix)
		created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, &registeredresources.CreateRegisteredResourceValueRequest{
			ResourceId: resource.GetId(),
			Value:      val,
		})
		s.Require().NoError(err)
		s.Require().NotNil(created)
		return created.GetId()
	}

	firstID := create(1)
	time.Sleep(5 * time.Millisecond)
	secondID := create(2)
	time.Sleep(5 * time.Millisecond)
	thirdID := create(3)

	list, err := s.db.PolicyClient.ListRegisteredResourceValues(s.ctx, &registeredresources.ListRegisteredResourceValuesRequest{
		ResourceId: resource.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(list)

	assertIDsInOrder(s.T(), list.GetValues(), func(v *policy.RegisteredResourceValue) string { return v.GetId() }, firstID, secondID, thirdID)
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
		ActionAttributeValues: []*registeredresources.ActionAttributeValue{
			{
				ActionIdentifier: &registeredresources.ActionAttributeValue_ActionName{
					ActionName: actions.ActionNameRead,
				},
				AttributeValueIdentifier: &registeredresources.ActionAttributeValue_AttributeValueFqn{
					AttributeValueFqn: "https://example.com/attr/attr1/value/value1",
				},
			},
		},
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
		Identifier: &registeredresources.GetRegisteredResourceValueRequest_Id{
			Id: created.GetId(),
		},
	})
	s.Require().NoError(err)
	s.Require().NotNil(got)
	s.Equal(created.GetValue(), got.GetValue())
	s.Equal(labels, got.GetMetadata().GetLabels())
	s.Require().Len(got.GetActionAttributeValues(), 1)

	// update with changes
	updated, err = s.db.PolicyClient.UpdateRegisteredResourceValue(s.ctx, &registeredresources.UpdateRegisteredResourceValueRequest{
		Id:    created.GetId(),
		Value: "updated_value",
		Metadata: &common.MetadataMutable{
			Labels: updateLabels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
		ActionAttributeValues: []*registeredresources.ActionAttributeValue{
			{
				ActionIdentifier: &registeredresources.ActionAttributeValue_ActionName{
					ActionName: actions.ActionNameDelete,
				},
				AttributeValueIdentifier: &registeredresources.ActionAttributeValue_AttributeValueFqn{
					AttributeValueFqn: "https://example.com/attr/attr1/value/value1",
				},
			},
			{
				ActionIdentifier: &registeredresources.ActionAttributeValue_ActionName{
					ActionName: "custom_action_1",
				},
				AttributeValueIdentifier: &registeredresources.ActionAttributeValue_AttributeValueFqn{
					AttributeValueFqn: "https://example.com/attr/attr2/value/value2",
				},
			},
		},
	})
	s.Require().NoError(err)
	s.NotNil(updated)

	// verify resource updated
	got, err = s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, &registeredresources.GetRegisteredResourceValueRequest{
		Identifier: &registeredresources.GetRegisteredResourceValueRequest_Id{
			Id: created.GetId(),
		},
	})
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal("updated_value", got.GetValue())
	s.Equal(expectedLabels, got.GetMetadata().GetLabels())
	metadata := got.GetMetadata()
	createdAt := metadata.GetCreatedAt()
	updatedAt := metadata.GetUpdatedAt()
	s.False(createdAt.AsTime().IsZero())
	s.False(updatedAt.AsTime().IsZero())
	s.True(updatedAt.AsTime().After(createdAt.AsTime()))
	actionAttrValues := got.GetActionAttributeValues()
	s.Require().Len(actionAttrValues, 2)
	s.Equal(actions.ActionNameDelete, actionAttrValues[0].GetAction().GetName())
	attrValue1 := actionAttrValues[0].GetAttributeValue()
	s.Equal("https://example.com/attr/attr1/value/value1", attrValue1.GetFqn())
	s.Equal("value1", attrValue1.GetValue())
	s.Equal("custom_action_1", actionAttrValues[1].GetAction().GetName())
	attrValue2 := actionAttrValues[1].GetAttributeValue()
	s.Equal("https://example.com/attr/attr2/value/value2", attrValue2.GetFqn())
	s.Equal("value2", attrValue2.GetValue())
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
		Identifier: &registeredresources.GetRegisteredResourceValueRequest_Id{
			Id: created.GetId(),
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
		ActionAttributeValues: []*registeredresources.ActionAttributeValue{
			{
				ActionIdentifier: &registeredresources.ActionAttributeValue_ActionName{
					ActionName: actions.ActionNameCreate,
				},
				AttributeValueIdentifier: &registeredresources.ActionAttributeValue_AttributeValueFqn{
					AttributeValueFqn: "https://example.com/attr/attr1/value/value1",
				},
			},
		},
	})
	s.Require().NoError(err)
	s.NotNil(created)

	deleted, err := s.db.PolicyClient.DeleteRegisteredResourceValue(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.Require().Equal(created.GetId(), deleted.GetId())

	// verify resource value deleted

	got, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, &registeredresources.GetRegisteredResourceValueRequest{
		Identifier: &registeredresources.GetRegisteredResourceValueRequest_Id{
			Id: created.GetId(),
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(got)

	// verify resource value action attribute values deleted
	// using QueryRow directly since the registered resource value was just deleted and the get above will return a nil result
	row, err := s.db.PolicyClient.QueryRow(s.ctx,
		"SELECT COUNT(*) FROM registered_resource_action_attribute_values WHERE registered_resource_value_id = $1",
		[]any{created.GetId()})
	s.Require().NoError(err)
	var count int
	err = row.Scan(&count)
	s.Require().NoError(err)
	s.Equal(0, count)
}

func (s *RegisteredResourcesSuite) Test_DeleteRegisteredResourceValue_WithInvalidID_Fails() {
	deleted, err := s.db.PolicyClient.DeleteRegisteredResourceValue(s.ctx, invalidID)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(deleted)
}

///
/// Registered Resource Action Attribute Values
///

// Cascade Deletes

func (s *RegisteredResourcesSuite) Test_DeleteAction_CascadeDeleteActionAttributeValue_Succeeds() {
	// create action and resource value with action attribute values

	action, err := s.db.PolicyClient.CreateAction(s.ctx, &pbActions.CreateActionRequest{
		Name: "test_delete_action",
	})
	s.Require().NoError(err)

	res, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_delete_action_res",
	})
	s.Require().NoError(err)
	s.NotNil(res)

	attrVal := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")

	resVal, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: res.GetId(),
		Value:      "test_delete_action_res_value",
		ActionAttributeValues: []*registeredresources.ActionAttributeValue{
			{
				ActionIdentifier: &registeredresources.ActionAttributeValue_ActionId{
					ActionId: action.GetId(),
				},
				AttributeValueIdentifier: &registeredresources.ActionAttributeValue_AttributeValueId{
					AttributeValueId: attrVal.ID,
				},
			},
		},
	})
	s.Require().NoError(err)
	s.NotNil(resVal)
	s.Require().Len(resVal.GetActionAttributeValues(), 1)

	// delete action

	_, err = s.db.PolicyClient.DeleteAction(s.ctx, &pbActions.DeleteActionRequest{
		Id: action.GetId(),
	})
	s.Require().NoError(err)

	// verify resource value action attribute values deleted

	resVal, err = s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, &registeredresources.GetRegisteredResourceValueRequest{
		Identifier: &registeredresources.GetRegisteredResourceValueRequest_Id{
			Id: resVal.GetId(),
		},
	})
	s.Require().NoError(err)
	s.NotNil(resVal)
	s.Empty(resVal.GetActionAttributeValues())
}

func (s *RegisteredResourcesSuite) Test_DeleteAttributeValue_CascadeDeleteActionAttributeValue_Succeeds() {
	// create attribute value and resource value with action attribute values

	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test_delete_attr_value.com",
	})
	s.Require().NoError(err)
	s.NotNil(ns)

	attr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId: ns.GetId(),
		Name:        "test_delete_attr",
		Values:      []string{"test_delete_attr_value1"},
	})
	s.Require().NoError(err)
	s.NotNil(attr)

	attrVal := attr.GetValues()[0]
	s.Require().NotNil(attrVal)

	res, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_delete_attr_value_res",
	})
	s.Require().NoError(err)
	s.NotNil(res)

	resVal, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: res.GetId(),
		Value:      "test_delete_attr_value_res_value",
		ActionAttributeValues: []*registeredresources.ActionAttributeValue{
			{
				ActionIdentifier: &registeredresources.ActionAttributeValue_ActionName{
					ActionName: actions.ActionNameCreate,
				},
				AttributeValueIdentifier: &registeredresources.ActionAttributeValue_AttributeValueId{
					AttributeValueId: attrVal.GetId(),
				},
			},
		},
	})
	s.Require().NoError(err)
	s.NotNil(resVal)
	s.Require().Len(resVal.GetActionAttributeValues(), 1)

	// delete attribute value

	_, err = s.db.PolicyClient.UnsafeDeleteAttributeValue(s.ctx, attrVal, &unsafe.UnsafeDeleteAttributeValueRequest{
		Id:  attrVal.GetId(),
		Fqn: attrVal.GetFqn(),
	})
	s.Require().NoError(err)

	// verify resource value action attribute values deleted

	resVal, err = s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, &registeredresources.GetRegisteredResourceValueRequest{
		Identifier: &registeredresources.GetRegisteredResourceValueRequest_Id{
			Id: resVal.GetId(),
		},
	})
	s.Require().NoError(err)
	s.NotNil(resVal)
	s.Empty(resVal.GetActionAttributeValues())
}
