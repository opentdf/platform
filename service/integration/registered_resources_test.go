package integration

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/suite"
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
	existingRes := s.f.GetRegisteredResourceKey("res_with_values")
	existingResValue1 := s.f.GetRegisteredResourceValueKey("res_with_values__value1")
	existingResValue2 := s.f.GetRegisteredResourceValueKey("res_with_values__value2")

	got, err := s.db.PolicyClient.GetRegisteredResource(s.ctx, existingRes.ID)
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(existingRes.Name, got.GetName())
	metadata := got.GetMetadata()
	s.False(metadata.GetCreatedAt().AsTime().IsZero())
	s.False(metadata.GetUpdatedAt().AsTime().IsZero())
	values := got.GetValues()
	s.Require().Len(values, 2)
	s.Equal(existingResValue1.Value, values[0].GetValue())
	s.Equal(existingResValue2.Value, values[1].GetValue())
}

func (s *RegisteredResourcesSuite) Test_GetRegisteredResource_WithoutValues_Succeeds() {
	created, err := s.db.PolicyClient.CreateRegisteredResource(s.ctx, &registeredresources.CreateRegisteredResourceRequest{
		Name: "test_get_res_without_values",
	})
	s.Require().NoError(err)
	s.NotNil(created)

	got, err := s.db.PolicyClient.GetRegisteredResource(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetName(), got.GetName())
	values := got.GetValues()
	s.Require().Empty(values)
}

func (s *RegisteredResourcesSuite) Test_GetRegisteredResource_InvalidID_Fails() {
	got, err := s.db.PolicyClient.GetRegisteredResource(s.ctx, invalidID)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(got)
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
	got, err := s.db.PolicyClient.GetRegisteredResource(s.ctx, created.GetId())
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
	got, err = s.db.PolicyClient.GetRegisteredResource(s.ctx, created.GetId())
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
	got, err := s.db.PolicyClient.GetRegisteredResource(s.ctx, created.GetId())
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
	got, err := s.db.PolicyClient.GetRegisteredResource(s.ctx, created.GetId())
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(got)

	// verify resource values deleted
	gotValues := created.GetValues()

	gotValue1, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, gotValues[0].GetId())
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(gotValue1)

	gotValue2, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, gotValues[1].GetId())
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
	res := s.f.GetRegisteredResourceKey("res_only")
	req := &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: res.ID,
		Value:      "test_create_res_value",
	}

	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(created)
}

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResourceValue_NormalizedName_Succeeds() {
	res := s.f.GetRegisteredResourceKey("res_only")
	req := &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: res.ID,
		Value:      "TeST_CrEaTe_RES_value_NorMa-LiZeD",
	}

	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(created)
	s.Equal(strings.ToLower(req.GetValue()), created.GetValue())
}

func (s *RegisteredResourcesSuite) Test_CreateRegisteredResourceValue_WithMetadata_Succeeds() {
	req := &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: s.f.GetRegisteredResourceKey("res_only").ID,
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

	got, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, existingResValue1.ID)
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(existingRes.ID, got.GetResource().GetId())
	s.Equal(existingResValue1.Value, got.GetValue())
	metadata := got.GetMetadata()
	s.False(metadata.GetCreatedAt().AsTime().IsZero())
	s.False(metadata.GetUpdatedAt().AsTime().IsZero())
}

func (s *RegisteredResourcesSuite) Test_GetRegisteredResourceValue_InvalidID_Fails() {
	got, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, invalidID)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(got)
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

	existingRes := s.f.GetRegisteredResourceKey("res_only")
	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: existingRes.ID,
		Value:      "test_update_res_value",
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
	got, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.Require().NotNil(got)
	s.Equal(created.GetValue(), got.GetValue())
	s.EqualValues(labels, got.GetMetadata().GetLabels())

	// update with changes
	updated, err = s.db.PolicyClient.UpdateRegisteredResourceValue(s.ctx, &registeredresources.UpdateRegisteredResourceValueRequest{
		Id:    created.GetId(),
		Value: "test_update_res_value__new_value",
		Metadata: &common.MetadataMutable{
			Labels: updateLabels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	s.Require().NoError(err)
	s.NotNil(updated)

	// verify resource updated
	got, err = s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal("test_update_res_value__new_value", got.GetValue())
	s.EqualValues(expectedLabels, got.GetMetadata().GetLabels())
	metadata := got.GetMetadata()
	createdAt := metadata.GetCreatedAt()
	updatedAt := metadata.GetUpdatedAt()
	s.False(createdAt.AsTime().IsZero())
	s.False(updatedAt.AsTime().IsZero())
	s.True(updatedAt.AsTime().After(createdAt.AsTime()))
}

func (s *RegisteredResourcesSuite) Test_UpdateRegisteredResourceValue_NormalizedName_Succeeds() {
	existingRes := s.f.GetRegisteredResourceKey("res_only")
	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: existingRes.ID,
		Value:      "test_update_res_value_normalized",
	})
	s.Require().NoError(err)
	s.NotNil(created)

	updated, err := s.db.PolicyClient.UpdateRegisteredResourceValue(s.ctx, &registeredresources.UpdateRegisteredResourceValueRequest{
		Id:    created.GetId(),
		Value: "TeST_UpDaTe_RES_value_NorMa-LiZeD",
	})
	s.Require().NoError(err)
	s.NotNil(updated)

	// verify resource value updated
	got, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal("test_update_res_value_norma-lized", got.GetValue())
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
	existingResValue := s.f.GetRegisteredResourceValueKey("res_with_values__value1")

	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: existingResValue.RegisteredResourceID,
		Value:      "test_update_res_value_non_unique",
	})
	s.Require().NoError(err)
	s.NotNil(created)

	updated, err := s.db.PolicyClient.UpdateRegisteredResourceValue(s.ctx, &registeredresources.UpdateRegisteredResourceValueRequest{
		Id:    created.GetId(),
		Value: existingResValue.Value,
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
	s.Nil(updated)
}

// Delete

func (s *RegisteredResourcesSuite) Test_DeleteRegisteredResourceValue_Succeeds() {
	existingRes := s.f.GetRegisteredResourceKey("res_only")
	created, err := s.db.PolicyClient.CreateRegisteredResourceValue(s.ctx, &registeredresources.CreateRegisteredResourceValueRequest{
		ResourceId: existingRes.ID,
		Value:      "test_delete_res_value",
	})
	s.Require().NoError(err)

	deleted, err := s.db.PolicyClient.DeleteRegisteredResourceValue(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.Require().Equal(created.GetId(), deleted.GetId())

	// verify resource value deleted

	got, err := s.db.PolicyClient.GetRegisteredResourceValue(s.ctx, created.GetId())
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
