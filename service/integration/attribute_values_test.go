package integration

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/proto"
)

var absentAttributeValueUUID = "78909865-8888-9999-9999-000000000000"

type AttributeValuesSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context //nolint:containedctx // context is used in the test suite
}

func (s *AttributeValuesSuite) SetupSuite() {
	slog.Info("setting up db.AttributeValues test suite")
	s.ctx = context.Background()
	fixtureNamespaceID = s.f.GetNamespaceKey("example.com").ID
	fixtureKeyAccessServerID = s.f.GetKasRegistryKey("key_access_server_1").ID
	c := *Config
	c.DB.Schema = "test_opentdf_attribute_values"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
	stillActiveNsID, stillActiveAttributeID, deactivatedAttrValueID = setupDeactivateAttributeValue(s)
}

func (s *AttributeValuesSuite) TearDownSuite() {
	slog.Info("tearing down db.AttributeValues test suite")
	s.f.TearDown()
}

func (s *AttributeValuesSuite) Test_ListAttributeValues_WithAttributeID_Succeeds() {
	attrID := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1").AttributeDefinitionID

	listRsp, err := s.db.PolicyClient.ListAttributeValues(s.ctx, &attributes.ListAttributeValuesRequest{
		AttributeId: attrID,
		State:       common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE,
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)
	listed := listRsp.GetValues()

	// ensure list contains the two test fixtures and that response matches expected data
	f1 := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	f2 := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value2")

	for _, val := range listed {
		if val.GetId() == f1.ID {
			s.Equal(f1.ID, val.GetId())
			s.Equal(f1.Value, val.GetValue())
			s.Equal(f1.AttributeDefinitionID, val.GetAttribute().GetId())
		} else if val.GetId() == f2.ID {
			s.Equal(f2.ID, val.GetId())
			s.Equal(f2.Value, val.GetValue())
			s.Equal(f2.AttributeDefinitionID, val.GetAttribute().GetId())
		}
	}
}

func (s *AttributeValuesSuite) Test_ListAttributeValues_NoPagination_Succeeds() {
	allFixtureValueFqns := map[string]bool{
		"https://example.com/attr/attr1/value/value1":                          false,
		"https://example.com/attr/attr1/value/value2":                          false,
		"https://example.com/attr/attr2/value/value1":                          false,
		"https://example.com/attr/attr2/value/value2":                          false,
		"https://example.net/attr/attr1/value/value1":                          false,
		"https://example.net/attr/attr1/value/value2":                          false,
		"https://scenario.com/attr/working_group/value/blue":                   false,
		"https://deactivated.io/attr/deactivated_attr/value/deactivated_value": false,
	}
	listRsp, err := s.db.PolicyClient.ListAttributeValues(s.ctx, &attributes.ListAttributeValuesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)
	// mark every listed value true
	for _, val := range listRsp.GetValues() {
		allFixtureValueFqns[val.GetFqn()] = true
	}
	// ensure all fixtures were found by unbounded list
	for fqn, found := range allFixtureValueFqns {
		if !found {
			s.Failf("failed to list fixture", fqn)
		}
	}
}

func (s *AttributeValuesSuite) Test_ListAttributeValues_Limit_Succeeds() {
	var limit int32 = 2
	listRsp, err := s.db.PolicyClient.ListAttributeValues(s.ctx, &attributes.ListAttributeValuesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
		Pagination: &policy.PageRequest{
			Limit: limit,
		},
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)
	listed := listRsp.GetValues()
	s.Equal(len(listed), int(limit))

	for _, val := range listed {
		s.NotEmpty(val.GetFqn())
		s.NotEmpty(val.GetId())
		s.NotEmpty(val.GetValue())
	}

	// request with one below maximum
	listRsp, err = s.db.PolicyClient.ListAttributeValues(s.ctx, &attributes.ListAttributeValuesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax - 1,
		},
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)

	// request with exactly maximum
	listRsp, err = s.db.PolicyClient.ListAttributeValues(s.ctx, &attributes.ListAttributeValuesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax,
		},
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)
}

func (s *NamespacesSuite) Test_ListAttributeValues_Limit_TooLarge_Fails() {
	listRsp, err := s.db.PolicyClient.ListAttributeValues(s.ctx, &attributes.ListAttributeValuesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax + 1,
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrListLimitTooLarge)
	s.Nil(listRsp)
}

func (s *AttributeValuesSuite) Test_ListAttributeValues_Offset_Succeeds() {
	req := &attributes.ListAttributeValuesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
	}
	// make initial list request to compare against
	listRsp, err := s.db.PolicyClient.ListAttributeValues(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(listRsp)
	listed := listRsp.GetValues()

	// set the offset pagination
	offset := 5
	req.Pagination = &policy.PageRequest{
		Offset: int32(offset),
	}
	offsetListRsp, err := s.db.PolicyClient.ListAttributeValues(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(offsetListRsp)
	offsetListed := offsetListRsp.GetValues()

	// length is reduced by the offset amount
	s.Equal(len(offsetListed), len(listed)-offset)

	// objects are equal between offset and original list beginning at offset index
	for i, val := range offsetListed {
		s.True(proto.Equal(val, listed[i+offset]))
	}
}

func (s *AttributeValuesSuite) Test_GetAttributeValue() {
	f := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")

	testCases := []struct {
		name           string
		input          interface{}
		identifierType string
	}{
		{
			name:           "Deprecated ID",
			input:          f.ID,
			identifierType: "Deprecated ID",
		},
		{
			name:           "New Identifier - ID",
			input:          &attributes.GetAttributeValueRequest_ValueId{ValueId: f.ID},
			identifierType: "New ID",
		},
		{
			name:           "New Identifier - FQN",
			input:          &attributes.GetAttributeValueRequest_Fqn{Fqn: "https://example.com/attr/attr1/value/value1"},
			identifierType: "FQN",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			v, err := s.db.PolicyClient.GetAttributeValue(s.ctx, tc.input)
			s.Require().NoError(err, "Failed to get AttributeValue by %s: %v", tc.identifierType, tc.input)
			s.Require().NotNil(v, "Expected non-nil AttributeValue for %s: %v", tc.identifierType, tc.input)

			s.Equal(f.ID, v.GetId(), "ID mismatch for %s: %v", tc.identifierType, tc.input)
			s.Equal(f.Value, v.GetValue(), "Value mismatch for %s: %v", tc.identifierType, tc.input)
			s.Equal(f.AttributeDefinitionID, v.GetAttribute().GetId(), "AttributeDefinitionID mismatch for %s: %v", tc.identifierType, tc.input)
			s.Equal("https://example.com/attr/attr1/value/value1", v.GetFqn(), "FQN mismatch for %s: %v", tc.identifierType, tc.input)

			metadata := v.GetMetadata()
			s.Require().NotNil(metadata, "Metadata should not be nil for %s: %v", tc.identifierType, tc.input)
			createdAt := metadata.GetCreatedAt()
			updatedAt := metadata.GetUpdatedAt()
			s.Require().NotNil(createdAt, "CreatedAt should not be nil for %s: %v", tc.identifierType, tc.input)
			s.Require().NotNil(updatedAt, "UpdatedAt should not be nil for %s: %v", tc.identifierType, tc.input)

			s.True(createdAt.IsValid() && createdAt.AsTime().Unix() > 0, "CreatedAt is invalid for %s: %v", tc.identifierType, tc.input)
			s.True(updatedAt.IsValid() && updatedAt.AsTime().Unix() > 0, "UpdatedAt is invalid for %s: %v", tc.identifierType, tc.input)
		})
	}
}

func (s *AttributeValuesSuite) Test_GetAttributeValue_NotFound() {
	testCases := []struct {
		name           string
		input          interface{} // Could be string ID or identifier struct if you want to test different not-found scenarios later
		identifierType string      // For clarity in case you expand test cases
	}{
		{
			name:           "Not Found - Deprecated ID", // Or just "Not Found" if only one case
			input:          absentAttributeValueUUID,
			identifierType: "Deprecated ID", // Or "UUID" or "ID"
		},
		{
			name:           "Not Found - New Identifier - ID",
			input:          &attributes.GetAttributeValueRequest_ValueId{ValueId: absentAttributeValueUUID},
			identifierType: "New ID",
		},
		{
			name:           "Not Found - New Identifier - FQN",
			input:          &attributes.GetAttributeValueRequest_Fqn{Fqn: "https://example.com/attr/attr1/value/absent_value"},
			identifierType: "FQN",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			attr, err := s.db.PolicyClient.GetAttributeValue(s.ctx, tc.input)
			s.Require().Error(err, "Expected an error when AttributeValue is not found by %s: %v", tc.identifierType, tc.input)
			s.Nil(attr, "Expected nil AttributeValue when not found by %s: %v", tc.identifierType, tc.input)
			s.Require().ErrorIs(err, db.ErrNotFound, "Expected ErrNotFound when AttributeValue is not found by %s: %v", tc.identifierType, tc.input)
		})
	}
}

func (s *AttributeValuesSuite) Test_GetAttributeValue_ContainsKASGrants() {
	// create a value with KAS grants
	attrDef := s.f.GetAttributeKey("example.net/attr/attr1")
	value := &attributes.CreateAttributeValueRequest{
		Value: "kas_grants_test",
	}
	createdValue, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attrDef.ID, value)
	s.Require().NoError(err)
	s.NotNil(createdValue)

	// ensure it has no grants
	got, err := s.db.PolicyClient.GetAttributeValue(s.ctx, createdValue.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Empty(got.GetGrants())

	fixtureKeyAccessServer := s.f.GetKasRegistryKey("key_access_server_1")
	fixtureKeyAccessServerID := fixtureKeyAccessServer.ID
	assignment := &attributes.ValueKeyAccessServer{
		ValueId:           createdValue.GetId(),
		KeyAccessServerId: fixtureKeyAccessServerID,
	}
	grant, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, assignment)
	s.Require().NoError(err)
	s.NotNil(grant)

	// get the value and ensure it contains the grants
	got, err = s.db.PolicyClient.GetAttributeValue(s.ctx, createdValue.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(createdValue.GetId(), got.GetId())
	gotGrants := got.GetGrants()
	s.Len(gotGrants, 1)
	s.Equal(fixtureKeyAccessServerID, gotGrants[0].GetId())
	s.Equal(fixtureKeyAccessServer.Name, gotGrants[0].GetName())
}

func (s *AttributeValuesSuite) Test_CreateAttributeValue_SetsActiveStateTrueByDefault() {
	attrDef := s.f.GetAttributeKey("example.net/attr/attr1")

	req := &attributes.CreateAttributeValueRequest{
		Value: "testing-create-gives-active-true-by-default",
	}
	createdValue, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attrDef.ID, req)
	s.Require().NoError(err)
	s.NotNil(createdValue)
	s.True(createdValue.GetActive().GetValue())
}

func (s *AttributeValuesSuite) Test_CreateAttributeValue_NormalizesValueToLowerCase() {
	attrDef := s.f.GetAttributeKey("example.net/attr/attr1")
	v := "VaLuE_12_ShOuLdBe-NoRmAlIzEd"

	req := &attributes.CreateAttributeValueRequest{
		Value: v,
	}
	createdValue, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attrDef.ID, req)
	s.Require().NoError(err)
	s.NotNil(createdValue)
	s.Equal(strings.ToLower(v), createdValue.GetValue())

	got, err := s.db.PolicyClient.GetAttributeValue(s.ctx, createdValue.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(strings.ToLower(v), createdValue.GetValue(), got.GetValue())
}

func (s *AttributeValuesSuite) Test_GetAttributeValue_Deactivated_Succeeds() {
	inactive := s.f.GetAttributeValueKey("deactivated.io/attr/deactivated_attr/value/deactivated_value")

	got, err := s.db.PolicyClient.GetAttributeValue(s.ctx, inactive.ID)
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(inactive.ID, got.GetId())
	s.Equal(inactive.Value, got.GetValue())
	s.False(got.GetActive().GetValue())
}

func (s *AttributeValuesSuite) Test_CreateAttributeValue_Succeeds() {
	attrDef := s.f.GetAttributeKey("example.net/attr/attr1")
	metadata := &common.MetadataMutable{
		Labels: map[string]string{
			"name": "this is the test name of my attribute value",
		},
	}

	value := &attributes.CreateAttributeValueRequest{
		Value:    "value_create_success",
		Metadata: metadata,
	}
	createdValue, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attrDef.ID, value)
	s.Require().NoError(err)
	s.NotNil(createdValue)

	got, err := s.db.PolicyClient.GetAttributeValue(s.ctx, createdValue.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(createdValue.GetId(), got.GetId())
	s.Equal(createdValue.GetValue(), got.GetValue())
	s.EqualValues(createdValue.GetMetadata().GetLabels(), got.GetMetadata().GetLabels())
}

func (s *AttributeValuesSuite) Test_CreateAttributeValue_WithInvalidAttributeId_Fails() {
	value := &attributes.CreateAttributeValueRequest{
		Value: "some value",
	}
	createdValue, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, nonExistentAttrID, value)
	s.Require().Error(err)
	s.Nil(createdValue)
	s.Require().ErrorIs(err, db.ErrForeignKeyViolation)
}

func (s *AttributeValuesSuite) Test_UpdateAttributeValue() {
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

	// create a value
	attrDef := s.f.GetAttributeKey("example.net/attr/attr1")
	created, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attrDef.ID, &attributes.CreateAttributeValueRequest{
		Value: "created value testing update",
		Metadata: &common.MetadataMutable{
			Labels: labels,
		},
	})
	s.Require().NoError(err)
	s.NotNil(created)

	// update with no changes
	updatedWithoutChange, err := s.db.PolicyClient.UpdateAttributeValue(s.ctx, &attributes.UpdateAttributeValueRequest{
		Id: created.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(updatedWithoutChange)
	s.Equal(created.GetId(), updatedWithoutChange.GetId())

	// update with changes
	updatedWithChange, err := s.db.PolicyClient.UpdateAttributeValue(s.ctx, &attributes.UpdateAttributeValueRequest{
		Metadata: &common.MetadataMutable{
			Labels: updateLabels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
		Id:                     created.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(updatedWithChange)
	s.Equal(created.GetId(), updatedWithChange.GetId())

	// get it again to verify it was updated
	got, err := s.db.PolicyClient.GetAttributeValue(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.EqualValues(expectedLabels, got.GetMetadata().GetLabels())
	metadata := got.GetMetadata()
	createdAt := metadata.GetCreatedAt()
	updatedAt := metadata.GetUpdatedAt()
	s.False(createdAt.AsTime().IsZero())
	s.False(updatedAt.AsTime().IsZero())
	s.True(updatedAt.AsTime().After(createdAt.AsTime()))
}

func (s *AttributeValuesSuite) Test_UpdateAttributeValue_WithInvalidId_Fails() {
	updated, err := s.db.PolicyClient.UpdateAttributeValue(s.ctx, &attributes.UpdateAttributeValueRequest{
		// some data is required to ensure the request reaches the db
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"update": "true",
			},
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
		Id:                     absentAttributeValueUUID,
	})
	s.Require().Error(err)
	s.Nil(updated)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributeValuesSuite) Test_UnsafeUpdateAttributeValue() {
	// create a value
	attrDef := s.f.GetAttributeKey("example.net/attr/attr1")
	created, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attrDef.ID, &attributes.CreateAttributeValueRequest{
		Value: "created_value",
	})
	s.Require().NoError(err)
	s.NotNil(created)

	// update with changes
	updatedWithChange, err := s.db.PolicyClient.UnsafeUpdateAttributeValue(s.ctx, &unsafe.UnsafeUpdateAttributeValueRequest{
		Id:    created.GetId(),
		Value: "new_value",
	})
	s.Require().NoError(err)
	s.NotNil(updatedWithChange)
	s.Equal(created.GetId(), updatedWithChange.GetId())

	// get it again to verify it was updated
	got, err := s.db.PolicyClient.GetAttributeValue(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Equal("new_value", got.GetValue())

	// verify can get the new by fqn but not the original
	original := "https://example.net/attr/attr1/value/created_value"
	retrieved, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{original},
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(retrieved)

	updated := "https://example.net/attr/attr1/value/new_value"
	retrieved, err = s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{updated},
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	s.Require().NoError(err)
	s.NotNil(retrieved)
	s.Len(retrieved, 1)
	s.Equal(updated, retrieved[updated].GetValue().GetFqn())

	// get its parent attribute to verify the value was updated
	attribute, err := s.db.PolicyClient.GetAttribute(s.ctx, attrDef.ID)
	s.Require().NoError(err)
	s.NotNil(attribute)
	for _, v := range attribute.GetValues() {
		if v.GetId() == got.GetId() {
			s.Equal("new_value", v.GetValue())
		}
		s.NotEqual("created_value", v.GetValue())
	}
}

func (s *AttributeValuesSuite) Test_UnsafeUpdateAttributeValue_WithInvalidId_Fails() {
	updated, err := s.db.PolicyClient.UnsafeUpdateAttributeValue(s.ctx, &unsafe.UnsafeUpdateAttributeValueRequest{
		Id:    absentAttributeValueUUID,
		Value: "new_value",
	})
	s.Require().Error(err)
	s.Nil(updated)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributeValuesSuite) Test_UnsafeUpdateAttributeValue_CasingNormalized() {
	// create a value
	attrDef := s.f.GetAttributeKey("example.net/attr/attr1")
	created, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attrDef.ID, &attributes.CreateAttributeValueRequest{
		Value: "CREATED",
	})
	s.Require().NoError(err)
	s.NotNil(created)
	got, _ := s.db.PolicyClient.GetAttributeValue(s.ctx, created.GetId())
	s.NotNil(got)
	s.Equal("created", got.GetValue())

	// update with changes
	updatedWithChange, err := s.db.PolicyClient.UnsafeUpdateAttributeValue(s.ctx, &unsafe.UnsafeUpdateAttributeValueRequest{
		Id:    created.GetId(),
		Value: "NEW_VALUE_UPPER_CASE",
	})
	s.Require().NoError(err)
	s.NotNil(updatedWithChange)
	s.Equal(created.GetId(), updatedWithChange.GetId())

	// get it again to verify it was updated
	got, err = s.db.PolicyClient.GetAttributeValue(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Equal("new_value_upper_case", got.GetValue())
}

func (s *AttributeValuesSuite) Test_UnsafeDeleteAttributeValue() {
	attrID := s.f.GetAttributeKey("example.net/attr/attr1").ID
	// create a value
	value := &attributes.CreateAttributeValueRequest{
		Value: "created_delete",
	}
	created, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attrID, value)
	s.Require().NoError(err)
	s.NotNil(created)
	got, _ := s.db.PolicyClient.GetAttributeValue(s.ctx, created.GetId())
	s.NotNil(got)

	// delete it
	req := &unsafe.UnsafeDeleteAttributeValueRequest{
		Id:  created.GetId(),
		Fqn: got.GetFqn(),
	}
	resp, err := s.db.PolicyClient.UnsafeDeleteAttributeValue(s.ctx, got, req)
	s.Require().NoError(err)
	s.NotNil(resp)

	// get it again to verify it no longer exists
	got, err = s.db.PolicyClient.GetAttributeValue(s.ctx, created.GetId())
	s.Require().Error(err)
	s.Nil(got)

	// verify it's not in the list of parent attribute's values
	attribute, err := s.db.PolicyClient.GetAttribute(s.ctx, attrID)
	s.Require().NoError(err)
	s.NotNil(attribute)
	for _, v := range attribute.GetValues() {
		s.NotEqual(created.GetId(), v.GetId())
	}

	// verify it can be recreated without conflict
	newlyCreated, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attrID, value)
	s.Require().NoError(err)
	s.NotNil(newlyCreated)
	s.NotEqual(newlyCreated.GetId(), created.GetId())
}

func (s *AttributeValuesSuite) Test_UnsafeDeleteAttribute_WrongFqn_Fails() {
	fixtureAttrID := s.f.GetAttributeKey("example.net/attr/attr1").ID

	created, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, fixtureAttrID, &attributes.CreateAttributeValueRequest{
		Value: "delete_test",
	})
	s.Require().NoError(err)
	s.NotNil(created)

	got, _ := s.db.PolicyClient.GetAttributeValue(s.ctx, created.GetId())
	s.NotNil(got)

	req := &unsafe.UnsafeDeleteAttributeValueRequest{
		Id: created.GetId(),
		// wrong namespace
		Fqn: "https://example.com/attr/attr1/value/delete_test",
	}
	resp, err := s.db.PolicyClient.UnsafeDeleteAttributeValue(s.ctx, got, req)
	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributeValuesSuite) Test_DeactivateAttributeValue_WithInvalidIdFails() {
	deactivated, err := s.db.PolicyClient.DeactivateAttributeValue(s.ctx, absentAttributeValueUUID)
	s.Require().Error(err)
	s.Nil(deactivated)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

// reusable setup for creating a namespace -> attr -> value and then deactivating the attribute (cascades to value)
func setupDeactivateAttributeValue(s *AttributeValuesSuite) (string, string, string) {
	// create a namespace
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "cascading-deactivate-attribute-value.com",
	})
	s.Require().NoError(err)
	s.NotZero(n.GetId())

	// add an attribute under that namespaces
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__cascading-deactivate-attr-value",
		NamespaceId: n.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)

	// add a value under that attribute
	val := &attributes.CreateAttributeValueRequest{
		Value: "test__cascading-deactivate-attr-value-value",
	}
	createdVal, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, createdAttr.GetId(), val)
	s.Require().NoError(err)
	s.NotNil(createdVal)

	// deactivate the attribute value
	deactivatedAttr, err := s.db.PolicyClient.DeactivateAttributeValue(s.ctx, createdVal.GetId())
	s.Require().NoError(err)
	s.NotNil(deactivatedAttr)

	return n.GetId(), createdAttr.GetId(), createdVal.GetId()
}

// Verify behavior that DB does not bubble up deactivation of value to attributes and namespaces
func (s *AttributeValuesSuite) Test_DeactivateAttribute_Cascades_List() {
	type test struct {
		name     string
		testFunc func(state common.ActiveStateEnum) bool
		state    common.ActiveStateEnum
		isFound  bool
	}

	listNamespaces := func(state common.ActiveStateEnum) bool {
		listedNamespacesRsp, err := s.db.PolicyClient.ListNamespaces(s.ctx, &namespaces.ListNamespacesRequest{
			State: state,
		})
		s.Require().NoError(err)
		s.NotNil(listedNamespacesRsp)
		listedNamespaces := listedNamespacesRsp.GetNamespaces()
		for _, ns := range listedNamespaces {
			if stillActiveNsID == ns.GetId() {
				return true
			}
		}
		return false
	}

	listAttributes := func(state common.ActiveStateEnum) bool {
		listedAttrsRsp, err := s.db.PolicyClient.ListAttributes(s.ctx, &attributes.ListAttributesRequest{
			State: state,
		})
		s.Require().NoError(err)
		s.NotNil(listedAttrsRsp)
		listedAttrs := listedAttrsRsp.GetAttributes()
		for _, a := range listedAttrs {
			if stillActiveAttributeID == a.GetId() {
				return true
			}
		}
		return false
	}

	listValues := func(state common.ActiveStateEnum) bool {
		listedValsRsp, err := s.db.PolicyClient.ListAttributeValues(s.ctx, &attributes.ListAttributeValuesRequest{
			State:       state,
			AttributeId: stillActiveAttributeID,
		})
		s.Require().NoError(err)
		s.NotNil(listedValsRsp)
		listedVals := listedValsRsp.GetValues()
		for _, v := range listedVals {
			if deactivatedAttrValueID == v.GetId() {
				return true
			}
		}
		return false
	}

	tests := []test{
		{
			name:     "namespace is NOT found in LIST of INACTIVE",
			testFunc: listNamespaces,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE,
			isFound:  false,
		},
		{
			name:     "namespace is found when filtering for ACTIVE state",
			testFunc: listNamespaces,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE,
			isFound:  true,
		},
		{
			name:     "namespace is found when filtering for ANY state",
			testFunc: listNamespaces,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
			isFound:  true,
		},
		{
			name:     "attribute is NOT found when filtering for INACTIVE state",
			testFunc: listAttributes,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE,
			isFound:  false,
		},
		{
			name:     "attribute is found when filtering for ANY state",
			testFunc: listAttributes,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
			isFound:  true,
		},
		{
			name:     "attribute is found when filtering for ACTIVE state",
			testFunc: listAttributes,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE,
			isFound:  true,
		},
		{
			name:     "value is NOT found in LIST of ACTIVE",
			testFunc: listValues,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE,
			isFound:  false,
		},
		{
			name:     "value is found when filtering for INACTIVE state",
			testFunc: listValues,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE,
			isFound:  true,
		},
		{
			name:     "value is found when filtering for ANY state",
			testFunc: listValues,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
			isFound:  true,
		},
	}

	for _, tableTest := range tests {
		s.Run(tableTest.name, func() {
			found := tableTest.testFunc(tableTest.state)
			s.Equal(tableTest.isFound, found)
		})
	}
}

func (s *AttributeValuesSuite) Test_DeactivateAttributeValue_Get() {
	// namespace is still active (not bubbled up)
	gotNs, err := s.db.PolicyClient.GetNamespace(s.ctx, stillActiveNsID)
	s.Require().NoError(err)
	s.NotNil(gotNs)
	s.True(gotNs.GetActive().GetValue())

	// attribute is still active (not bubbled up)
	gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, stillActiveAttributeID)
	s.Require().NoError(err)
	s.NotNil(gotAttr)
	s.True(gotAttr.GetActive().GetValue())

	// value was deactivated
	gotVal, err := s.db.PolicyClient.GetAttributeValue(s.ctx, deactivatedAttrValueID)
	s.Require().NoError(err)
	s.NotNil(gotVal)
	s.False(gotVal.GetActive().GetValue())
}

func (s *AttributeValuesSuite) Test_UnsafeReactivateAttributeValue() {
	// create a value
	attrDef := s.f.GetAttributeKey("example.com/attr/attr1")
	created, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attrDef.ID, &attributes.CreateAttributeValueRequest{
		Value: "testing_reactivation",
	})
	s.Require().NoError(err)
	s.NotNil(created)

	// deactivate the value
	deactivated, err := s.db.PolicyClient.DeactivateAttributeValue(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(deactivated)

	got, _ := s.db.PolicyClient.GetAttributeValue(s.ctx, created.GetId())
	s.NotNil(got)
	s.False(got.GetActive().GetValue())

	// reactivate the value
	reactivated, err := s.db.PolicyClient.UnsafeReactivateAttributeValue(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(reactivated)

	// get it again to verify it was reactivated
	got, err = s.db.PolicyClient.GetAttributeValue(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.True(got.GetActive().GetValue())
}

func (s *AttributeValuesSuite) Test_UnsafeReactivateAttributeValue_WithInvalidIdFails() {
	reactivated, err := s.db.PolicyClient.UnsafeReactivateAttributeValue(s.ctx, absentAttributeValueUUID)
	s.Require().Error(err)
	s.Nil(reactivated)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributeValuesSuite) Test_UnsafeReactivateAttributeValue_DoesNotReactivateParentsOrSiblings() {
	// create an attribute
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_to_deactivate",
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values:      []string{"example_value_1", "example_value_2"},
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)

	got, _ := s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	s.NotNil(got)
	s.True(got.GetActive().GetValue())
	values := got.GetValues()

	// deactivate the attribute
	deactivated, err := s.db.PolicyClient.DeactivateAttribute(s.ctx, createdAttr.GetId())
	s.Require().NoError(err)
	s.NotNil(deactivated)

	// ensure values are deactivated
	for _, v := range values {
		gotVal, _ := s.db.PolicyClient.GetAttributeValue(s.ctx, v.GetId())
		s.NotNil(gotVal)
		s.False(gotVal.GetActive().GetValue())
	}

	// reactivate the first value
	reactivated, err := s.db.PolicyClient.UnsafeReactivateAttributeValue(s.ctx, values[0].GetId())
	s.Require().NoError(err)
	s.NotNil(reactivated)

	// ensure the value is now active
	gotVal, _ := s.db.PolicyClient.GetAttributeValue(s.ctx, values[0].GetId())
	s.NotNil(gotVal)
	s.True(gotVal.GetActive().GetValue())

	// ensure the attribute is still deactivated
	gotAttr, _ := s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	s.NotNil(gotAttr)
	s.False(gotAttr.GetActive().GetValue())

	// ensure the second value is still deactivated
	gotVal, _ = s.db.PolicyClient.GetAttributeValue(s.ctx, values[1].GetId())
	s.NotNil(gotVal)
	s.False(gotVal.GetActive().GetValue())
}

func (s *AttributeValuesSuite) Test_AssignKeyAccessServerToValue_Returns_Error_When_Value_Not_Found() {
	v := &attributes.ValueKeyAccessServer{
		ValueId:           absentAttributeValueUUID,
		KeyAccessServerId: fixtureKeyAccessServerID,
	}

	resp, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, v)

	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorIs(err, db.ErrForeignKeyViolation)
}

func (s *AttributeValuesSuite) Test_AssignKeyAccessServerToValue_Returns_Error_When_KeyAccessServer_Not_Found() {
	v := &attributes.ValueKeyAccessServer{
		ValueId:           s.f.GetAttributeValueKey("example.net/attr/attr1/value/value1").ID,
		KeyAccessServerId: nonExistentKasRegistryID,
	}

	resp, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, v)

	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorIs(err, db.ErrForeignKeyViolation)
}

func (s *AttributeValuesSuite) Test_AssignKeyAccessServerToValue_Returns_Success_When_Value_And_KeyAccessServer_Exist() {
	v := &attributes.ValueKeyAccessServer{
		ValueId:           s.f.GetAttributeValueKey("example.net/attr/attr1/value/value1").ID,
		KeyAccessServerId: fixtureKeyAccessServerID,
	}

	resp, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, v)

	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(v, resp)
}

func (s *AttributeValuesSuite) Test_RemoveKeyAccessServerFromValue_Returns_Error_When_Value_Not_Found() {
	v := &attributes.ValueKeyAccessServer{
		ValueId:           absentAttributeValueUUID,
		KeyAccessServerId: fixtureKeyAccessServerID,
	}

	resp, err := s.db.PolicyClient.RemoveKeyAccessServerFromValue(s.ctx, v)

	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributeValuesSuite) Test_RemoveKeyAccessServerFromValue_Returns_Error_When_KeyAccessServer_Not_Found() {
	v := &attributes.ValueKeyAccessServer{
		ValueId:           s.f.GetAttributeValueKey("example.net/attr/attr1/value/value1").ID,
		KeyAccessServerId: nonExistentAttrID,
	}

	resp, err := s.db.PolicyClient.RemoveKeyAccessServerFromValue(s.ctx, v)

	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributeValuesSuite) Test_RemoveKeyAccessServerFromValue_Returns_Success_When_Value_And_KeyAccessServer_Exist() {
	v := &attributes.ValueKeyAccessServer{
		ValueId:           s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1").ID,
		KeyAccessServerId: s.f.GetKasRegistryKey("key_access_server_1").ID,
	}

	resp, err := s.db.PolicyClient.RemoveKeyAccessServerFromValue(s.ctx, v)

	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(v, resp)
}

func TestAttributeValuesSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping attribute values integration tests")
	}
	suite.Run(t, new(AttributeValuesSuite))
}
