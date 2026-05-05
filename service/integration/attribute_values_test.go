package integration

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/suite"
)

var absentAttributeValueUUID = "78909865-8888-9999-9999-000000000000"

type AttributeValuesSuite struct {
	suite.Suite
	f           fixtures.Fixtures
	db          fixtures.DBInterface
	ctx         context.Context //nolint:containedctx // context is used in the test suite
	namespaces  []*policy.Namespace
	obligations []*policy.Obligation
}

func (s *AttributeValuesSuite) SetupSuite() {
	slog.Info("setting up db.AttributeValues test suite")
	s.ctx = context.Background()
	fixtureNamespaceID = s.f.GetNamespaceKey("example.com").ID
	fixtureKeyAccessServerID = s.f.GetKasRegistryKey("key_access_server_1").ID
	c := *Config
	c.DB.Schema = "test_opentdf_attribute_values"
	s.db = fixtures.NewDBInterface(s.ctx, c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision(s.ctx)
	stillActiveNsID, stillActiveAttributeID, deactivatedAttrValueID = setupDeactivateAttributeValue(s)
}

func (s *AttributeValuesSuite) SetupTest() {
	s.namespaces = make([]*policy.Namespace, 0)
	s.obligations = make([]*policy.Obligation, 0)
}

func (s *AttributeValuesSuite) TearDownTest() {
	for _, obl := range s.obligations {
		_, err := s.db.PolicyClient.DeleteObligation(s.ctx, &obligations.DeleteObligationRequest{
			Id:  obl.GetId(),
			Fqn: obl.GetFqn(),
		})
		s.Require().NoError(err)
	}
	for _, namespace := range s.namespaces {
		_, err := s.db.PolicyClient.UnsafeDeleteNamespace(s.ctx, namespace, namespace.GetFqn())
		s.Require().NoError(err)
	}
}

func (s *AttributeValuesSuite) TearDownSuite() {
	slog.Info("tearing down db.AttributeValues test suite")
	s.f.TearDown(s.ctx)
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
	s.Equal(createdValue.GetMetadata().GetLabels(), got.GetMetadata().GetLabels())
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
	s.Equal(expectedLabels, got.GetMetadata().GetLabels())
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
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(retrieved)

	updated := "https://example.net/attr/attr1/value/new_value"
	retrieved, err = s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{updated},
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
	s.NotEmpty(n.GetId())

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
		gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, stillActiveAttributeID)
		s.Require().NoError(err)
		s.NotNil(gotAttr)
		for _, v := range gotAttr.GetValues() {
			if deactivatedAttrValueID != v.GetId() {
				continue
			}
			switch state {
			case common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE:
				return v.GetActive().GetValue()
			case common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE:
				return !v.GetActive().GetValue()
			case common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY:
				return true
			case common.ActiveStateEnum_ACTIVE_STATE_ENUM_UNSPECIFIED:
				return v.GetActive().GetValue()
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

// Add tests for assinging key to value / removing key from value

func (s *AttributeValuesSuite) Test_AssignPublicKeyToAttributeValue_Returns_Error_When_Attribute_Not_Found() {
	kasKeys := s.f.GetKasRegistryServerKeys("kas_key_1")
	resp, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &attributes.ValueKey{
		ValueId: nonExistentAttrID,
		KeyId:   kasKeys.ID,
	})

	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorIs(err, db.ErrForeignKeyViolation)
}

func (s *AttributeValuesSuite) Test_AssignPublicKeyToAttributeValue_NotActiveKey_Fail() {
	var kasID string
	keys := make([]*policy.KasKey, 0)
	defer func() {
		for _, key := range keys {
			r := &unsafe.UnsafeDeleteKasKeyRequest{
				Id:     key.GetKey().GetId(),
				Kid:    key.GetKey().GetKeyId(),
				KasUri: key.GetKasUri(),
			}
			_, err := s.db.PolicyClient.UnsafeDeleteKey(s.ctx, key, r)
			s.Require().NoError(err)
		}

		if kasID != "" {
			// delete the kas
			_, err := s.db.PolicyClient.DeleteKeyAccessServer(s.ctx, kasID)
			s.Require().NoError(err)
		}
	}()

	// create a KAS
	kas := &kasregistry.CreateKeyAccessServerRequest{
		Uri: "https://example.com/kas-av-not-active",
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Remote{
				Remote: "https://example.com/kas-av-not-active/key/1",
			},
		},
		Name: "def_kas_name_av_not_active",
	}
	createdKAS, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, kas)
	s.Require().NoError(err)
	s.NotNil(createdKAS)
	kasID = createdKAS.GetId()

	// create a key
	kasKey := &kasregistry.CreateKeyRequest{
		KasId:        kasID,
		KeyId:        "kas_key_1_av_not_active",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:      policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
		PublicKeyCtx: &policy.PublicKeyCtx{
			Pem: keyCtx, // Assuming keyCtx is defined in the test suite or fixtures
		},
	}
	toBeRotatedKey, err := s.db.PolicyClient.CreateKey(s.ctx, kasKey)
	s.Require().NoError(err)
	s.NotNil(toBeRotatedKey)
	keys = append(keys, toBeRotatedKey.GetKasKey())

	// rotate the key
	newKey := &kasregistry.RotateKeyRequest_NewKey{
		KeyId:     "kas_key_1_av_not_active_rotated",
		Algorithm: policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:   policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
		PublicKeyCtx: &policy.PublicKeyCtx{
			Pem: keyCtx, // Assuming keyCtx is defined
		},
	}
	rotatedInKey, err := s.db.PolicyClient.RotateKey(s.ctx, toBeRotatedKey.GetKasKey(), newKey)
	s.Require().NoError(err)
	s.NotNil(rotatedInKey)
	keys = append(keys, rotatedInKey.GetKasKey())

	// Get an attribute value
	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")

	// Attempt to assign the original (now inactive) key to the attribute value
	resp, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &attributes.ValueKey{
		ValueId: attrValue.ID,
		KeyId:   toBeRotatedKey.GetKasKey().GetKey().GetId(),
	})
	s.Require().Error(err)
	s.Nil(resp)
	s.Require().Contains(err.Error(), fmt.Sprintf("key with id %s is not active", toBeRotatedKey.GetKasKey().GetKey().GetId()))
}

func (s *AttributeValuesSuite) Test_AssignPublicKeyToAttributeValue_Returns_Error_When_Key_Not_Found() {
	f := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	resp, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &attributes.ValueKey{
		ValueId: f.ID,
		KeyId:   nonExistentAttrID,
	})

	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributeValuesSuite) Test_AssignPublicKeyToAttributeValue_Succeeds() {
	f := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	gotAttrValue, err := s.db.PolicyClient.GetAttributeValue(s.ctx, &attributes.GetAttributeValueRequest_ValueId{
		ValueId: f.ID,
	})
	s.Require().NoError(err)
	s.NotNil(gotAttrValue)
	s.Empty(gotAttrValue.GetKasKeys())

	kasKeyFixture := s.f.GetKasRegistryServerKeys("kas_key_1")
	kasKey, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{Id: kasKeyFixture.ID})
	s.Require().NoError(err)
	resp, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &attributes.ValueKey{
		ValueId: gotAttrValue.GetId(),
		KeyId:   kasKey.GetKey().GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(resp)

	gotAttrValue, err = s.db.PolicyClient.GetAttributeValue(s.ctx, &attributes.GetAttributeValueRequest_ValueId{
		ValueId: f.ID,
	})
	s.Require().NoError(err)
	s.NotNil(gotAttrValue)
	s.Len(gotAttrValue.GetKasKeys(), 1)
	validateSimpleKasKey(&s.Suite, kasKey, gotAttrValue.GetKasKeys()[0])

	resp, err = s.db.PolicyClient.RemovePublicKeyFromValue(s.ctx, &attributes.ValueKey{
		ValueId: gotAttrValue.GetId(),
		KeyId:   kasKey.GetKey().GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(resp)

	gotAttrValue, err = s.db.PolicyClient.GetAttributeValue(s.ctx, &attributes.GetAttributeValueRequest_ValueId{
		ValueId: f.ID,
	})
	s.Require().NoError(err)
	s.NotNil(gotAttrValue)
	s.Empty(gotAttrValue.GetKasKeys())
}

func (s *AttributeValuesSuite) Test_RemovePublicKeyFromAttributeValue_Not_Found_Fails() {
	f := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	gotAttr, err := s.db.PolicyClient.GetAttributeValue(s.ctx, f.ID)
	s.Require().NoError(err)
	s.NotNil(gotAttr)
	s.Empty(gotAttr.GetKasKeys())

	kasKey := s.f.GetKasRegistryServerKeys("kas_key_1")
	resp, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &attributes.ValueKey{
		ValueId: f.ID,
		KeyId:   kasKey.ID,
	})
	s.Require().NoError(err)
	s.NotNil(resp)

	invalidResp, err := s.db.PolicyClient.RemovePublicKeyFromValue(s.ctx, &attributes.ValueKey{
		ValueId: "009735f1-0fcf-4deb-a47b-760d0ae65fef", // uuid
		KeyId:   resp.GetKeyId(),
	})
	s.Require().Error(err)
	s.Nil(invalidResp)
	s.Require().ErrorIs(err, db.ErrNotFound)

	invalidResp, err = s.db.PolicyClient.RemovePublicKeyFromValue(s.ctx, &attributes.ValueKey{
		ValueId: resp.GetValueId(),
		KeyId:   nonExistentKeyID,
	})
	s.Require().Error(err)
	s.Nil(invalidResp)
	s.Require().ErrorIs(err, db.ErrNotFound)

	resp, err = s.db.PolicyClient.RemovePublicKeyFromValue(s.ctx, &attributes.ValueKey{
		ValueId: resp.GetValueId(),
		KeyId:   resp.GetKeyId(),
	})
	s.Require().NoError(err)
	s.NotNil(resp)
}

func (s *AttributeValuesSuite) Test_GetAttributeValue_With_Two_Obligations_Success() {
	// Create a namespace
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test-obligations.com",
	})
	s.Require().NoError(err)
	s.NotNil(ns)
	s.namespaces = append(s.namespaces, ns)

	// Create an attribute definition
	attrDef, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		Name:        "test-attr-for-obligations",
		NamespaceId: ns.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	})
	s.Require().NoError(err)
	s.NotNil(attrDef)

	// Create a test attribute value that will have obligations triggered by it
	req := &attributes.CreateAttributeValueRequest{
		Value: "test_value_with_obligations",
	}
	createdValue, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attrDef.GetId(), req)
	s.Require().NoError(err)
	s.NotNil(createdValue)

	// Create first obligation with two obligation values
	obl1, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceId: ns.GetId(),
		Name:        "test_obligation_1",
	})
	s.Require().NoError(err)
	s.obligations = append(s.obligations, obl1)

	// Create first obligation value with two triggers
	readAction := s.getActionByNameInNamespace("read", ns.GetId())
	updateAction := s.getActionByNameInNamespace("update", ns.GetId())

	obl1Val1, err := s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationId: obl1.GetId(),
		Value:        "obligation_value_1",
		Triggers: []*obligations.ValueTriggerRequest{
			{
				Action:         &common.IdNameIdentifier{Id: readAction.GetId()},
				AttributeValue: &common.IdFqnIdentifier{Id: createdValue.GetId()},
				Context: &policy.RequestContext{
					Pep: &policy.PolicyEnforcementPoint{
						ClientId: "test-client-1",
					},
				},
			},
			{
				Action:         &common.IdNameIdentifier{Id: updateAction.GetId()},
				AttributeValue: &common.IdFqnIdentifier{Id: createdValue.GetId()},
				Context: &policy.RequestContext{
					Pep: &policy.PolicyEnforcementPoint{
						ClientId: "test-client-2",
					},
				},
			},
		},
	})
	s.Require().NoError(err)

	// Create second obligation value with two triggers
	obl1Val2, err := s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationId: obl1.GetId(),
		Value:        "obligation_value_2",
		Triggers: []*obligations.ValueTriggerRequest{
			{
				Action:         &common.IdNameIdentifier{Id: readAction.GetId()},
				AttributeValue: &common.IdFqnIdentifier{Id: createdValue.GetId()},
				Context: &policy.RequestContext{
					Pep: &policy.PolicyEnforcementPoint{
						ClientId: "test-client-3",
					},
				},
			},
		},
	})
	s.Require().NoError(err)

	// Create second obligation with one obligation value
	obl2, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceId: ns.GetId(),
		Name:        "test_obligation_2",
	})
	s.Require().NoError(err)
	s.obligations = append(s.obligations, obl2)

	// Create obligation value with one trigger
	obl2Val1, err := s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationId: obl2.GetId(),
		Value:        "obligation_value_3",
		Triggers: []*obligations.ValueTriggerRequest{
			{
				Action:         &common.IdNameIdentifier{Id: updateAction.GetId()},
				AttributeValue: &common.IdFqnIdentifier{Id: createdValue.GetId()},
				Context: &policy.RequestContext{
					Pep: &policy.PolicyEnforcementPoint{
						ClientId: "test-client-5",
					},
				},
			},
		},
	})
	s.Require().NoError(err)

	// Test GetAttributeValue and verify obligations are returned
	retrievedValue, err := s.db.PolicyClient.GetAttributeValue(s.ctx, createdValue.GetId())
	s.Require().NoError(err)
	s.NotNil(retrievedValue)
	s.Require().Len(retrievedValue.GetObligations(), 2)

	obl1.Values = append(obl1.Values, obl1Val1, obl1Val2)
	obl2.Values = append(obl2.Values, obl2Val1)
	s.assertObligations([]*policy.Obligation{obl1, obl2}, retrievedValue.GetObligations())
}

func (s *AttributeValuesSuite) Test_CreateAttributeValue_WithObligationTriggers_Succeeds() {
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test-inline-obligation-triggers.com",
	})
	s.Require().NoError(err)
	s.NotNil(ns)
	s.namespaces = append(s.namespaces, ns)

	attrDef, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		Name:        "test-inline-obligation-triggers-attr",
		NamespaceId: ns.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	})
	s.Require().NoError(err)
	s.NotNil(attrDef)

	obl1, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceId: ns.GetId(),
		Name:        "test_inline_obligation_1",
	})
	s.Require().NoError(err)
	s.obligations = append(s.obligations, obl1)

	obl2, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceId: ns.GetId(),
		Name:        "test_inline_obligation_2",
	})
	s.Require().NoError(err)
	s.obligations = append(s.obligations, obl2)

	obl1Val1, err := s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationId: obl1.GetId(),
		Value:        "inline_obligation_value_1",
	})
	s.Require().NoError(err)

	obl1Val2, err := s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationId: obl1.GetId(),
		Value:        "inline_obligation_value_2",
	})
	s.Require().NoError(err)

	obl2Val1, err := s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationId: obl2.GetId(),
		Value:        "inline_obligation_value_3",
	})
	s.Require().NoError(err)

	readAction := s.getActionByNameInNamespace("read", ns.GetId())
	updateAction := s.getActionByNameInNamespace("update", ns.GetId())

	createdValue, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attrDef.GetId(), &attributes.CreateAttributeValueRequest{
		Value: "test_value_with_inline_triggers",
		ObligationTriggers: []*attributes.AttributeValueObligationTriggerRequest{
			{
				ObligationValue: &common.IdFqnIdentifier{Id: obl1Val1.GetId()},
				Action:          &common.IdNameIdentifier{Id: readAction.GetId()},
				Metadata: &common.MetadataMutable{
					Labels: map[string]string{"source": "inline-trigger-1"},
				},
				Context: &policy.RequestContext{
					Pep: &policy.PolicyEnforcementPoint{
						ClientId: "test-client-1",
					},
				},
			},
			{
				ObligationValue: &common.IdFqnIdentifier{Fqn: obl1Val2.GetFqn()},
				Action:          &common.IdNameIdentifier{Name: updateAction.GetName()},
				Context: &policy.RequestContext{
					Pep: &policy.PolicyEnforcementPoint{
						ClientId: "test-client-2",
					},
				},
			},
			{
				ObligationValue: &common.IdFqnIdentifier{Id: obl2Val1.GetId()},
				Action:          &common.IdNameIdentifier{Name: readAction.GetName()},
			},
		},
	})
	s.Require().NoError(err)
	s.NotNil(createdValue)
	s.Require().Len(createdValue.GetObligations(), 2)

	retrievedValue, err := s.db.PolicyClient.GetAttributeValue(s.ctx, createdValue.GetId())
	s.Require().NoError(err)
	s.NotNil(retrievedValue)
	s.Require().Len(retrievedValue.GetObligations(), 2)

	obligationsByID := make(map[string]*policy.Obligation)
	for _, obligation := range retrievedValue.GetObligations() {
		obligationsByID[obligation.GetId()] = obligation
	}

	retrievedObl1, found := obligationsByID[obl1.GetId()]
	s.Require().True(found)
	s.Require().Len(retrievedObl1.GetValues(), 2)

	retrievedObl1Values := make(map[string]*policy.ObligationValue)
	for _, value := range retrievedObl1.GetValues() {
		retrievedObl1Values[value.GetId()] = value
	}

	s.assertObligationValueHasSingleTrigger(retrievedObl1Values[obl1Val1.GetId()], obl1Val1, readAction, createdValue, "test-client-1")
	s.assertObligationValueHasSingleTrigger(retrievedObl1Values[obl1Val2.GetId()], obl1Val2, updateAction, createdValue, "test-client-2")

	triggerWithMetadata, err := s.db.PolicyClient.GetObligationTrigger(s.ctx, &obligations.GetObligationTriggerRequest{
		Id: retrievedObl1Values[obl1Val1.GetId()].GetTriggers()[0].GetId(),
	})
	s.Require().NoError(err)
	s.Require().NotNil(triggerWithMetadata.GetMetadata())
	s.Equal("inline-trigger-1", triggerWithMetadata.GetMetadata().GetLabels()["source"])

	retrievedObl2, found := obligationsByID[obl2.GetId()]
	s.Require().True(found)
	s.Require().Len(retrievedObl2.GetValues(), 1)
	s.assertObligationValueHasSingleTrigger(retrievedObl2.GetValues()[0], obl2Val1, readAction, createdValue, "")
}

func (s *AttributeValuesSuite) Test_CreateAttributeValue_WithObligationTriggers_CrossNamespaceObligationValue_Succeeds() {
	sourceNamespace, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test-inline-cross-namespace-trigger-source.com",
	})
	s.Require().NoError(err)
	s.NotNil(sourceNamespace)
	s.namespaces = append(s.namespaces, sourceNamespace)

	attrDef, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		Name:        "test-inline-cross-namespace-trigger-attr",
		NamespaceId: sourceNamespace.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	})
	s.Require().NoError(err)
	s.NotNil(attrDef)

	targetNamespace, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test-inline-cross-namespace-trigger-target.com",
	})
	s.Require().NoError(err)
	s.NotNil(targetNamespace)
	s.namespaces = append(s.namespaces, targetNamespace)

	targetObligation, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceId: targetNamespace.GetId(),
		Name:        "test_inline_cross_namespace_obligation",
	})
	s.Require().NoError(err)
	s.obligations = append(s.obligations, targetObligation)

	targetObligationValue, err := s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationId: targetObligation.GetId(),
		Value:        "inline_cross_namespace_obligation_value",
	})
	s.Require().NoError(err)

	customAction, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name:        "inline-cross-namespace-trigger-action",
		NamespaceId: sourceNamespace.GetId(),
	})
	s.Require().NoError(err)

	createdValue, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attrDef.GetId(), &attributes.CreateAttributeValueRequest{
		Value: "test_value_with_cross_namespace_inline_trigger",
		ObligationTriggers: []*attributes.AttributeValueObligationTriggerRequest{
			{
				ObligationValue: &common.IdFqnIdentifier{Fqn: targetObligationValue.GetFqn()},
				Action:          &common.IdNameIdentifier{Name: customAction.GetName()},
				Context: &policy.RequestContext{
					Pep: &policy.PolicyEnforcementPoint{
						ClientId: "cross-namespace-inline-client",
					},
				},
			},
		},
	})
	s.Require().NoError(err)
	s.NotNil(createdValue)
	s.Require().Len(createdValue.GetObligations(), 1)

	retrievedValue, err := s.db.PolicyClient.GetAttributeValue(s.ctx, createdValue.GetId())
	s.Require().NoError(err)
	s.NotNil(retrievedValue)
	s.Require().Len(retrievedValue.GetObligations(), 1)

	retrievedObligation := retrievedValue.GetObligations()[0]
	s.Equal(targetObligation.GetId(), retrievedObligation.GetId())
	s.Equal(targetObligation.GetName(), retrievedObligation.GetName())
	s.Require().NotNil(retrievedObligation.GetNamespace())
	s.Equal(targetNamespace.GetFqn(), retrievedObligation.GetNamespace().GetFqn())
	s.Require().Len(retrievedObligation.GetValues(), 1)

	s.assertObligationValueHasSingleTrigger(
		retrievedObligation.GetValues()[0],
		targetObligationValue,
		customAction,
		createdValue,
		"cross-namespace-inline-client",
	)
}

func (s *AttributeValuesSuite) Test_CreateAttributeValue_WithObligationTriggers_ObligationValueFQNNotFound_Fails() {
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test-inline-obligation-trigger-missing-obligation-fqn.com",
	})
	s.Require().NoError(err)
	s.NotNil(ns)
	s.namespaces = append(s.namespaces, ns)

	attrDef, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		Name:        "test-inline-obligation-trigger-missing-obligation-fqn-attr",
		NamespaceId: ns.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	})
	s.Require().NoError(err)
	s.NotNil(attrDef)

	obl, err := s.db.PolicyClient.CreateObligation(s.ctx, &obligations.CreateObligationRequest{
		NamespaceId: ns.GetId(),
		Name:        "test_inline_missing_obligation_fqn",
	})
	s.Require().NoError(err)
	s.obligations = append(s.obligations, obl)

	_, err = s.db.PolicyClient.CreateObligationValue(s.ctx, &obligations.CreateObligationValueRequest{
		ObligationId: obl.GetId(),
		Value:        "test_inline_missing_obligation_fqn_value",
	})
	s.Require().NoError(err)

	readAction := s.getActionByNameInNamespace("read", ns.GetId())

	createdValue, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attrDef.GetId(), &attributes.CreateAttributeValueRequest{
		Value: "test_value_missing_obligation_fqn",
		ObligationTriggers: []*attributes.AttributeValueObligationTriggerRequest{
			{
				ObligationValue: &common.IdFqnIdentifier{
					Fqn: ns.GetFqn() + "/obl/" + obl.GetName() + "/value/missing_obligation_value",
				},
				Action: &common.IdNameIdentifier{Id: readAction.GetId()},
			},
		},
	})
	s.Require().Error(err)
	s.Nil(createdValue)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func TestAttributeValuesSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping attribute values integration tests")
	}
	suite.Run(t, new(AttributeValuesSuite))
}

func (s *AttributeValuesSuite) getActionByNameInNamespace(name string, namespaceID string) *policy.Action {
	action, err := s.db.PolicyClient.GetAction(s.ctx, &actions.GetActionRequest{
		Identifier:  &actions.GetActionRequest_Name{Name: name},
		NamespaceId: namespaceID,
	})
	s.Require().NoError(err)
	return action
}

func (s *AttributeValuesSuite) assertObligationValueHasSingleTrigger(
	actualObligationValue *policy.ObligationValue,
	expectedObligationValue *policy.ObligationValue,
	expectedAction *policy.Action,
	expectedAttributeValue *policy.Value,
	expectedClientID string,
) {
	s.Require().NotNil(actualObligationValue)
	s.Equal(expectedObligationValue.GetId(), actualObligationValue.GetId())
	s.Equal(expectedObligationValue.GetValue(), actualObligationValue.GetValue())
	s.Equal(expectedObligationValue.GetFqn(), actualObligationValue.GetFqn())
	s.Require().Len(actualObligationValue.GetTriggers(), 1)

	trigger := actualObligationValue.GetTriggers()[0]
	s.Require().NotEmpty(trigger.GetId())

	if trigger.GetObligationValue() != nil {
		s.Equal(expectedObligationValue.GetId(), trigger.GetObligationValue().GetId())
		s.Equal(expectedObligationValue.GetValue(), trigger.GetObligationValue().GetValue())
		s.Equal(expectedObligationValue.GetFqn(), trigger.GetObligationValue().GetFqn())
		s.Require().NotNil(trigger.GetObligationValue().GetObligation())
		s.Equal(expectedObligationValue.GetObligation().GetId(), trigger.GetObligationValue().GetObligation().GetId())
		s.Equal(expectedObligationValue.GetObligation().GetName(), trigger.GetObligationValue().GetObligation().GetName())
		s.Equal(expectedObligationValue.GetObligation().GetNamespace().GetFqn(), trigger.GetObligationValue().GetObligation().GetNamespace().GetFqn())
	}

	s.Require().NotNil(trigger.GetAction())
	s.Equal(expectedAction.GetId(), trigger.GetAction().GetId())
	s.Equal(expectedAction.GetName(), trigger.GetAction().GetName())
	s.Require().NotNil(trigger.GetNamespace())
	s.NotEmpty(trigger.GetNamespace().GetId())
	s.Equal(strings.Split(expectedAttributeValue.GetFqn(), "/attr/")[0], trigger.GetNamespace().GetFqn())

	s.Require().NotNil(trigger.GetAttributeValue())
	s.Equal(expectedAttributeValue.GetId(), trigger.GetAttributeValue().GetId())
	s.Equal(expectedAttributeValue.GetFqn(), trigger.GetAttributeValue().GetFqn())
	if trigger.GetAttributeValue().GetValue() != "" {
		s.Equal(expectedAttributeValue.GetValue(), trigger.GetAttributeValue().GetValue())
	}

	if expectedClientID == "" {
		s.Empty(trigger.GetContext())
		return
	}

	s.Require().Len(trigger.GetContext(), 1)
	s.Equal(expectedClientID, trigger.GetContext()[0].GetPep().GetClientId())
}

func (s *AttributeValuesSuite) assertObligations(expected, actual []*policy.Obligation) {
	s.Require().Len(actual, len(expected), "number of obligations does not match")

	expectedMap := make(map[string]*policy.Obligation)
	for _, obl := range expected {
		expectedMap[obl.GetId()] = obl
	}

	for _, actObl := range actual {
		expObl, foundObl := expectedMap[actObl.GetId()]
		s.Require().True(foundObl, "unexpected obligation with ID %s", actObl.GetId())
		s.Equal(expObl.GetName(), actObl.GetName(), "obligation name mismatch for ID %s", actObl.GetId())
		s.Require().Len(actObl.GetValues(), len(expObl.GetValues()), "number of obligation values does not match for obligation ID %s", actObl.GetId())
		s.Require().Equal(expObl.GetFqn(), actObl.GetFqn(), "obligation namespace FQN mismatch for obligation ID %s", actObl.GetId())

		expValuesMap := make(map[string]*policy.ObligationValue)
		for _, val := range expObl.GetValues() {
			expValuesMap[val.GetId()] = val
		}

		for _, actVal := range actObl.GetValues() {
			expVal, foundVal := expValuesMap[actVal.GetId()]
			s.Require().True(foundVal, "unexpected obligation value with ID %s for obligation ID %s", actVal.GetId(), actObl.GetId())
			s.Require().Equal(expVal.GetValue(), actVal.GetValue(), "obligation value mismatch for value ID %s", actVal.GetId())
			s.Require().Len(actVal.GetTriggers(), len(expVal.GetTriggers()), "number of triggers does not match for obligation value ID %s", actVal.GetId())
			s.Require().Equal(expVal.GetFqn(), actVal.GetFqn(), "obligation value FQN mismatch for value ID %s", actVal.GetId())

			expTriggersMap := make(map[string]*policy.ObligationTrigger)
			for _, trig := range expVal.GetTriggers() {
				expTriggersMap[trig.GetId()] = trig
			}

			for _, actTrig := range actVal.GetTriggers() {
				expTrig, found := expTriggersMap[actTrig.GetId()]
				s.Require().True(found, "unexpected trigger with ID %s for obligation value ID %s", actTrig.GetId(), actVal.GetId())
				s.Require().Equal(expTrig.GetAction().GetId(), actTrig.GetAction().GetId(), "trigger action ID mismatch for action ID %s", actTrig.GetAction().GetId())
				s.Require().Len(actTrig.GetContext(), len(expTrig.GetContext()), "number of trigger context entries does not match for actual trigger %s", actTrig.GetId())
				if len(actTrig.GetContext()) >= 1 {
					expContextMap := make(map[string]*policy.RequestContext)
					for _, ctx := range expTrig.GetContext() {
						expContextMap[ctx.GetPep().GetClientId()] = ctx
					}

					for _, ctx := range actTrig.GetContext() {
						s.Require().Equal(expContextMap[ctx.GetPep().GetClientId()], ctx, "trigger context mismatch for actual trigger %s", actTrig.GetId())
					}
				}
				s.Require().Equal(expTrig.GetAttributeValue().GetId(), actTrig.GetAttributeValue().GetId(), "trigger attribute value ID mismatch for actual trigger %s", actTrig.GetId())
			}
		}
	}
}
