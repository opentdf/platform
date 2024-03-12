package integration

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/internal/fixtures"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	policydb "github.com/opentdf/platform/services/policy/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type AttributesSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context
}

var (
	fixtureNamespaceId       string
	nonExistentAttrId        = "00000000-6789-4321-9876-123456765436"
	fixtureKeyAccessServerId string
)

func (s *AttributesSuite) SetupSuite() {
	slog.Info("setting up db.Attributes test suite")
	s.ctx = context.Background()
	fixtureNamespaceId = s.f.GetNamespaceKey("example.com").Id
	fixtureKeyAccessServerId = s.f.GetKasRegistryKey("key_access_server_1").Id
	c := *Config
	c.DB.Schema = "test_opentdf_attribute_definitions"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
	stillActiveNsId, deactivatedAttrId, deactivatedAttrValueId = setupCascadeDeactivateAttribute(s)
}

func (s *AttributesSuite) TearDownSuite() {
	slog.Info("tearing down db.Attributes test suite")
	s.f.TearDown()
}

func (s *AttributesSuite) getAttributeFixtures() []fixtures.FixtureDataAttribute {
	return []fixtures.FixtureDataAttribute{
		s.f.GetAttributeKey("example.com/attr/attr1"),
		s.f.GetAttributeKey("example.com/attr/attr2"),
		s.f.GetAttributeKey("example.net/attr/attr1"),
		s.f.GetAttributeKey("example.net/attr/attr2"),
		s.f.GetAttributeKey("example.net/attr/attr3"),
		s.f.GetAttributeKey("example.org/attr/attr1"),
		s.f.GetAttributeKey("example.org/attr/attr2"),
		s.f.GetAttributeKey("example.org/attr/attr3"),
	}
}

func (s *AttributesSuite) Test_CreateAttribute_NoMetadataSucceeds() {
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_no_metadata",
		NamespaceId: fixtureNamespaceId,
		Rule:        attributes.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdAttr)
}

func (s *AttributesSuite) Test_CreateAttribute_WithMetadataSucceeds() {
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_metadata",
		NamespaceId: fixtureNamespaceId,
		Rule:        attributes.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"origin": "Some info about origin",
			},
		},
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdAttr)
}

func (s *AttributesSuite) Test_CreateAttribute_SetsActiveStateTrueByDefault() {
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_active_state_default",
		NamespaceId: fixtureNamespaceId,
		Rule:        attributes.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdAttr)
	assert.Equal(s.T(), true, createdAttr.Active.Value)
}

func (s *AttributesSuite) Test_CreateAttribute_WithInvalidNamespaceFails() {
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_invalid_namespace",
		NamespaceId: nonExistentNamespaceId,
		Rule:        attributes.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrForeignKeyViolation)
	assert.Nil(s.T(), createdAttr)
}

func (s *AttributesSuite) Test_CreateAttribute_WithNonUniqueNameConflictFails() {
	attr := &attributes.CreateAttributeRequest{
		Name:        s.f.GetAttributeKey("example.com/attr/attr1").Name,
		NamespaceId: fixtureNamespaceId,
		Rule:        attributes.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrUniqueConstraintViolation)
	assert.Nil(s.T(), createdAttr)
}

func (s *AttributesSuite) Test_CreateAttribute_WithEveryRuleSucceeds() {
	otherNamespaceId := s.f.GetNamespaceKey("example.net").Id
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_any_of_rule_value",
		NamespaceId: otherNamespaceId,
		Rule:        attributes.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdAttr)

	attr = &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_all_of_rule_value",
		NamespaceId: otherNamespaceId,
		Rule:        attributes.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err = s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdAttr)

	attr = &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_unspecified_rule_value",
		NamespaceId: otherNamespaceId,
		Rule:        attributes.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
	}
	createdAttr, err = s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdAttr)

	attr = &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_hierarchy_rule_value",
		NamespaceId: otherNamespaceId,
		Rule:        attributes.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
	}
	createdAttr, err = s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdAttr)
}

func (s *AttributesSuite) Test_CreateAttribute_WithInvalidRuleFails() {
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_invalid_rule",
		NamespaceId: fixtureNamespaceId,
		// fake an enum value index far beyond reason
		Rule: attributes.AttributeRuleTypeEnum(100),
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrEnumValueInvalid)
	assert.Nil(s.T(), createdAttr)
}

func (s *AttributesSuite) Test_GetAttribute() {
	fixtures := s.getAttributeFixtures()

	for _, f := range fixtures {
		gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, f.Id)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), gotAttr)
		assert.Equal(s.T(), f.Id, gotAttr.Id)
		assert.Equal(s.T(), f.Name, gotAttr.Name)
		assert.Equal(s.T(), fmt.Sprintf("%s%s", policydb.AttributeRuleTypeEnumPrefix, f.Rule), gotAttr.Rule.Enum().String())
		assert.Equal(s.T(), f.NamespaceId, gotAttr.Namespace.Id)
	}
}

func (s *AttributesSuite) Test_GetAttribute_WithInvalidIdFails() {
	// this uuid does not exist
	gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, nonExistentAttrId)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), gotAttr)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *AttributesSuite) Test_GetAttribute_Deactivated_Succeeds() {
	deactivated := s.f.GetAttributeKey("deactivated.io/attr/attr1")
	gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, deactivated.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotAttr)
	assert.Equal(s.T(), deactivated.Id, gotAttr.Id)
	assert.Equal(s.T(), deactivated.Name, gotAttr.Name)
	assert.Equal(s.T(), false, gotAttr.Active.Value)
}

func (s *AttributesSuite) Test_ListAttribute() {
	fixtures := s.getAttributeFixtures()

	list, err := s.db.PolicyClient.ListAllAttributes(s.ctx, policydb.StateActive)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), list)

	// all fixtures are listed
	for _, f := range fixtures {
		var found bool
		for _, l := range list {
			if f.Id == l.Id {
				found = true
				break
			}
		}
		assert.True(s.T(), found)
	}
}

func (s *AttributesSuite) Test_UpdateAttribute() {
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

	attr := &attributes.CreateAttributeRequest{
		Name:        "test__update_attribute",
		NamespaceId: fixtureNamespaceId,
		Rule:        attributes.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
		Metadata: &common.MetadataMutable{
			Labels: labels,
		},
	}
	created, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), created)

	// update with no changes
	updatedWithoutChange, err := s.db.PolicyClient.UpdateAttribute(s.ctx, created.Id, &attributes.UpdateAttributeRequest{})
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updatedWithoutChange)
	assert.Equal(s.T(), created.Id, updatedWithoutChange.Id)

	// update with metadata
	updatedWithChange, err := s.db.PolicyClient.UpdateAttribute(s.ctx, created.Id, &attributes.UpdateAttributeRequest{
		Metadata: &common.MetadataMutable{
			Labels: updateLabels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updatedWithChange)
	assert.Equal(s.T(), created.Id, updatedWithChange.Id)

	got, err := s.db.PolicyClient.GetAttribute(s.ctx, created.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), created.Id, got.Id)
	assert.EqualValues(s.T(), expectedLabels, got.Metadata.GetLabels())
}

func (s *AttributesSuite) Test_UpdateAttribute_WithInvalidIdFails() {
	update := &attributes.UpdateAttributeRequest{
		// Metadata is required otherwise there will be no database request
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"origin": "Some info about origin",
			},
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE,
	}
	resp, err := s.db.PolicyClient.UpdateAttribute(s.ctx, nonExistentAttrId, update)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), resp)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *AttributesSuite) Test_UpdateAttribute_NamespaceIsImmutableOnUpdate() {
	s.T().Skip("Defunct test: not possible to test update in this way; check request struct for validation instead.")
	original := &attributes.CreateAttributeRequest{
		Name:        "test__update_attribute_namespace_immutable",
		NamespaceId: s.f.GetNamespaceKey("example.com").Id,
		Rule:        attributes.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, original)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdAttr)

	// should error on attempt to change namespace
	update := &attributes.UpdateAttributeRequest{}
	resp, err := s.db.PolicyClient.UpdateAttribute(s.ctx, createdAttr.Id, update)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), resp)
	assert.ErrorIs(s.T(), err, db.ErrRestrictViolation)

	// validate namespace should not have been changed
	updated, err := s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updated)
	assert.Equal(s.T(), original.NamespaceId, updated.Namespace.Id)
}

func (s *AttributesSuite) Test_UpdateAttributeWithSameNameAndNamespaceConflictFails() {
	s.T().Skip("Defunct test: not possible to test update in this way; check request struct for validation instead.")
	fixtureData := s.f.GetAttributeKey("example.org/attr/attr3")
	original := &attributes.CreateAttributeRequest{
		Name:        "test__update_attribute_with_same_name_and_namespace",
		NamespaceId: fixtureData.NamespaceId,
		Rule:        attributes.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, original)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdAttr)

	conflict := &attributes.UpdateAttributeRequest{}
	resp, err := s.db.PolicyClient.UpdateAttribute(s.ctx, fixtureData.Id, conflict)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), resp)
	assert.ErrorIs(s.T(), err, db.ErrUniqueConstraintViolation)
}

func (s *AttributesSuite) Test_DeleteAttribute() {
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__delete_attribute",
		NamespaceId: fixtureNamespaceId,
		Rule:        attributes.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdAttr)

	deleted, err := s.db.PolicyClient.DeleteAttribute(s.ctx, createdAttr.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), deleted)

	// should not exist anymore
	resp, err := s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.Id)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), resp)
}

func (s *AttributesSuite) Test_DeleteAttribute_WithInvalidIdFails() {
	deleted, err := s.db.PolicyClient.DeleteAttribute(s.ctx, nonExistentAttrId)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), deleted)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *AttributesSuite) Test_DeactivateAttribute_WithInvalidIdFails() {
	deactivated, err := s.db.PolicyClient.DeactivateAttribute(s.ctx, nonExistentAttrId)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), deactivated)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

// reusable setup for creating a namespace -> attr -> value and then deactivating the attribute (cascades to value)
func setupCascadeDeactivateAttribute(s *AttributesSuite) (string, string, string) {
	// create a namespace
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test__cascading-deactivate-ns",
	})
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), n.Id)

	// add an attribute under that namespaces
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__cascading-deactivate-attr",
		NamespaceId: n.Id,
		Rule:        attributes.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdAttr)

	// add a value under that attribute
	val := &attributes.CreateAttributeValueRequest{
		Value: "test__cascading-deactivate-attr-value",
	}
	createdVal, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, createdAttr.Id, val)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdVal)

	// deactivate the attribute
	deactivatedAttr, err := s.db.PolicyClient.DeactivateAttribute(s.ctx, createdAttr.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), deactivatedAttr)

	return n.Id, createdAttr.Id, createdVal.Id
}

func (s *AttributesSuite) Test_DeactivateAttribute_Cascades_List() {
	type test struct {
		name     string
		testFunc func(state string) bool
		state    string
		isFound  bool
	}

	listNamespaces := func(state string) bool {
		listedNamespaces, err := s.db.PolicyClient.ListNamespaces(s.ctx, state)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), listedNamespaces)
		for _, ns := range listedNamespaces {
			if stillActiveNsId == ns.Id {
				return true
			}
		}
		return false
	}

	listAttributes := func(state string) bool {
		listedAttrs, err := s.db.PolicyClient.ListAllAttributes(s.ctx, state)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), listedAttrs)
		for _, a := range listedAttrs {
			if deactivatedAttrId == a.Id {
				return true
			}
		}
		return false
	}

	listValues := func(state string) bool {
		listedVals, err := s.db.PolicyClient.ListAttributeValues(s.ctx, deactivatedAttrId, state)
		assert.Nil(s.T(), err)
		assert.NotNil(s.T(), listedVals)
		for _, v := range listedVals {
			if deactivatedAttrValueId == v.Id {
				return true
			}
		}
		return false
	}

	tests := []test{
		{
			name:     "namespace is NOT found in LIST of INACTIVE",
			testFunc: listNamespaces,
			state:    policydb.StateInactive,
			isFound:  false,
		},
		{
			name:     "namespace is found when filtering for ACTIVE state",
			testFunc: listNamespaces,
			state:    policydb.StateActive,
			isFound:  true,
		},
		{
			name:     "namespace is found when filtering for ANY state",
			testFunc: listNamespaces,
			state:    policydb.StateAny,
			isFound:  true,
		},
		{
			name:     "attribute is found when filtering for INACTIVE state",
			testFunc: listAttributes,
			state:    policydb.StateInactive,
			isFound:  true,
		},
		{
			name:     "attribute is found when filtering for ANY state",
			testFunc: listAttributes,
			state:    policydb.StateAny,
			isFound:  true,
		},
		{
			name:     "attribute is NOT found when filtering for ACTIVE state",
			testFunc: listAttributes,
			state:    policydb.StateActive,
			isFound:  false,
		},
		{
			name:     "value is NOT found in LIST of ACTIVE",
			testFunc: listValues,
			state:    policydb.StateActive,
			isFound:  false,
		},
		{
			name:     "value is found when filtering for INACTIVE state",
			testFunc: listValues,
			state:    policydb.StateInactive,
			isFound:  true,
		},
		{
			name:     "value is found when filtering for ANY state",
			testFunc: listValues,
			state:    policydb.StateAny,
			isFound:  true,
		},
	}

	for _, tableTest := range tests {
		s.T().Run(tableTest.name, func(t *testing.T) {
			found := tableTest.testFunc(tableTest.state)
			assert.Equal(t, tableTest.isFound, found)
		})
	}
}

func (s *AttributesSuite) Test_DeactivateAttribute_Cascades_ToValues_Get() {
	// ensure the namespace has state active still (not bubbled up)
	gotNs, err := s.db.PolicyClient.GetNamespace(s.ctx, stillActiveNsId)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotNs)
	assert.Equal(s.T(), true, gotNs.Active.Value)

	// ensure the attribute has state inactive
	gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, deactivatedAttrId)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotAttr)
	assert.Equal(s.T(), false, gotAttr.Active.Value)

	// ensure the value has state inactive
	gotVal, err := s.db.PolicyClient.GetAttributeValue(s.ctx, deactivatedAttrValueId)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotVal)
	assert.Equal(s.T(), false, gotVal.Active.Value)
}

func (s *AttributesSuite) Test_AssignKeyAccessServerToAttribute_Returns_Error_When_Attribute_Not_Found() {
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       nonExistentAttrId,
		KeyAccessServerId: fixtureKeyAccessServerId,
	}
	resp, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, aKas)

	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), resp)
	assert.ErrorIs(s.T(), err, db.ErrForeignKeyViolation)
}

func (s *AttributesSuite) Test_AssignKeyAccessServerToAttribute_Returns_Error_When_KeyAccessServer_Not_Found() {
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       s.f.GetAttributeKey("example.com/attr/attr1").Id,
		KeyAccessServerId: nonExistentAttrId,
	}
	resp, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, aKas)

	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), resp)
	assert.ErrorIs(s.T(), err, db.ErrForeignKeyViolation)
}

func (s *AttributesSuite) Test_AssignKeyAccessServerToAttribute_Returns_Success_When_Attribute_And_KeyAccessServer_Exist() {
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       s.f.GetAttributeKey("example.com/attr/attr2").Id,
		KeyAccessServerId: fixtureKeyAccessServerId,
	}
	resp, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, aKas)

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), resp)
	assert.Equal(s.T(), aKas, resp)
}

func (s *AttributesSuite) Test_RemoveKeyAccessServerFromAttribute_Returns_Error_When_Attribute_Not_Found() {
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       nonExistentAttrId,
		KeyAccessServerId: fixtureKeyAccessServerId,
	}
	resp, err := s.db.PolicyClient.RemoveKeyAccessServerFromAttribute(s.ctx, aKas)

	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), resp)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *AttributesSuite) Test_RemoveKeyAccessServerFromAttribute_Returns_Error_When_KeyAccessServer_Not_Found() {
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       s.f.GetAttributeKey("example.com/attr/attr1").Id,
		KeyAccessServerId: nonExistentAttrId,
	}
	resp, err := s.db.PolicyClient.RemoveKeyAccessServerFromAttribute(s.ctx, aKas)

	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), resp)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *AttributesSuite) Test_RemoveKeyAccessServerFromAttribute_Returns_Success_When_Attribute_And_KeyAccessServer_Exist() {
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       s.f.GetAttributeKey("example.com/attr/attr1").Id,
		KeyAccessServerId: s.f.GetKasRegistryKey("key_access_server_1").Id,
	}
	resp, err := s.db.PolicyClient.RemoveKeyAccessServerFromAttribute(s.ctx, aKas)

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), resp)
	assert.Equal(s.T(), aKas, resp)
}

func TestAttributesSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping attributes integration tests")
	}
	suite.Run(t, new(AttributesSuite))
}
