package integration

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/services/internal/db"
	"github.com/opentdf/platform/services/internal/fixtures"
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
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.NoError(err)
	s.NotNil(createdAttr)
}

func (s *AttributesSuite) Test_CreateAttribute_WithValueSucceeds() {
	values := []string{"value1", "value2", "value3"}
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_values",
		NamespaceId: fixtureNamespaceId,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values:      values,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	createdVals := []string{}
	for _, v := range createdAttr.GetValues() {
		createdVals = append(createdVals, v.GetValue())
	}
	s.Equal(values, createdVals)
	s.NoError(err)
	s.NotNil(createdAttr)
}

func (s *AttributesSuite) Test_CreateAttribute_WithMetadataSucceeds() {
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_metadata",
		NamespaceId: fixtureNamespaceId,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"origin": "Some info about origin",
			},
		},
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.NoError(err)
	s.NotNil(createdAttr)
}

func (s *AttributesSuite) Test_CreateAttribute_SetsActiveStateTrueByDefault() {
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_active_state_default",
		NamespaceId: fixtureNamespaceId,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.NoError(err)
	s.NotNil(createdAttr)
	s.Equal(true, createdAttr.GetActive().GetValue())
}

func (s *AttributesSuite) Test_CreateAttribute_WithInvalidNamespaceFails() {
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_invalid_namespace",
		NamespaceId: nonExistentNamespaceId,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.NotNil(err)
	s.ErrorIs(err, db.ErrForeignKeyViolation)
	s.Nil(createdAttr)
}

func (s *AttributesSuite) Test_CreateAttribute_WithNonUniqueNameConflictFails() {
	attr := &attributes.CreateAttributeRequest{
		Name:        s.f.GetAttributeKey("example.com/attr/attr1").Name,
		NamespaceId: fixtureNamespaceId,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.NotNil(err)
	s.ErrorIs(err, db.ErrUniqueConstraintViolation)
	s.Nil(createdAttr)
}

func (s *AttributesSuite) Test_CreateAttribute_WithEveryRuleSucceeds() {
	otherNamespaceId := s.f.GetNamespaceKey("example.net").Id
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_any_of_rule_value",
		NamespaceId: otherNamespaceId,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.NoError(err)
	s.NotNil(createdAttr)

	attr = &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_all_of_rule_value",
		NamespaceId: otherNamespaceId,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err = s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.NoError(err)
	s.NotNil(createdAttr)

	attr = &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_unspecified_rule_value",
		NamespaceId: otherNamespaceId,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
	}
	createdAttr, err = s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.NoError(err)
	s.NotNil(createdAttr)

	attr = &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_hierarchy_rule_value",
		NamespaceId: otherNamespaceId,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
	}
	createdAttr, err = s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.NoError(err)
	s.NotNil(createdAttr)
}

func (s *AttributesSuite) Test_CreateAttribute_WithInvalidRuleFails() {
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_invalid_rule",
		NamespaceId: fixtureNamespaceId,
		// fake an enum value index far beyond reason
		Rule: policy.AttributeRuleTypeEnum(100),
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.NotNil(err)
	s.ErrorIs(err, db.ErrEnumValueInvalid)
	s.Nil(createdAttr)
}

func (s *AttributesSuite) Test_UnsafeUpdateAttribute_ReplaceValuesOrder() {
	// TODO: write test when unsafe behaviors are implemented [https://github.com/opentdf/platform/issues/115]
	s.T().Skip("Unsafe service behaviors not yet implemented.")
}

func (s *AttributesSuite) Test_GetAttribute_OrderOfValuesIsPreserved() {
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__get_attribute_order_of_values",
		NamespaceId: fixtureNamespaceId,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
		Values:      []string{"FIRST", "SECOND", "THIRD"},
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdAttr)
	assert.Equal(s.T(), 3, len(createdAttr.GetValues()))
	assert.Equal(s.T(), policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, createdAttr.GetRule())

	// add a fourth value
	val := &attributes.CreateAttributeValueRequest{
		Value:       "FOURTH",
		AttributeId: createdAttr.Id,
	}

	createdVal, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, createdAttr.GetId(), val)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdVal)

	// get attribute and ensure the order of the values is preserved
	gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotAttr)
	assert.Equal(s.T(), 4, len(gotAttr.GetValues()))
	assert.Equal(s.T(), "FIRST", gotAttr.GetValues()[0].GetValue())
	assert.Equal(s.T(), "SECOND", gotAttr.GetValues()[1].GetValue())
	assert.Equal(s.T(), "THIRD", gotAttr.GetValues()[2].GetValue())
	assert.Equal(s.T(), "FOURTH", gotAttr.GetValues()[3].GetValue())
	assert.Equal(s.T(), policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, gotAttr.GetRule())

	// deactivate one of the values
	deactivatedVal, err := s.db.PolicyClient.DeactivateAttributeValue(s.ctx, gotAttr.Values[1].Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), deactivatedVal)

	// get attribute and ensure order stays consistent
	gotAttr, err = s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotAttr)
	assert.Equal(s.T(), 4, len(gotAttr.GetValues()))
	assert.Equal(s.T(), "FIRST", gotAttr.GetValues()[0].GetValue())
	assert.Equal(s.T(), "SECOND", gotAttr.GetValues()[1].GetValue())
	assert.Equal(s.T(), "THIRD", gotAttr.GetValues()[2].GetValue())
	assert.Equal(s.T(), "FOURTH", gotAttr.GetValues()[3].GetValue())
	assert.Equal(s.T(), policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, gotAttr.GetRule())

	// get attribute by value fqn and ensure the order of the values is preserved
	fqns := []string{fmt.Sprintf("https://%s/attr/%s/value/%s", gotAttr.GetNamespace().GetName(), createdAttr.GetName(), gotAttr.GetValues()[0].GetValue())}
	req := &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: fqns,
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	}
	resp, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, req)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), resp)
	assert.Equal(s.T(), 1, len(resp))
	gotVals := resp[fqns[0]].GetAttribute().GetValues()
	assert.Equal(s.T(), 4, len(gotVals))
	assert.Equal(s.T(), "FIRST", gotVals[0].GetValue())
	assert.Equal(s.T(), "SECOND", gotVals[1].GetValue())
	assert.Equal(s.T(), "THIRD", gotVals[2].GetValue())
	assert.Equal(s.T(), "FOURTH", gotVals[3].GetValue())
}

func (s *AttributesSuite) Test_GetAttribute() {
	fixtures := s.getAttributeFixtures()

	for _, f := range fixtures {
		gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, f.Id)
		s.NoError(err)
		s.NotNil(gotAttr)
		s.Equal(f.Id, gotAttr.GetId())
		s.Equal(f.Name, gotAttr.GetName())
		s.Equal(fmt.Sprintf("%s%s", policydb.AttributeRuleTypeEnumPrefix, f.Rule), gotAttr.GetRule().Enum().String())
		s.Equal(f.NamespaceId, gotAttr.GetNamespace().GetId())
	}
}

func (s *AttributesSuite) Test_GetAttribute_WithInvalidIdFails() {
	// this uuid does not exist
	gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, nonExistentAttrId)
	s.NotNil(err)
	s.Nil(gotAttr)
	s.ErrorIs(err, db.ErrNotFound)
}

func (s *AttributesSuite) Test_GetAttribute_Deactivated_Succeeds() {
	deactivated := s.f.GetAttributeKey("deactivated.io/attr/attr1")
	gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, deactivated.Id)
	s.NoError(err)
	s.NotNil(gotAttr)
	s.Equal(deactivated.Id, gotAttr.GetId())
	s.Equal(deactivated.Name, gotAttr.GetName())
	s.Equal(false, gotAttr.GetActive().GetValue())
}

func (s *AttributesSuite) Test_ListAttribute() {
	fixtures := s.getAttributeFixtures()

	list, err := s.db.PolicyClient.ListAllAttributes(s.ctx, policydb.StateActive, "")
	s.NoError(err)
	s.NotNil(list)

	// all fixtures are listed
	for _, f := range fixtures {
		var found bool
		for _, l := range list {
			if f.Id == l.GetId() {
				found = true
				break
			}
		}
		s.True(found)
	}
}

func (s *AttributesSuite) Test_ListAttributesByNamespace() {
	// get all unique namespace_ids
	namespaces := map[string]string{}
	for _, f := range s.getAttributeFixtures() {
		namespaces[f.NamespaceId] = ""
	}
	// list attributes by namespace id
	for nsId := range namespaces {
		list, err := s.db.PolicyClient.ListAllAttributes(s.ctx, policydb.StateAny, nsId)
		s.NoError(err)
		s.NotNil(list)
		s.NotEmpty(list)
		for _, l := range list {
			s.Equal(nsId, l.GetNamespace().GetId())
		}
		namespaces[nsId] = list[0].GetNamespace().GetName()
	}

	// list attributes by namespace name
	for _, nsName := range namespaces {
		list, err := s.db.PolicyClient.ListAllAttributes(s.ctx, policydb.StateAny, nsName)
		s.NoError(err)
		s.NotNil(list)
		s.NotEmpty(list)
		for _, l := range list {
			s.Equal(nsName, l.GetNamespace().GetName())
		}
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
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
		Metadata: &common.MetadataMutable{
			Labels: labels,
		},
	}
	created, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.NoError(err)
	s.NotNil(created)

	// update with no changes
	updatedWithoutChange, err := s.db.PolicyClient.UpdateAttribute(s.ctx, created.GetId(), &attributes.UpdateAttributeRequest{})
	s.NoError(err)
	s.NotNil(updatedWithoutChange)
	s.Equal(created.GetId(), updatedWithoutChange.GetId())

	// update with metadata
	updatedWithChange, err := s.db.PolicyClient.UpdateAttribute(s.ctx, created.GetId(), &attributes.UpdateAttributeRequest{
		Metadata: &common.MetadataMutable{
			Labels: updateLabels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	s.NoError(err)
	s.NotNil(updatedWithChange)
	s.Equal(created.GetId(), updatedWithChange.GetId())

	got, err := s.db.PolicyClient.GetAttribute(s.ctx, created.GetId())
	s.NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.EqualValues(expectedLabels, got.GetMetadata().GetLabels())
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
	s.NotNil(err)
	s.Nil(resp)
	s.ErrorIs(err, db.ErrNotFound)
}

func (s *AttributesSuite) Test_UpdateAttribute_NamespaceIsImmutableOnUpdate() {
	s.T().Skip("Defunct test: not possible to test update in this way; check request struct for validation instead.")
	original := &attributes.CreateAttributeRequest{
		Name:        "test__update_attribute_namespace_immutable",
		NamespaceId: s.f.GetNamespaceKey("example.com").Id,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, original)
	s.NoError(err)
	s.NotNil(createdAttr)

	// should error on attempt to change namespace
	update := &attributes.UpdateAttributeRequest{}
	resp, err := s.db.PolicyClient.UpdateAttribute(s.ctx, createdAttr.GetId(), update)
	s.NotNil(err)
	s.Nil(resp)
	s.ErrorIs(err, db.ErrRestrictViolation)

	// validate namespace should not have been changed
	updated, err := s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	s.NoError(err)
	s.NotNil(updated)
	s.Equal(original.GetNamespaceId(), updated.GetNamespace().GetId())
}

func (s *AttributesSuite) Test_UpdateAttributeWithSameNameAndNamespaceConflictFails() {
	s.T().Skip("Defunct test: not possible to test update in this way; check request struct for validation instead.")
	fixtureData := s.f.GetAttributeKey("example.org/attr/attr3")
	original := &attributes.CreateAttributeRequest{
		Name:        "test__update_attribute_with_same_name_and_namespace",
		NamespaceId: fixtureData.NamespaceId,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, original)
	s.NoError(err)
	s.NotNil(createdAttr)

	conflict := &attributes.UpdateAttributeRequest{}
	resp, err := s.db.PolicyClient.UpdateAttribute(s.ctx, fixtureData.Id, conflict)
	s.NotNil(err)
	s.Nil(resp)
	s.ErrorIs(err, db.ErrUniqueConstraintViolation)
}

func (s *AttributesSuite) Test_DeleteAttribute() {
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__delete_attribute",
		NamespaceId: fixtureNamespaceId,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.NoError(err)
	s.NotNil(createdAttr)

	deleted, err := s.db.PolicyClient.DeleteAttribute(s.ctx, createdAttr.GetId())
	s.NoError(err)
	s.NotNil(deleted)

	// should not exist anymore
	resp, err := s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	s.NotNil(err)
	s.Nil(resp)
}

func (s *AttributesSuite) Test_DeleteAttribute_WithInvalidIdFails() {
	deleted, err := s.db.PolicyClient.DeleteAttribute(s.ctx, nonExistentAttrId)
	s.NotNil(err)
	s.Nil(deleted)
	s.ErrorIs(err, db.ErrNotFound)
}

func (s *AttributesSuite) Test_DeactivateAttribute_WithInvalidIdFails() {
	deactivated, err := s.db.PolicyClient.DeactivateAttribute(s.ctx, nonExistentAttrId)
	s.NotNil(err)
	s.Nil(deactivated)
	s.ErrorIs(err, db.ErrNotFound)
}

// reusable setup for creating a namespace -> attr -> value and then deactivating the attribute (cascades to value)
func setupCascadeDeactivateAttribute(s *AttributesSuite) (string, string, string) {
	// create a namespace
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test__cascading-deactivate-ns",
	})
	s.NoError(err)
	s.NotZero(n.GetId())

	// add an attribute under that namespaces
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__cascading-deactivate-attr",
		NamespaceId: n.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.NoError(err)
	s.NotNil(createdAttr)

	// add a value under that attribute
	val := &attributes.CreateAttributeValueRequest{
		Value: "test__cascading-deactivate-attr-value",
	}
	createdVal, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, createdAttr.GetId(), val)
	s.NoError(err)
	s.NotNil(createdVal)

	// deactivate the attribute
	deactivatedAttr, err := s.db.PolicyClient.DeactivateAttribute(s.ctx, createdAttr.GetId())
	s.NoError(err)
	s.NotNil(deactivatedAttr)

	return n.GetId(), createdAttr.GetId(), createdVal.GetId()
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
		s.NoError(err)
		s.NotNil(listedNamespaces)
		for _, ns := range listedNamespaces {
			if stillActiveNsId == ns.GetId() {
				return true
			}
		}
		return false
	}

	listAttributes := func(state string) bool {
		listedAttrs, err := s.db.PolicyClient.ListAllAttributes(s.ctx, state, "")
		s.NoError(err)
		s.NotNil(listedAttrs)
		for _, a := range listedAttrs {
			if deactivatedAttrId == a.GetId() {
				return true
			}
		}
		return false
	}

	listValues := func(state string) bool {
		listedVals, err := s.db.PolicyClient.ListAttributeValues(s.ctx, deactivatedAttrId, state)
		s.NoError(err)
		s.NotNil(listedVals)
		for _, v := range listedVals {
			if deactivatedAttrValueId == v.GetId() {
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
	s.NoError(err)
	s.NotNil(gotNs)
	s.Equal(true, gotNs.GetActive().GetValue())

	// ensure the attribute has state inactive
	gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, deactivatedAttrId)
	s.NoError(err)
	s.NotNil(gotAttr)
	s.Equal(false, gotAttr.GetActive().GetValue())

	// ensure the value has state inactive
	gotVal, err := s.db.PolicyClient.GetAttributeValue(s.ctx, deactivatedAttrValueId)
	s.NoError(err)
	s.NotNil(gotVal)
	s.Equal(false, gotVal.GetActive().GetValue())
}

func (s *AttributesSuite) Test_AssignKeyAccessServerToAttribute_Returns_Error_When_Attribute_Not_Found() {
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       nonExistentAttrId,
		KeyAccessServerId: fixtureKeyAccessServerId,
	}
	resp, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, aKas)

	s.NotNil(err)
	s.Nil(resp)
	s.ErrorIs(err, db.ErrForeignKeyViolation)
}

func (s *AttributesSuite) Test_AssignKeyAccessServerToAttribute_Returns_Error_When_KeyAccessServer_Not_Found() {
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       s.f.GetAttributeKey("example.com/attr/attr1").Id,
		KeyAccessServerId: nonExistentAttrId,
	}
	resp, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, aKas)

	s.NotNil(err)
	s.Nil(resp)
	s.ErrorIs(err, db.ErrForeignKeyViolation)
}

func (s *AttributesSuite) Test_AssignKeyAccessServerToAttribute_Returns_Success_When_Attribute_And_KeyAccessServer_Exist() {
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       s.f.GetAttributeKey("example.com/attr/attr2").Id,
		KeyAccessServerId: fixtureKeyAccessServerId,
	}
	resp, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, aKas)

	s.NoError(err)
	s.NotNil(resp)
	s.Equal(aKas, resp)
}

func (s *AttributesSuite) Test_RemoveKeyAccessServerFromAttribute_Returns_Error_When_Attribute_Not_Found() {
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       nonExistentAttrId,
		KeyAccessServerId: fixtureKeyAccessServerId,
	}
	resp, err := s.db.PolicyClient.RemoveKeyAccessServerFromAttribute(s.ctx, aKas)

	s.NotNil(err)
	s.Nil(resp)
	s.ErrorIs(err, db.ErrNotFound)
}

func (s *AttributesSuite) Test_RemoveKeyAccessServerFromAttribute_Returns_Error_When_KeyAccessServer_Not_Found() {
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       s.f.GetAttributeKey("example.com/attr/attr1").Id,
		KeyAccessServerId: nonExistentAttrId,
	}
	resp, err := s.db.PolicyClient.RemoveKeyAccessServerFromAttribute(s.ctx, aKas)

	s.NotNil(err)
	s.Nil(resp)
	s.ErrorIs(err, db.ErrNotFound)
}

func (s *AttributesSuite) Test_RemoveKeyAccessServerFromAttribute_Returns_Success_When_Attribute_And_KeyAccessServer_Exist() {
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       s.f.GetAttributeKey("example.com/attr/attr1").Id,
		KeyAccessServerId: s.f.GetKasRegistryKey("key_access_server_1").Id,
	}
	resp, err := s.db.PolicyClient.RemoveKeyAccessServerFromAttribute(s.ctx, aKas)

	s.NoError(err)
	s.NotNil(resp)
	s.Equal(aKas, resp)
}

func TestAttributesSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping attributes integration tests")
	}
	suite.Run(t, new(AttributesSuite))
}
