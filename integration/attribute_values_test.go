package integration

import (
	"context"
	"log/slog"
	"sort"
	"testing"

	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/internal/fixtures"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	policydb "github.com/opentdf/platform/services/policy/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

var nonExistentAttributeValueUuid = "78909865-8888-9999-9999-000000000000"

type AttributeValuesSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context
}

func (s *AttributeValuesSuite) SetupSuite() {
	slog.Info("setting up db.AttributeValues test suite")
	s.ctx = context.Background()
	fixtureKeyAccessServerId = s.f.GetKasRegistryKey("key_access_server_1").Id
	c := *Config
	c.DB.Schema = "test_opentdf_attribute_values"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
	stillActiveNsId, stillActiveAttributeId, deactivatedAttrValueId = setupDeactivateAttributeValue(s)
}

func (s *AttributeValuesSuite) TearDownSuite() {
	slog.Info("tearing down db.AttributeValues test suite")
	s.f.TearDown()
}

func (s *AttributeValuesSuite) Test_ListAttributeValues() {
	attrId := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1").AttributeDefinitionId

	list, err := s.db.PolicyClient.ListAttributeValues(s.ctx, attrId, policydb.StateActive)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), list)

	// ensure list contains the two test fixtures and that response matches expected data
	f1 := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	f2 := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value2")

	for _, item := range list {
		if item.Id == f1.Id {
			assert.Equal(s.T(), f1.Id, item.Id)
			assert.Equal(s.T(), f1.Value, item.Value)
			assert.Equal(s.T(), len(f1.Members), len(item.Members))
			// assert.Equal(s.T(), f1.AttributeDefinitionId, item.AttributeId)
		} else if item.Id == f2.Id {
			assert.Equal(s.T(), f2.Id, item.Id)
			assert.Equal(s.T(), f2.Value, item.Value)
			assert.Equal(s.T(), len(f2.Members), len(item.Members))
			// assert.Equal(s.T(), f2.AttributeDefinitionId, item.AttributeId)
		}
	}
}

func (s *AttributeValuesSuite) Test_GetAttributeValue() {
	f := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	v, err := s.db.PolicyClient.GetAttributeValue(s.ctx, f.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), v)

	assert.Equal(s.T(), f.Id, v.Id)
	assert.Equal(s.T(), f.Value, v.Value)
	assert.Equal(s.T(), len(f.Members), len(v.Members))
	// assert.Equal(s.T(), f.AttributeDefinitionId, v.AttributeId)
	assert.Equal(s.T(), "https://example.com/attr/attr1/value/value1", v.Fqn)
}

func (s *AttributeValuesSuite) Test_GetAttributeValue_NotFound() {
	attr, err := s.db.PolicyClient.GetAttributeValue(s.ctx, nonExistentAttributeValueUuid)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), attr)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *AttributeValuesSuite) Test_CreateAttributeValue_SetsActiveStateTrueByDefault() {
	attrDef := s.f.GetAttributeKey("example.net/attr/attr1")

	req := &attributes.CreateAttributeValueRequest{
		Value: "testing create gives active true by default",
	}
	createdValue, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attrDef.Id, req)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdValue)
	assert.Equal(s.T(), true, createdValue.Active.Value)
}

func (s *AttributeValuesSuite) Test_GetAttributeValue_Deactivated_Succeeds() {
	inactive := s.f.GetAttributeValueKey("deactivated.io/attr/attr1/value/deactivated_value")

	got, err := s.db.PolicyClient.GetAttributeValue(s.ctx, inactive.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), inactive.Id, got.Id)
	assert.Equal(s.T(), inactive.Value, got.Value)
	assert.Equal(s.T(), len(inactive.Members), len(got.Members))
	assert.Equal(s.T(), false, got.Active.Value)
}

func (s *AttributeValuesSuite) Test_CreateAttributeValue_NoMembers_Succeeds() {
	attrDef := s.f.GetAttributeKey("example.net/attr/attr1")
	metadata := &common.MetadataMutable{
		Labels: map[string]string{
			"name": "this is the test name of my attribute value",
		},
	}

	value := &attributes.CreateAttributeValueRequest{
		Value:    "value create with members test value",
		Metadata: metadata,
	}
	createdValue, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attrDef.Id, value)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdValue)

	got, err := s.db.PolicyClient.GetAttributeValue(s.ctx, createdValue.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), createdValue.Id, got.Id)
	assert.Equal(s.T(), createdValue.Value, got.Value)
	assert.Equal(s.T(), len(createdValue.Members), len(got.Members))
	assert.EqualValues(s.T(), createdValue.Metadata.Labels, got.Metadata.Labels)
}
func equalMembers(t *testing.T, v1 *policy.Value, v2 *policy.Value, withFqn bool) {
	m1 := v1.Members
	m2 := v2.Members
	sort.Slice(m1, func(x, y int) bool {
		return m1[x].Id < m1[y].Id
	})
	sort.Slice(m2, func(x, y int) bool {
		return m2[x].Id < m2[y].Id
	})
	for idx := range m1 {
		assert.Equal(t, m1[idx].Id, m2[idx].Id)
		assert.Equal(t, m1[idx].Value, m2[idx].Value)
		if withFqn {
			assert.Equal(t, m1[idx].Fqn, m2[idx].Fqn)
		}
		assert.Equal(t, m1[idx].Active.Value, m2[idx].Active.Value)
	}
}
func (s *AttributeValuesSuite) Test_CreateAttributeValue_WithMembers_Succeeds() {
	attrDef := s.f.GetAttributeKey("example.net/attr/attr1")
	metadata := &common.MetadataMutable{
		Labels: map[string]string{
			"name": "testing create with members",
		},
	}

	value := &attributes.CreateAttributeValueRequest{
		Value: "value3",
		Members: []string{
			s.f.GetAttributeValueKey("example.net/attr/attr1/value/value1").Id,
			s.f.GetAttributeValueKey("example.net/attr/attr1/value/value2").Id,
		},
		Metadata: metadata,
	}
	createdValue, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attrDef.Id, value)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdValue)

	got, err := s.db.PolicyClient.GetAttributeValue(s.ctx, createdValue.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), createdValue.Id, got.Id)
	assert.Equal(s.T(), createdValue.Value, got.Value)
	assert.EqualValues(s.T(), createdValue.Metadata.Labels, got.Metadata.Labels)
	assert.Equal(s.T(), len(createdValue.Members), len(got.Members))

	assert.True(s.T(), len(got.Members) > 0)
	equalMembers(s.T(), createdValue, got, true)

	// members must exist
	createdValue, err = s.db.PolicyClient.CreateAttributeValue(s.ctx, attrDef.Id, &attributes.CreateAttributeValueRequest{
		Value: "value4",
		Members: []string{
			nonExistentAttributeValueUuid,
		},
	},
	)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), createdValue)
	assert.ErrorIs(s.T(), err, db.ErrForeignKeyViolation)
}

func (s *AttributeValuesSuite) Test_CreateAttributeValue_WithInvalidAttributeId_Fails() {
	value := &attributes.CreateAttributeValueRequest{
		Value: "some value",
	}
	createdValue, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, nonExistentAttrId, value)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), createdValue)
	assert.ErrorIs(s.T(), err, db.ErrForeignKeyViolation)
}

func (s *AttributeValuesSuite) Test_CreateAttributeValue_WithInvalidMember_Fails() {
	attrDef := s.f.GetAttributeKey("example.net/attr/attr2")
	metadata := &common.MetadataMutable{
		Labels: map[string]string{
			"name": "testing create with members",
		},
	}

	value := &attributes.CreateAttributeValueRequest{
		Value: "value3",
		Members: []string{
			nonExistentAttributeValueUuid,
		},
		Metadata: metadata,
	}
	createdValue, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attrDef.Id, value)
	assert.Nil(s.T(), createdValue)
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrForeignKeyViolation)

	attrDef = s.f.GetAttributeKey("example.net/attr/attr3")
	value.Members[0] = "not a uuid"
	createdValue, err = s.db.PolicyClient.CreateAttributeValue(s.ctx, attrDef.Id, value)
	assert.Nil(s.T(), createdValue)
	assert.NotNil(s.T(), err)
	assert.ErrorIs(s.T(), err, db.ErrUuidInvalid)
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
	created, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attrDef.Id, &attributes.CreateAttributeValueRequest{
		Value: "created value testing update",
		Metadata: &common.MetadataMutable{
			Labels: labels,
		},
	})
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), created)

	// update with no changes
	updatedWithoutChange, err := s.db.PolicyClient.UpdateAttributeValue(s.ctx, &attributes.UpdateAttributeValueRequest{
		Id: created.Id,
	})
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updatedWithoutChange)
	assert.Equal(s.T(), created.Id, updatedWithoutChange.Id)

	// update with changes
	updatedWithChange, err := s.db.PolicyClient.UpdateAttributeValue(s.ctx, &attributes.UpdateAttributeValueRequest{
		Metadata: &common.MetadataMutable{
			Labels: updateLabels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
		Id:                     created.Id,
	})
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updatedWithChange)
	assert.Equal(s.T(), created.Id, updatedWithChange.Id)

	// get it again to verify it was updated
	got, err := s.db.PolicyClient.GetAttributeValue(s.ctx, created.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), created.Id, got.Id)
	assert.EqualValues(s.T(), expectedLabels, got.Metadata.GetLabels())
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
		Id:                     nonExistentAttributeValueUuid,
	})
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), updated)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *AttributeValuesSuite) Test_DeleteAttribute() {
	// create a value
	value := &attributes.CreateAttributeValueRequest{
		Value: "created value testing delete",
	}
	created, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, s.f.GetAttributeKey("example.net/attr/attr1").Id, value)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), created)

	// delete it
	resp, err := s.db.PolicyClient.DeleteAttributeValue(s.ctx, created.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), resp)

	// get it again to verify it no longer exists
	got, err := s.db.PolicyClient.GetAttributeValue(s.ctx, created.Id)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), got)
}

func (s *AttributeValuesSuite) Test_DeleteAttribute_NotFound() {
	resp, err := s.db.PolicyClient.DeleteAttributeValue(s.ctx, nonExistentAttributeValueUuid)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), resp)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *AttributeValuesSuite) Test_DeactivateAttributeValue_WithInvalidIdFails() {
	deactivated, err := s.db.PolicyClient.DeactivateAttributeValue(s.ctx, nonExistentAttributeValueUuid)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), deactivated)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

// reusable setup for creating a namespace -> attr -> value and then deactivating the attribute (cascades to value)
func setupDeactivateAttributeValue(s *AttributeValuesSuite) (string, string, string) {
	// create a namespace
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "cascading-deactivate-attribute-value.com",
	})
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), n.Id)

	// add an attribute under that namespaces
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__cascading-deactivate-attr-value",
		NamespaceId: n.Id,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdAttr)

	// add a value under that attribute
	val := &attributes.CreateAttributeValueRequest{
		Value: "test__cascading-deactivate-attr-value-value",
	}
	createdVal, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, createdAttr.Id, val)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdVal)

	// deactivate the attribute value
	deactivatedAttr, err := s.db.PolicyClient.DeactivateAttributeValue(s.ctx, createdVal.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), deactivatedAttr)

	return n.Id, createdAttr.Id, createdVal.Id
}

// Verify behavior that DB does not bubble up deactivation of value to attributes and namespaces
func (s *AttributeValuesSuite) Test_DeactivateAttribute_Cascades_List() {
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
			if stillActiveAttributeId == a.Id {
				return true
			}
		}
		return false
	}

	listValues := func(state string) bool {
		listedVals, err := s.db.PolicyClient.ListAttributeValues(s.ctx, stillActiveAttributeId, state)
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
			name:     "attribute is NOT found when filtering for INACTIVE state",
			testFunc: listAttributes,
			state:    policydb.StateInactive,
			isFound:  false,
		},
		{
			name:     "attribute is found when filtering for ANY state",
			testFunc: listAttributes,
			state:    policydb.StateAny,
			isFound:  true,
		},
		{
			name:     "attribute is found when filtering for ACTIVE state",
			testFunc: listAttributes,
			state:    policydb.StateActive,
			isFound:  true,
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

func (s *AttributeValuesSuite) Test_DeactivateAttributeValue_Get() {
	// namespace is still active (not bubbled up)
	gotNs, err := s.db.PolicyClient.GetNamespace(s.ctx, stillActiveNsId)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotNs)
	assert.Equal(s.T(), true, gotNs.Active.Value)

	// attribute is still active (not bubbled up)
	gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, stillActiveAttributeId)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotAttr)
	assert.Equal(s.T(), true, gotAttr.Active.Value)

	// value was deactivated
	gotVal, err := s.db.PolicyClient.GetAttributeValue(s.ctx, deactivatedAttrValueId)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotVal)
	assert.Equal(s.T(), false, gotVal.Active.Value)
}

func (s *AttributeValuesSuite) Test_AssignKeyAccessServerToValue_Returns_Error_When_Value_Not_Found() {
	v := &attributes.ValueKeyAccessServer{
		ValueId:           nonExistentAttributeValueUuid,
		KeyAccessServerId: fixtureKeyAccessServerId,
	}

	resp, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, v)

	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), resp)
	assert.ErrorIs(s.T(), err, db.ErrForeignKeyViolation)
}

func (s *AttributeValuesSuite) Test_AssignKeyAccessServerToValue_Returns_Error_When_KeyAccessServer_Not_Found() {
	v := &attributes.ValueKeyAccessServer{
		ValueId:           s.f.GetAttributeValueKey("example.net/attr/attr1/value/value1").Id,
		KeyAccessServerId: nonExistentKasRegistryId,
	}

	resp, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, v)

	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), resp)
	assert.ErrorIs(s.T(), err, db.ErrForeignKeyViolation)
}

func (s *AttributeValuesSuite) Test_AssignKeyAccessServerToValue_Returns_Success_When_Value_And_KeyAccessServer_Exist() {
	v := &attributes.ValueKeyAccessServer{
		ValueId:           s.f.GetAttributeValueKey("example.net/attr/attr1/value/value1").Id,
		KeyAccessServerId: fixtureKeyAccessServerId,
	}

	resp, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, v)

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), resp)
	assert.Equal(s.T(), v, resp)
}

func (s *AttributeValuesSuite) Test_RemoveKeyAccessServerFromValue_Returns_Error_When_Value_Not_Found() {
	v := &attributes.ValueKeyAccessServer{
		ValueId:           nonExistentAttributeValueUuid,
		KeyAccessServerId: fixtureKeyAccessServerId,
	}

	resp, err := s.db.PolicyClient.RemoveKeyAccessServerFromValue(s.ctx, v)

	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), resp)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *AttributeValuesSuite) Test_RemoveKeyAccessServerFromValue_Returns_Error_When_KeyAccessServer_Not_Found() {
	v := &attributes.ValueKeyAccessServer{
		ValueId:           s.f.GetAttributeValueKey("example.net/attr/attr1/value/value1").Id,
		KeyAccessServerId: nonExistentAttrId,
	}

	resp, err := s.db.PolicyClient.RemoveKeyAccessServerFromValue(s.ctx, v)

	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), resp)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *AttributeValuesSuite) Test_RemoveKeyAccessServerFromValue_Returns_Success_When_Value_And_KeyAccessServer_Exist() {
	v := &attributes.ValueKeyAccessServer{
		ValueId:           s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1").Id,
		KeyAccessServerId: s.f.GetKasRegistryKey("key_access_server_1").Id,
	}

	resp, err := s.db.PolicyClient.RemoveKeyAccessServerFromValue(s.ctx, v)

	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), resp)
	assert.Equal(s.T(), v, resp)
}

func TestAttributeValuesSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping attribute values integration tests")
	}
	suite.Run(t, new(AttributeValuesSuite))
}
