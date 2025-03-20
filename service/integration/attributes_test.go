package integration

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	policydb "github.com/opentdf/platform/service/policy/db"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/proto"
)

type AttributesSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context //nolint:containedctx // context is used in the test suite
}

var (
	fixtureNamespaceID       string
	nonExistentAttrID        = "00000000-6789-4321-9876-123456765436"
	fixtureKeyAccessServerID string
)

func (s *AttributesSuite) SetupSuite() {
	slog.Info("setting up db.Attributes test suite")
	s.ctx = context.Background()
	fixtureNamespaceID = s.f.GetNamespaceKey("example.com").ID
	fixtureKeyAccessServerID = s.f.GetKasRegistryKey("key_access_server_1").ID
	c := *Config
	c.DB.Schema = "test_opentdf_attribute_definitions"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
	stillActiveNsID, deactivatedAttrID, deactivatedAttrValueID = setupCascadeDeactivateAttribute(s)
}

func (s *AttributesSuite) TearDownSuite() {
	slog.Info("tearing down db.Attributes test suite")
	s.f.TearDown()
}

func (s *AttributesSuite) getAttributeFixtures() map[string]fixtures.FixtureDataAttribute {
	return map[string]fixtures.FixtureDataAttribute{
		"example.com/attr/attr1": s.f.GetAttributeKey("example.com/attr/attr1"),
		"example.com/attr/attr2": s.f.GetAttributeKey("example.com/attr/attr2"),
		"example.net/attr/attr1": s.f.GetAttributeKey("example.net/attr/attr1"),
		"example.net/attr/attr2": s.f.GetAttributeKey("example.net/attr/attr2"),
		"example.net/attr/attr3": s.f.GetAttributeKey("example.net/attr/attr3"),
		"example.org/attr/attr1": s.f.GetAttributeKey("example.org/attr/attr1"),
		"example.org/attr/attr2": s.f.GetAttributeKey("example.org/attr/attr2"),
		"example.org/attr/attr3": s.f.GetAttributeKey("example.org/attr/attr3"),
	}
}

func (s *AttributesSuite) Test_CreateAttribute_NoMetadataSucceeds() {
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_no_metadata",
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)
}

func (s *AttributesSuite) Test_CreateAttribute_NormalizeName() {
	name := "NaMe_12_ShOuLdBe-NoRmAlIzEd"
	attr := &attributes.CreateAttributeRequest{
		Name:        name,
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)
	s.Equal(strings.ToLower(name), createdAttr.GetName())

	got, err := s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(strings.ToLower(name), got.GetName(), createdAttr.GetName())
}

func (s *AttributesSuite) Test_CreateAttribute_WithValueSucceeds() {
	values := []string{"value1", "value2", "value3"}
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_values",
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values:      values,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	createdVals := []string{}
	for _, v := range createdAttr.GetValues() {
		createdVals = append(createdVals, v.GetValue())
	}
	s.Equal(values, createdVals)
	s.Require().NoError(err)
	s.NotNil(createdAttr)
}

func (s *AttributesSuite) Test_CreateAttribute_WithMetadataSucceeds() {
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_metadata",
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"origin": "Some info about origin",
			},
		},
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)
}

func (s *AttributesSuite) Test_CreateAttribute_SetsActiveStateTrueByDefault() {
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_active_state_default",
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)
	s.True(createdAttr.GetActive().GetValue())
}

func (s *AttributesSuite) Test_CreateAttribute_WithInvalidNamespaceFails() {
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_invalid_namespace",
		NamespaceId: nonExistentNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrForeignKeyViolation)
	s.Nil(createdAttr)
}

func (s *AttributesSuite) Test_CreateAttribute_WithNonUniqueNameConflictFails() {
	attr := &attributes.CreateAttributeRequest{
		Name:        s.f.GetAttributeKey("example.com/attr/attr1").Name,
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
	s.Nil(createdAttr)
}

func (s *AttributesSuite) Test_CreateAttribute_WithEveryRuleSucceeds() {
	otherNamespaceID := s.f.GetNamespaceKey("example.net").ID
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_any_of_rule_value",
		NamespaceId: otherNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)

	attr = &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_all_of_rule_value",
		NamespaceId: otherNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err = s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)

	attr = &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_unspecified_rule_value",
		NamespaceId: otherNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
	}
	createdAttr, err = s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)

	attr = &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_hierarchy_rule_value",
		NamespaceId: otherNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
	}
	createdAttr, err = s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)
}

func (s *AttributesSuite) Test_CreateAttribute_WithInvalidRuleFails() {
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__create_attribute_with_invalid_rule",
		NamespaceId: fixtureNamespaceID,
		// fake an enum value index far beyond reason
		Rule: policy.AttributeRuleTypeEnum(100),
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrEnumValueInvalid)
	s.Nil(createdAttr)
}

func (s *AttributesSuite) Test_GetAttribute_OrderOfValuesIsPreserved() {
	values := []string{"first", "second", "third", "fourth"}
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__get_attribute_order_of_values",
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
		Values:      []string{strings.ToUpper(values[0]), strings.ToUpper(values[1]), strings.ToUpper(values[2])},
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)
	s.Len(createdAttr.GetValues(), 3)
	s.Equal(policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, createdAttr.GetRule())

	// add a fourth value
	val := &attributes.CreateAttributeValueRequest{
		Value:       strings.ToUpper(values[3]),
		AttributeId: createdAttr.GetId(),
	}

	createdVal, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, createdAttr.GetId(), val)
	s.Require().NoError(err)
	s.NotNil(createdVal)

	// get attribute and ensure the order of the values is preserved (normalized to lower case)
	gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	s.Require().NoError(err)
	s.NotNil(gotAttr)
	s.Len(gotAttr.GetValues(), 4)
	s.Equal(values[0], gotAttr.GetValues()[0].GetValue())
	s.Equal(values[1], gotAttr.GetValues()[1].GetValue())
	s.Equal(values[2], gotAttr.GetValues()[2].GetValue())
	s.Equal(values[3], gotAttr.GetValues()[3].GetValue())
	s.Equal(policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, gotAttr.GetRule())

	// deactivate one of the values
	deactivatedVal, err := s.db.PolicyClient.DeactivateAttributeValue(s.ctx, gotAttr.GetValues()[1].GetId())
	s.Require().NoError(err)
	s.NotNil(deactivatedVal)

	// get attribute and ensure order stays consistent with all present
	gotAttr, err = s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	s.Require().NoError(err)
	s.NotNil(gotAttr)
	s.Len(gotAttr.GetValues(), 4)
	s.Equal(values[0], gotAttr.GetValues()[0].GetValue())
	s.Equal(values[1], gotAttr.GetValues()[1].GetValue())
	s.Equal(values[2], gotAttr.GetValues()[2].GetValue())
	s.Equal(values[3], gotAttr.GetValues()[3].GetValue())
	s.Equal(policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, gotAttr.GetRule())

	// get attribute by value fqn and ensure the order of the values is preserved with the deactivated not returned
	fqns := []string{fmt.Sprintf("https://%s/attr/%s/value/%s", gotAttr.GetNamespace().GetName(), createdAttr.GetName(), gotAttr.GetValues()[0].GetValue())}
	req := &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: fqns,
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	}
	resp, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Len(resp, 1)
	gotVals := resp[fqns[0]].GetAttribute().GetValues()
	s.Len(gotVals, 3)
	// the value that was originally second and deactivated should not have been returned
	s.Equal(values[0], gotVals[0].GetValue())
	s.Equal(values[2], gotVals[1].GetValue())
	s.Equal(values[3], gotVals[2].GetValue())
}

func (s *AttributesSuite) Test_GetAttribute() {
	fixtures := s.getAttributeFixtures()

	for fqn, f := range fixtures {
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
				input:          &attributes.GetAttributeRequest_AttributeId{AttributeId: f.ID},
				identifierType: "New ID",
			},
			{
				name:           "New Identifier - FQN",
				input:          &attributes.GetAttributeRequest_Fqn{Fqn: fqn},
				identifierType: "FQN",
			},
		}

		for _, tc := range testCases {
			s.Run(fmt.Sprintf("%s - %s", fqn, tc.name), func() { // Include fqn in test name for clarity
				gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, tc.input)
				s.Require().NoError(err, "Failed to get Attribute by %s: %v", tc.identifierType, tc.input)
				s.Require().NotNil(gotAttr, "Expected non-nil Attribute for %s: %v", tc.identifierType, tc.input)

				s.Equal(f.ID, gotAttr.GetId(), "ID mismatch for %s: %v", tc.identifierType, tc.input)
				s.Equal(f.Name, gotAttr.GetName(), "Name mismatch for %s: %v", tc.identifierType, tc.input)
				s.Equal(fmt.Sprintf("%s%s", policydb.AttributeRuleTypeEnumPrefix, f.Rule), gotAttr.GetRule().Enum().String(), "Rule mismatch for %s: %v", tc.identifierType, tc.input)
				s.Equal(f.NamespaceID, gotAttr.GetNamespace().GetId(), "NamespaceID mismatch for %s: %v", tc.identifierType, tc.input)

				metadata := gotAttr.GetMetadata()
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
}

func (s *AttributesSuite) Test_GetAttribute_NotFound() {
	testCases := []struct {
		name           string
		input          interface{} // Could be string ID or identifier struct if needed later
		identifierType string
	}{
		{
			name:           "Not Found - Deprecated ID", // Or just "Not Found" if only one case is needed
			input:          nonExistentAttrID,
			identifierType: "Deprecated ID", // Or "UUID", "ID"
		},
		{
			name:           "Not Found - New Identifier - ID",
			input:          &attributes.GetAttributeRequest_AttributeId{AttributeId: nonExistentAttrID},
			identifierType: "New ID",
		},
		{
			name:           "Not Found - New Identifier - FQN",
			input:          &attributes.GetAttributeRequest_Fqn{Fqn: "https://example.com/attr/non_existent_attr"},
			identifierType: "FQN",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, tc.input)
			s.Require().Error(err, "Expected error when Attribute is not found by %s: %v", tc.identifierType, tc.input)
			s.Nil(gotAttr, "Expected nil Attribute when not found by %s: %v", tc.identifierType, tc.input)
			s.Require().ErrorIs(err, db.ErrNotFound, "Expected ErrNotFound when Attribute is not found by %s: %v", tc.identifierType, tc.input)
		})
	}
}

func (s *AttributesSuite) Test_GetAttribute_Deactivated_Succeeds() {
	deactivated := s.f.GetAttributeKey("deactivated.io/attr/deactivated_attr")
	gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, deactivated.ID)
	s.Require().NoError(err)
	s.NotNil(gotAttr)
	s.Equal(deactivated.ID, gotAttr.GetId())
	s.Equal(deactivated.Name, gotAttr.GetName())
	s.False(gotAttr.GetActive().GetValue())
}

func (s *AttributesSuite) Test_GetAttribute_ContainsKASGrants() {
	// create an attribute
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__get_attribute_contains_kas_grants",
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)

	// create a KAS
	kas := &kasregistry.CreateKeyAccessServerRequest{
		Uri: "https://example.com/kas",
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Remote{
				Remote: "https://example.com/kas/key/1",
			},
		},
		Name: "def_kas-name",
	}
	createdKAS, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, kas)
	s.Require().NoError(err)
	s.NotNil(createdKAS)

	// create a grant for the KAS
	assignment := &attributes.AttributeKeyAccessServer{
		AttributeId:       createdAttr.GetId(),
		KeyAccessServerId: createdKAS.GetId(),
	}

	createdGrant, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, assignment)
	s.Require().NoError(err)
	s.NotNil(createdGrant)

	// get the attribute & ensure it contains the grant
	gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	s.Require().NoError(err)
	s.NotNil(gotAttr)

	gotGrants := gotAttr.GetGrants()
	s.Len(gotGrants, 1)
	s.Equal(createdKAS.GetId(), gotGrants[0].GetId())
	s.Equal(kas.GetName(), gotGrants[0].GetName())
}

func (s *AttributesSuite) Test_ListAttributes_NoPagination_Succeeds() {
	fixtures := s.getAttributeFixtures()

	r := &attributes.ListAttributesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
	}
	listRsp, err := s.db.PolicyClient.ListAttributes(s.ctx, r)
	s.Require().NoError(err)
	s.NotNil(listRsp)

	// all fixtures are listed
	for _, f := range fixtures {
		var found bool
		for _, l := range listRsp.GetAttributes() {
			if f.ID == l.GetId() {
				found = true
				break
			}
		}
		s.True(found)
	}
}

func (s *AttributesSuite) Test_ListAttributes_Limit_Succeeds() {
	var limit int32 = 2
	listRsp, err := s.db.PolicyClient.ListAttributes(s.ctx, &attributes.ListAttributesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
		Pagination: &policy.PageRequest{
			Limit: limit,
		},
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)
	listed := listRsp.GetAttributes()
	s.Equal(len(listed), int(limit))

	for _, definition := range listed {
		s.NotEmpty(definition.GetFqn())
		s.NotEmpty(definition.GetId())
		s.NotEmpty(definition.GetName())
	}

	// request with one below maximum
	listRsp, err = s.db.PolicyClient.ListAttributes(s.ctx, &attributes.ListAttributesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax - 1,
		},
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)

	// exactly maximum
	listRsp, err = s.db.PolicyClient.ListAttributes(s.ctx, &attributes.ListAttributesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax,
		},
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)
}

func (s *NamespacesSuite) Test_ListAttributes_Limit_TooLarge_Fails() {
	listRsp, err := s.db.PolicyClient.ListAttributes(s.ctx, &attributes.ListAttributesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax + 1,
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrListLimitTooLarge)
	s.Nil(listRsp)
}

func (s *AttributesSuite) Test_ListAttributes_Offset_Succeeds() {
	req := &attributes.ListAttributesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
	}
	// make initial list request to compare against
	listRsp, err := s.db.PolicyClient.ListAttributes(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(listRsp)
	listed := listRsp.GetAttributes()

	// set the offset pagination
	offset := 2
	req.Pagination = &policy.PageRequest{
		Offset: int32(offset),
	}
	offsetListRsp, err := s.db.PolicyClient.ListAttributes(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(offsetListRsp)
	offsetListed := offsetListRsp.GetAttributes()

	// length is reduced by the offset amount
	s.Equal(len(offsetListed), len(listed)-offset)

	// objects are equal between offset and original list beginning at offset index
	for i, attr := range offsetListed {
		s.True(proto.Equal(attr, listed[i+offset]))
	}
}

func (s *AttributesSuite) Test_ListAttributes_FqnsIncluded() {
	// create an attribute
	attr := &attributes.CreateAttributeRequest{
		Name:        "list_attribute_fqns_new_attr",
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values:      []string{"value1", "value2", "value3"},
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)

	r := &attributes.ListAttributesRequest{
		State:     common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE,
		Namespace: fixtureNamespaceID,
	}
	list, err := s.db.PolicyClient.ListAttributes(s.ctx, r)
	s.Require().NoError(err)
	s.NotNil(list)

	for _, a := range list.GetAttributes() {
		// attr fqn
		s.NotEqual("", a.GetFqn())
		s.Equal(fmt.Sprintf("https://%s/attr/%s", a.GetNamespace().GetName(), a.GetName()), a.GetFqn())

		// namespace fqn
		s.NotEqual("", a.GetNamespace().GetFqn())
		s.Equal(fmt.Sprintf("https://%s", a.GetNamespace().GetName()), a.GetNamespace().GetFqn())

		// value fqns
		for _, v := range a.GetValues() {
			s.NotEqual("", v.GetFqn())
			s.Equal(fmt.Sprintf("https://%s/attr/%s/value/%s", a.GetNamespace().GetName(), a.GetName(), v.GetValue()), v.GetFqn())
		}
	}
}

func (s *AttributesSuite) Test_ListAttributes_ByNamespaceIdOrName() {
	// get all unique namespace_ids
	namespaces := map[string]string{}
	for _, f := range s.getAttributeFixtures() {
		namespaces[f.NamespaceID] = ""
	}
	r := &attributes.ListAttributesRequest{
		State: common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
	}
	// list attributes by namespace id
	for nsID := range namespaces {
		r.Namespace = nsID
		rsp, err := s.db.PolicyClient.ListAttributes(s.ctx, r)
		s.Require().NoError(err)
		s.NotNil(rsp)
		listed := rsp.GetAttributes()
		s.NotEmpty(listed)
		for _, l := range listed {
			s.Equal(nsID, l.GetNamespace().GetId())
		}
		namespaces[nsID] = listed[0].GetNamespace().GetName()
	}

	// list attributes by namespace name
	for _, nsName := range namespaces {
		r.Namespace = nsName
		rsp, err := s.db.PolicyClient.ListAttributes(s.ctx, r)
		s.Require().NoError(err)
		s.NotNil(rsp)
		listed := rsp.GetAttributes()
		s.NotEmpty(listed)
		for _, l := range listed {
			s.Equal(nsName, l.GetNamespace().GetName())
		}
	}

	// list attributes by namespace name with case insensitivity
	for _, nsName := range namespaces {
		r.Namespace = strings.ToUpper(nsName)
		rsp, err := s.db.PolicyClient.ListAttributes(s.ctx, r)
		s.Require().NoError(err)
		s.NotNil(rsp)
		listed := rsp.GetAttributes()
		s.NotEmpty(listed)
		for _, l := range listed {
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
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
		Metadata: &common.MetadataMutable{
			Labels: labels,
		},
	}
	created, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(created)

	// update with no changes
	updatedWithoutChange, err := s.db.PolicyClient.UpdateAttribute(s.ctx, created.GetId(), &attributes.UpdateAttributeRequest{})
	s.Require().NoError(err)
	s.NotNil(updatedWithoutChange)
	s.Equal(created.GetId(), updatedWithoutChange.GetId())

	// update with metadata
	updatedWithChange, err := s.db.PolicyClient.UpdateAttribute(s.ctx, created.GetId(), &attributes.UpdateAttributeRequest{
		Metadata: &common.MetadataMutable{
			Labels: updateLabels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	s.Require().NoError(err)
	s.NotNil(updatedWithChange)
	s.Equal(created.GetId(), updatedWithChange.GetId())

	got, err := s.db.PolicyClient.GetAttribute(s.ctx, created.GetId())
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
	resp, err := s.db.PolicyClient.UpdateAttribute(s.ctx, nonExistentAttrID, update)
	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributesSuite) Test_UnsafeUpdateAttribute_WithRuleAndNameAndReordering() {
	originalName := "test__update_attribute_with_rule_and_name_and_reordering"
	newName := "updated_hello"
	namespaceID := s.f.GetNamespaceKey("example.org").ID
	values := []string{"abc", "def", "xyz", "testing"}
	attr := &attributes.CreateAttributeRequest{
		Name:        originalName,
		NamespaceId: namespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values:      values,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)

	got, err := s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	nsName := got.GetNamespace().GetName()
	updatedVals := []string{"def", "abc", "testing", "xyz"}
	updatedValIDs := make([]string, len(values))
	for i, v := range got.GetValues() {
		idx := slices.Index(updatedVals, v.GetValue())
		updatedValIDs[i] = got.GetValues()[idx].GetId()
	}

	// name, rule, order updates respected
	updated, err := s.db.PolicyClient.UnsafeUpdateAttribute(s.ctx, &unsafe.UnsafeUpdateAttributeRequest{
		Id:          createdAttr.GetId(),
		Name:        newName,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
		ValuesOrder: updatedValIDs,
	})
	s.Require().NoError(err)
	s.NotNil(updated)
	s.Equal(newName, updated.GetName())
	s.Equal(policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, updated.GetRule())

	// name, rule, order updates respected and fqn is updated
	updated, err = s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	s.Require().NoError(err)
	s.NotNil(updated)
	s.Equal(newName, updated.GetName())
	s.Equal(policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, updated.GetRule())
	s.Equal(fmt.Sprintf("https://%s/attr/%s", nsName, updated.GetName()), updated.GetFqn())
	s.Len(updated.GetValues(), len(values))

	// values reflect new updated name and requested update order
	for i, v := range updated.GetValues() {
		s.Equal(updatedVals[i], v.GetValue())
		fqn := fmt.Sprintf("https://%s/attr/%s/value/%s", nsName, newName, v.GetValue())

		val, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
			Fqns: []string{fqn},
			WithValue: &policy.AttributeValueSelector{
				WithSubjectMaps: true,
			},
		})
		s.Require().NoError(err)
		s.NotNil(val)
		s.Len(val, 1)
		s.Equal(v.GetId(), val[fqn].GetValue().GetId())
	}
}

func (s *AttributesSuite) Test_UnsafeUpdateAttribute_WithRule() {
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__update_attribute_with_rule",
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)

	got, err := s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF, got.GetRule())

	updated, err := s.db.PolicyClient.UnsafeUpdateAttribute(s.ctx, &unsafe.UnsafeUpdateAttributeRequest{
		Id:   createdAttr.GetId(),
		Rule: policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	})
	s.Require().NoError(err)
	s.NotNil(updated)
	s.Equal(policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, updated.GetRule())

	updated, err = s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	s.Require().NoError(err)
	s.NotNil(updated)
	s.Equal(policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, updated.GetRule())
}

func (s *AttributesSuite) Test_UnsafeUpdateAttribute_WithNewName() {
	originalName := "test__update_attribute_with_new_name"
	newName := originalName + "updated"
	attr := &attributes.CreateAttributeRequest{
		Name:        originalName,
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values:      []string{"abc", "def"},
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)

	got, err := s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	s.Require().NoError(err)
	s.NotNil(got)

	originalFqn := got.GetFqn()
	s.NotEqual("", originalFqn)

	// update with a new name
	updated, err := s.db.PolicyClient.UnsafeUpdateAttribute(s.ctx, &unsafe.UnsafeUpdateAttributeRequest{
		Id:   createdAttr.GetId(),
		Name: newName,
	})
	s.Require().NoError(err)
	s.NotNil(updated)
	s.Equal(newName, updated.GetName())
	s.NotEqual(originalFqn, updated.GetFqn())

	updated, err = s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	s.Require().NoError(err)
	s.NotNil(updated)

	// ensure the fqn has changed
	s.Equal(fmt.Sprintf("https://%s/attr/%s", got.GetNamespace().GetName(), updated.GetName()), updated.GetFqn())

	// ensure the name change is reflected
	s.Equal(newName, updated.GetName())

	// ensure everything else is unchanged
	s.Equal(got.GetRule(), updated.GetRule())
	s.Len(updated.GetValues(), 2)
	s.True(updated.GetActive().GetValue())

	// values are able to be looked up by fqn with new updated name
	fqns := []string{
		fmt.Sprintf("https://%s/attr/%s/value/%s", got.GetNamespace().GetName(), updated.GetName(), updated.GetValues()[0].GetValue()),
		fmt.Sprintf("https://%s/attr/%s/value/%s", got.GetNamespace().GetName(), updated.GetName(), updated.GetValues()[1].GetValue()),
	}
	req := &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: fqns,
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	}
	retrieved, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(retrieved)
	s.Len(retrieved, 2)

	val, err := s.db.PolicyClient.GetAttributeValue(s.ctx, updated.GetValues()[0].GetId())
	s.Require().NoError(err)
	s.NotNil(val)
	s.Equal(fqns[0], val.GetFqn())
	s.Contains(val.GetFqn(), updated.GetName())

	val, err = s.db.PolicyClient.GetAttributeValue(s.ctx, updated.GetValues()[1].GetId())
	s.Require().NoError(err)
	s.NotNil(val)
	s.Equal(fqns[1], val.GetFqn())
	s.Contains(val.GetFqn(), updated.GetName())
}

func (s *AttributesSuite) Test_UnsafeUpdateAttribute_NormalizesCasing() {
	created, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		Name:        "BANANA_PUDDING",
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values:      []string{"fig", "jam"},
	})
	s.Require().NoError(err)
	s.NotNil(created)

	got, err := s.db.PolicyClient.GetAttribute(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal("banana_pudding", got.GetName())
	s.Contains(got.GetFqn(), "banana_pudding")

	updated, err := s.db.PolicyClient.UnsafeUpdateAttribute(s.ctx, &unsafe.UnsafeUpdateAttributeRequest{
		Id:   created.GetId(),
		Name: "STRAWBERRY_SHORTCAKE",
	})
	s.Require().NoError(err)
	s.NotNil(updated)
	s.Equal("strawberry_shortcake", updated.GetName())

	got, err = s.db.PolicyClient.GetAttribute(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal("strawberry_shortcake", got.GetName())
	s.Contains(got.GetFqn(), "strawberry_shortcake")
}

func (s *AttributesSuite) Test_UnsafeUpdateAttribute_ReplaceValuesOrder() {
	toCreate := &attributes.CreateAttributeRequest{
		Name:        "test__unsafe_update_attribute_replace_values_order",
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY,
		Values:      []string{"first", "second", "third"},
	}
	created, err := s.db.PolicyClient.CreateAttribute(s.ctx, toCreate)
	s.Require().NoError(err)
	s.NotNil(created)
	s.Len(created.GetValues(), 3)

	// reverse values order
	reversed := make([]string, len(created.GetValues()))
	for i, v := range created.GetValues() {
		reversed[len(created.GetValues())-i-1] = v.GetId()
	}
	updated, err := s.db.PolicyClient.UnsafeUpdateAttribute(s.ctx, &unsafe.UnsafeUpdateAttributeRequest{
		Id:          created.GetId(),
		ValuesOrder: reversed,
	})
	s.Require().NoError(err)
	s.NotNil(updated)

	// get attribute and ensure the order of the values is preserved and successfully reversed
	got, err := s.db.PolicyClient.GetAttribute(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Len(got.GetValues(), 3)
	for i, v := range got.GetValues() {
		s.Equal(reversed[i], v.GetId())
	}
}

func (s *AttributesSuite) Test_UnsafeDeleteAttribute() {
	name := "test__delete_attribute"
	attr := &attributes.CreateAttributeRequest{
		Name:        name,
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED,
		Values:      []string{"value1", "value2", "value3"},
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)

	got, _ := s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())

	deleted, err := s.db.PolicyClient.UnsafeDeleteAttribute(s.ctx, got, got.GetFqn())
	s.Require().NoError(err)
	s.NotNil(deleted)

	// attribute should not exist anymore
	resp, err := s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	s.Require().Error(err)
	s.Nil(resp)

	// values should not exist anymore (cascade delete)
	for _, v := range createdAttr.GetValues() {
		resp, err := s.db.PolicyClient.GetAttributeValue(s.ctx, v.GetId())
		s.Require().Error(err)
		s.Nil(resp)
	}

	// namespace should still exist unaffected
	ns, err := s.db.PolicyClient.GetNamespace(s.ctx, fixtureNamespaceID)
	s.Require().NoError(err)
	s.NotNil(ns)
	s.NotEqual("", ns.GetId())

	// attribute should not be listed anymore
	rsp, err := s.db.PolicyClient.ListAttributes(s.ctx, &attributes.ListAttributesRequest{
		State:     common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
		Namespace: fixtureNamespaceID,
	})
	s.Require().NoError(err)
	s.NotNil(rsp)
	listed := rsp.GetAttributes()
	for _, l := range listed {
		s.NotEqual(createdAttr.GetId(), l.GetId())
	}

	// attr fqn should not be found
	fqn := fmt.Sprintf("https://%s/attr/%s", ns.GetName(), name)
	resp, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, fqn)
	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorIs(err, db.ErrNotFound)

	// value fqns should be deleted and not found
	for _, v := range got.GetValues() {
		fqns := []string{fmt.Sprintf("https://%s/attr/%s/value/%s", ns.GetName(), name, v.GetValue())}
		req := &attributes.GetAttributeValuesByFqnsRequest{
			Fqns: fqns,
			WithValue: &policy.AttributeValueSelector{
				WithSubjectMaps: true,
			},
		}
		retrieved, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, req)
		s.Require().Error(err)
		s.Nil(retrieved)
		s.Require().ErrorIs(err, db.ErrNotFound)
	}

	// should be able to create attribute of same name as deleted
	createdAttr, err = s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)
}

func (s *AttributesSuite) Test_UnsafeDeleteAttribute_WithBadFqnFails() {
	created, _ := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		Name:        "test__delete_attribute_with_bad_fqn",
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	})
	got, _ := s.db.PolicyClient.GetAttribute(s.ctx, created.GetId())
	s.NotNil(got)
	s.NotEqual("", got.GetFqn())

	deleted, err := s.db.PolicyClient.UnsafeDeleteAttribute(s.ctx, got, "bad_fqn")
	s.Require().Error(err)
	s.Nil(deleted)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributesSuite) Test_DeactivateAttribute_WithInvalidIdFails() {
	deactivated, err := s.db.PolicyClient.DeactivateAttribute(s.ctx, nonExistentAttrID)
	s.Require().Error(err)
	s.Nil(deactivated)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

// reusable setup for creating a namespace -> attr -> value and then deactivating the attribute (cascades to value)
func setupCascadeDeactivateAttribute(s *AttributesSuite) (string, string, string) {
	// create a namespace
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test__cascading-deactivate-ns",
	})
	s.Require().NoError(err)
	s.NotZero(n.GetId())

	// add an attribute under that namespaces
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__cascading-deactivate-attr",
		NamespaceId: n.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)

	// add a value under that attribute
	val := &attributes.CreateAttributeValueRequest{
		Value: "test__cascading-deactivate-attr-value",
	}
	createdVal, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, createdAttr.GetId(), val)
	s.Require().NoError(err)
	s.NotNil(createdVal)

	// deactivate the attribute
	deactivatedAttr, err := s.db.PolicyClient.DeactivateAttribute(s.ctx, createdAttr.GetId())
	s.Require().NoError(err)
	s.NotNil(deactivatedAttr)

	return n.GetId(), createdAttr.GetId(), createdVal.GetId()
}

func (s *AttributesSuite) Test_DeactivateAttribute_Cascades_List() {
	type test struct {
		name     string
		testFunc func(state common.ActiveStateEnum) bool
		state    common.ActiveStateEnum
		isFound  bool
	}

	listNamespaces := func(state common.ActiveStateEnum) bool {
		nsListRsp, err := s.db.PolicyClient.ListNamespaces(s.ctx, &namespaces.ListNamespacesRequest{
			State: state,
		})
		s.Require().NoError(err)
		s.NotNil(nsListRsp)
		listed := nsListRsp.GetNamespaces()
		for _, ns := range listed {
			if stillActiveNsID == ns.GetId() {
				return true
			}
		}
		return false
	}

	listAttributes := func(state common.ActiveStateEnum) bool {
		listAttrsRsp, err := s.db.PolicyClient.ListAttributes(s.ctx, &attributes.ListAttributesRequest{
			State: state,
		})
		s.Require().NoError(err)
		s.NotNil(listAttrsRsp)
		listed := listAttrsRsp.GetAttributes()
		for _, a := range listed {
			if deactivatedAttrID == a.GetId() {
				return true
			}
		}
		return false
	}

	listValues := func(state common.ActiveStateEnum) bool {
		valsListRsp, err := s.db.PolicyClient.ListAttributeValues(s.ctx, &attributes.ListAttributeValuesRequest{
			AttributeId: deactivatedAttrID,
			State:       state,
		})
		s.Require().NoError(err)
		s.NotNil(valsListRsp)
		listed := valsListRsp.GetValues()
		for _, v := range listed {
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
			name:     "attribute is found when filtering for INACTIVE state",
			testFunc: listAttributes,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE,
			isFound:  true,
		},
		{
			name:     "attribute is found when filtering for ANY state",
			testFunc: listAttributes,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
			isFound:  true,
		},
		{
			name:     "attribute is NOT found when filtering for ACTIVE state",
			testFunc: listAttributes,
			state:    common.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE,
			isFound:  false,
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

func (s *AttributesSuite) Test_DeactivateAttribute_Cascades_ToValues_Get() {
	// ensure the namespace has state active still (not bubbled up)
	gotNs, err := s.db.PolicyClient.GetNamespace(s.ctx, stillActiveNsID)
	s.Require().NoError(err)
	s.NotNil(gotNs)
	s.True(gotNs.GetActive().GetValue())

	// ensure the attribute has state inactive
	gotAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, deactivatedAttrID)
	s.Require().NoError(err)
	s.NotNil(gotAttr)
	s.False(gotAttr.GetActive().GetValue())

	// ensure the value has state inactive
	gotVal, err := s.db.PolicyClient.GetAttributeValue(s.ctx, deactivatedAttrValueID)
	s.Require().NoError(err)
	s.NotNil(gotVal)
	s.False(gotVal.GetActive().GetValue())
}

func (s *AttributesSuite) Test_UnsafeReactivateAttribute() {
	// create an attribute
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__unsafe_reactivate_attribute",
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values:      []string{"aa", "bb", "cc"},
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)

	// deactivate the attribute
	deactivatedAttr, err := s.db.PolicyClient.DeactivateAttribute(s.ctx, createdAttr.GetId())
	s.Require().NoError(err)
	s.NotNil(deactivatedAttr)
	s.False(deactivatedAttr.GetActive().GetValue())

	// reactivate the attribute
	reactivatedAttr, err := s.db.PolicyClient.UnsafeReactivateAttribute(s.ctx, createdAttr.GetId())
	s.Require().NoError(err)
	s.NotNil(reactivatedAttr)

	// found to be active
	activated, err := s.db.PolicyClient.GetAttribute(s.ctx, reactivatedAttr.GetId())
	s.Require().NoError(err)
	s.NotNil(activated)
	s.True(activated.GetActive().GetValue())

	// found in successive lookup by fqn
	activated, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, activated.GetFqn())
	s.Require().NoError(err)
	s.NotNil(activated)

	// ensure the values are still inactive
	for _, v := range reactivatedAttr.GetValues() {
		got, err := s.db.PolicyClient.GetAttributeValue(s.ctx, v.GetId())
		s.Require().NoError(err)
		s.NotNil(got)
		s.False(got.GetActive().GetValue())
	}
}

func (s *AttributesSuite) Test_UnsafeReactivateAttribute_WithInvalidIdFails() {
	reactivatedAttr, err := s.db.PolicyClient.UnsafeReactivateAttribute(s.ctx, nonExistentAttrID)
	s.Require().Error(err)
	s.Nil(reactivatedAttr)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributesSuite) Test_AssignKeyAccessServerToAttribute_Returns_Error_When_Attribute_Not_Found() {
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       nonExistentAttrID,
		KeyAccessServerId: fixtureKeyAccessServerID,
	}
	resp, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, aKas)

	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorIs(err, db.ErrForeignKeyViolation)
}

func (s *AttributesSuite) Test_AssignKeyAccessServerToAttribute_Returns_Error_When_KeyAccessServer_Not_Found() {
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       s.f.GetAttributeKey("example.com/attr/attr1").ID,
		KeyAccessServerId: nonExistentAttrID,
	}
	resp, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, aKas)

	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorIs(err, db.ErrForeignKeyViolation)
}

func (s *AttributesSuite) Test_AssignKeyAccessServerToAttribute_Returns_Success_When_Attribute_And_KeyAccessServer_Exist() {
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       s.f.GetAttributeKey("example.com/attr/attr2").ID,
		KeyAccessServerId: fixtureKeyAccessServerID,
	}
	resp, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, aKas)

	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(aKas, resp)
}

func (s *AttributesSuite) Test_RemoveKeyAccessServerFromAttribute_Returns_Error_When_Attribute_Not_Found() {
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       nonExistentAttrID,
		KeyAccessServerId: fixtureKeyAccessServerID,
	}
	resp, err := s.db.PolicyClient.RemoveKeyAccessServerFromAttribute(s.ctx, aKas)

	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributesSuite) Test_RemoveKeyAccessServerFromAttribute_Returns_Error_When_KeyAccessServer_Not_Found() {
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       s.f.GetAttributeKey("example.com/attr/attr1").ID,
		KeyAccessServerId: nonExistentAttrID,
	}
	resp, err := s.db.PolicyClient.RemoveKeyAccessServerFromAttribute(s.ctx, aKas)

	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributesSuite) Test_RemoveKeyAccessServerFromAttribute_Returns_Success_When_Attribute_And_KeyAccessServer_Exist() {
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       s.f.GetAttributeKey("example.com/attr/attr1").ID,
		KeyAccessServerId: s.f.GetKasRegistryKey("key_access_server_1").ID,
	}
	resp, err := s.db.PolicyClient.RemoveKeyAccessServerFromAttribute(s.ctx, aKas)

	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(aKas, resp)
}

func TestAttributesSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping attributes integration tests")
	}
	suite.Run(t, new(AttributesSuite))
}
