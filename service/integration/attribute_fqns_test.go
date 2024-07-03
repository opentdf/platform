package integration

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/suite"
)

type AttributeFqnSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context //nolint:containedctx // context is used in the test suite
}

func fqnBuilder(n string, a string, v string) string {
	fqn := "https://"
	switch {
	case n != "" && a != "" && v != "":
		return fqn + n + "/attr/" + a + "/value/" + v
	case n != "" && a != "" && v == "":
		return fqn + n + "/attr/" + a
	case n != "" && a == "":
		return fqn + n
	default:
		panic("Invalid FQN")
	}
}

func TestAttributeFqnSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping attributes integration tests")
	}
	suite.Run(t, new(AttributeFqnSuite))
}

func (s *AttributeFqnSuite) SetupSuite() {
	slog.Info("setting up db.AttributeFqn test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_attribute_fqn"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
}

func (s *AttributeFqnSuite) TearDownSuite() {
	slog.Info("tearing down db.AttributeFqn test suite")
	s.f.TearDown()
}

// Test Create Namespace
func (s *AttributeFqnSuite) TestCreateNamespace() {
	name := "test_namespace"
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: name,
	})
	s.Require().NoError(err)
	// Verify FQN
	fqn, err := s.db.PolicyClient.GetNamespace(s.ctx, n.GetId())
	s.Require().NoError(err)
	s.NotEmpty(fqn.GetFqn())
	s.Equal(fqnBuilder(name, "", ""), fqn.GetFqn())
}

// Test Create Attribute
func (s *AttributeFqnSuite) TestCreateAttribute() {
	n := s.f.GetNamespaceKey("example.com")
	name := "test_namespace"
	a, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId: n.ID,
		Name:        name,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	})
	s.Require().NoError(err)
	// Verify FQN
	fqn, err := s.db.PolicyClient.GetAttribute(s.ctx, a.GetId())
	s.Require().NoError(err)
	s.NotEmpty(fqn.GetFqn())
	s.Equal(fqnBuilder(n.Name, a.GetName(), ""), fqn.GetFqn())
}

// Test Create Attribute Value
func (s *AttributeFqnSuite) TestCreateAttributeValue() {
	a := s.f.GetAttributeKey("example.com/attr/attr1")
	n := s.f.GetNamespaceKey("example.com")
	name := "test_new_value"
	v, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, a.ID, &attributes.CreateAttributeValueRequest{
		Value: name,
	})
	s.Require().NoError(err)
	// Verify FQN
	fqn, err := s.db.PolicyClient.GetAttributeValue(s.ctx, v.GetId())
	s.Require().NoError(err)
	s.NotEmpty(fqn.GetFqn())
	s.Equal(fqnBuilder(n.Name, a.Name, v.GetValue()), fqn.GetFqn())
}

// Test Get one attribute by the FQN of one of its values
func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithAttrValueFqn() {
	fqnFixtureKey := "example.com/attr/attr1/value/value1"
	fullFqn := fmt.Sprintf("https://%s", fqnFixtureKey)
	valueFixture := s.f.GetAttributeValueKey(fqnFixtureKey)

	attr, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.Require().NoError(err)
	s.NotNil(attr)
	s.Equal(valueFixture.AttributeDefinitionID, attr.GetId())

	// there should be more than one value on the attribute
	s.Greater(len(attr.GetValues()), 1)

	// the value should match the fixture (verify by looping through and matching the fqn)
	for _, v := range attr.GetValues() {
		if v.GetId() == valueFixture.ID {
			s.Equal(fullFqn, v.GetFqn())
			s.Equal(valueFixture.ID, v.GetId())
			s.Equal(valueFixture.Value, v.GetValue())
			// the value should contain subject mappings
			s.GreaterOrEqual(len(v.GetSubjectMappings()), 3)
		}
	}
}

// Test Get one attribute by the FQN of one of its values
func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithCasingNormalized() {
	fqnFixtureKey := "example.com/attr/attr1/value/value1"
	fullFqn := strings.ToUpper(fmt.Sprintf("https://%s", fqnFixtureKey))
	valueFixture := s.f.GetAttributeValueKey(fqnFixtureKey)

	attr, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.Require().NoError(err)
	s.NotNil(attr)
	s.Equal(valueFixture.AttributeDefinitionID, attr.GetId())

	// there should be more than one value on the attribute
	s.Greater(len(attr.GetValues()), 1)

	// the value should match the fixture (verify by looping through and matching the fqn)
	for _, v := range attr.GetValues() {
		if v.GetId() == valueFixture.ID {
			s.Equal(strings.ToLower(fullFqn), v.GetFqn())
			s.Equal(valueFixture.ID, v.GetId())
			s.Equal(valueFixture.Value, v.GetValue())
			// the value should contain subject mappings
			s.GreaterOrEqual(len(v.GetSubjectMappings()), 3)
		}
	}
}

// Test Get one attribute by the FQN of the attribute definition
func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithAttrFqn() {
	fqnFixtureKey := "example.net/attr/attr1"
	fullFqn := fmt.Sprintf("https://%s", fqnFixtureKey)
	attrFixture := s.f.GetAttributeKey(fqnFixtureKey)

	attr, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.Require().NoError(err)

	// the number of values should match the fixture
	s.Len(attr.GetValues(), 2)

	// the attribute should match the fixture
	s.Equal(attr.GetId(), attrFixture.ID)
	s.Equal(attr.GetName(), attrFixture.Name)
	s.Equal(attr.GetRule().String(), fmt.Sprintf("ATTRIBUTE_RULE_TYPE_ENUM_%s", attrFixture.Rule))
	s.Equal(attr.GetActive().GetValue(), attrFixture.Active)
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithKeyAccessGrants_Definitions() {
	// create attribute under fixture namespace id
	n := s.f.GetNamespaceKey("example.org")
	a, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId: n.ID,
		Name:        "attr_with_grants",
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values:      []string{"value1", "value2"},
	})
	s.Require().NoError(err)
	s.NotNil(a)

	// create a new kas registration
	remoteKAS, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri: "https://example.org/kas",
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Remote{
				Remote: "https://example.org/kas",
			},
		},
	})
	s.Require().NoError(err)
	s.NotNil(remoteKAS)

	// make a first grant association
	grant, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, &attributes.AttributeKeyAccessServer{
		KeyAccessServerId: remoteKAS.GetId(),
		AttributeId:       a.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(grant)

	// create a second kas registration and grant it
	localKAS, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri: "https://example.org/kas2",
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Local{
				Local: "local_key",
			},
		},
	})
	s.Require().NoError(err)
	s.NotNil(localKAS)

	grant2, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, &attributes.AttributeKeyAccessServer{
		KeyAccessServerId: localKAS.GetId(),
		AttributeId:       a.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(grant2)

	// get the attribute by the fqn of the attribute definition
	got, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, "https://example.org/attr/attr_with_grants")
	s.Require().NoError(err)
	s.NotNil(got)

	// ensure the attribute has the grants
	s.Len(got.GetGrants(), 2)
	grantIDs := []string{remoteKAS.GetId(), localKAS.GetId()}
	s.Contains(grantIDs, got.GetGrants()[0].GetId())
	s.Contains(grantIDs, got.GetGrants()[1].GetId())
	s.NotEqual(got.GetGrants()[0].GetId(), got.GetGrants()[1].GetId())

	// get the attribute by the fqn of one of its values and ensure the grants are present
	got, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, "https://example.org/attr/attr_with_grants/value/value1")
	s.Require().NoError(err)
	s.NotNil(got)
	s.Len(got.GetGrants(), 2)

	// assign a KAS to the value and make sure it is not a top-level grant returned
	grant3, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, &attributes.ValueKeyAccessServer{
		KeyAccessServerId: localKAS.GetId(),
		ValueId:           a.GetValues()[0].GetId(),
	})
	s.NotNil(grant3)
	s.Require().NoError(err)

	got, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, "https://example.org/attr/attr_with_grants/value/value1")
	s.Require().NoError(err)
	s.NotNil(got)
	s.Len(got.GetGrants(), 2)
}

// func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithKeyAccessGrants_Values() {
// 	// create attribute under fixture namespace id
// 	n := s.f.GetNamespaceKey("example.org")
// 	a, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
// 		NamespaceId: n.ID,
// 		Name:        "attr_with_values_grants",
// 		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
// 		Values:      []string{"value1", "value2"},
// 	})
// 	s.Require().NoError(err)
// 	s.NotNil(a)
// 	valueFirstID := a.GetValues()[0].GetId()
// 	valueSecondID := a.GetValues()[1].GetId()

// 	// create a new kas registration
// 	remoteKAS, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
// 		Uri: "https://testing.org/kas",
// 		PublicKey: &policy.PublicKey{
// 			PublicKey: &policy.PublicKey_Remote{
// 				Remote: "https://testing.org/kas",
// 			},
// 		},
// 	})
// 	s.Require().NoError(err)
// 	s.NotNil(remoteKAS)

// 	// make a grant association to the first value
// 	grant, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, &attributes.ValueKeyAccessServer{
// 		KeyAccessServerId: remoteKAS.GetId(),
// 		ValueId:           valueFirstID,
// 	})
// 	s.Require().NoError(err)
// 	s.NotNil(grant)

// 	// create a second kas registration and grant it to the second value
// 	localKAS, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
// 		Uri: "https://testing.org/kas2",
// 		PublicKey: &policy.PublicKey{
// 			PublicKey: &policy.PublicKey_Local{
// 				Local: "local_key",
// 			},
// 		},
// 	})
// 	s.Require().NoError(err)
// 	s.NotNil(localKAS)

// 	grant2, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, &attributes.ValueKeyAccessServer{
// 		KeyAccessServerId: localKAS.GetId(),
// 		ValueId:           valueSecondID,
// 	})
// 	s.Require().NoError(err)
// 	s.NotNil(grant2)

// 	// get the attribute by the fqn of the attribute definition
// 	got, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, "https://example.org/attr/attr_with_grants")
// 	s.Require().NoError(err)
// 	s.NotNil(got)

// 	// ensure the attribute has no definition grants
// 	s.Len(got.GetGrants(), 0)

// 	// get the attribute by the fqn of one of its values and ensure the grants are present
// 	got, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, "https://example.org/attr/attr_with_grants/value/value1")
// 	s.Require().NoError(err)
// 	s.NotNil(got)
// 	s.Len(got.GetValues(), 2)
// 	s.Len(got.GetGrants(), 0)

// 	for _, v := range got.GetValues() {
// 		switch v.GetId() {
// 		case valueFirstID:
// 			s.Len(v.GetGrants(), 1)
// 			s.Equal(remoteKAS.GetId(), v.GetGrants()[0].GetId())
// 		case valueSecondID:
// 			s.Len(v.GetGrants(), 1)
// 			s.Equal(localKAS.GetId(), v.GetGrants()[0].GetId())
// 		default:
// 			s.Fail("unexpected value", v)
// 		}
// 	}
// }

// Test multiple get attributes by multiple fqns
func (s *AttributeFqnSuite) TestGetAttributesByValueFqns() {
	namespace := "testing_multiple_fqns.get"
	attr := "test_attr"
	value1 := "test_value"
	value2 := "test_value_2"
	fqn1 := fqnBuilder(namespace, attr, value1)
	fqn2 := fqnBuilder(namespace, attr, value2)

	// Create namespace
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: namespace,
	})
	s.Require().NoError(err)

	// Create attribute
	a, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId: n.GetId(),
		Name:        attr,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	})
	s.Require().NoError(err)

	// Create attribute value1
	v1, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, a.GetId(), &attributes.CreateAttributeValueRequest{
		Value: value1,
	})
	s.Require().NoError(err)

	// Get attributes by fqns with a solo value
	fqns := []string{fqn1}
	attributeAndValue, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: fqns,
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	s.Require().NoError(err)

	// Verify attribute1 is sole attribute
	s.Len(attributeAndValue, 1)
	val, ok := attributeAndValue[fqn1]
	s.True(ok)
	s.Equal(a.GetId(), val.GetAttribute().GetId())

	s.Equal(v1.GetId(), val.GetAttribute().GetValues()[0].GetId())
	s.Equal(v1.GetValue(), val.GetValue().GetValue())

	s.Equal(v1.GetValue(), val.GetAttribute().GetValues()[0].GetValue())
	s.Equal(v1.GetId(), val.GetValue().GetId())

	// Create attribute value2
	v2, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, a.GetId(), &attributes.CreateAttributeValueRequest{
		Value: value2,
	})
	s.Require().NoError(err)

	// Get attributes by fqns with two values
	fqns = []string{fqn1, fqn2}
	attributeAndValue, err = s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: fqns,
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	s.Require().NoError(err)
	s.Len(attributeAndValue, 2)

	val, ok = attributeAndValue[fqn2]
	s.True(ok)
	s.Equal(a.GetId(), val.GetAttribute().GetId())

	for _, v := range val.GetAttribute().GetValues() {
		switch {
		case v.GetId() == v1.GetId():
			s.Equal(v1.GetId(), v.GetId())
			s.Equal(v1.GetValue(), v.GetValue())
		case v.GetId() == v2.GetId():
			s.Equal(v2.GetId(), v.GetId())
			s.Equal(v2.GetValue(), v.GetValue())
		default:
			s.Fail("unexpected value", v)
		}
	}
}

func (s *AttributeFqnSuite) TestGetAttributesByValueFqns_AllValuesHaveProperFqns() {
	namespace := "testing_multiple_fqns.properfqns"
	attr := "test_attr"
	value1 := "test_value"
	value2 := "test_value_2"
	value3 := "testing_values_3"
	fqn1 := fqnBuilder(namespace, attr, value1)
	fqn2 := fqnBuilder(namespace, attr, value2)
	fqn3 := fqnBuilder(namespace, attr, value3)

	// Create namespace
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: namespace,
	})
	s.Require().NoError(err)

	// Create attribute
	a, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId: n.GetId(),
		Name:        attr,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	})
	s.Require().NoError(err)

	// Create attribute value1
	v1, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, a.GetId(), &attributes.CreateAttributeValueRequest{
		Value: value1,
	})
	s.Require().NoError(err)

	// Get attributes by fqns with a solo value
	fqns := []string{fqn1}
	attributeAndValues, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: fqns,
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	s.Require().NoError(err)

	// Verify attribute1 is sole attribute
	s.Len(attributeAndValues, 1)
	val, ok := attributeAndValues[fqn1]
	s.True(ok)
	s.Equal(a.GetId(), val.GetAttribute().GetId())

	s.Equal(v1.GetId(), val.GetAttribute().GetValues()[0].GetId())
	s.Equal(v1.GetValue(), val.GetValue().GetValue())

	s.Equal(v1.GetValue(), val.GetAttribute().GetValues()[0].GetValue())
	s.Equal(v1.GetId(), val.GetValue().GetId())

	// Create attribute value2
	v2, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, a.GetId(), &attributes.CreateAttributeValueRequest{
		Value: value2,
	})
	s.Require().NoError(err)

	// Create attribute value3
	v3, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, a.GetId(), &attributes.CreateAttributeValueRequest{
		Value: value3,
	})
	s.Require().NoError(err)
	s.NotNil(v3)

	// Get attributes by fqns with all three values
	fqns = []string{fqn1, fqn2, fqn3}
	attributeAndValues, err = s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: fqns,
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	s.Require().NoError(err)
	s.Len(attributeAndValues, 3)

	val, ok = attributeAndValues[fqn2]
	s.True(ok)
	s.Equal(a.GetId(), val.GetAttribute().GetId())

	val, ok = attributeAndValues[fqn3]
	s.True(ok)
	s.Equal(a.GetId(), val.GetAttribute().GetId())

	// ensure fqns are properly found in response for each value
	for fqn, attrAndVal := range attributeAndValues {
		values := attrAndVal.GetAttribute().GetValues()
		s.Equal(fqn, attrAndVal.GetValue().GetFqn())
		for i, v := range values {
			s.Equal(fqns[i], v.GetFqn())
			switch {
			case v.GetId() == v1.GetId():
				s.Equal(v1.GetId(), v.GetId())
				s.Equal(v1.GetValue(), v.GetValue())
			case v.GetId() == v2.GetId():
				s.Equal(v2.GetId(), v.GetId())
				s.Equal(v2.GetValue(), v.GetValue())
			case v.GetId() == v3.GetId():
				s.Equal(v3.GetId(), v.GetId())
				s.Equal(v3.GetValue(), v.GetValue())
			default:
				s.Fail("unexpected value", v)
			}
		}
	}
}

func (s *AttributeFqnSuite) TestGetAttributesByValueFqns_Fails_WithDeactivatedNamespace() {
	// create a new namespace
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test_fqn_namespace.co",
	})
	s.Require().NoError(err)

	// give it an attribute with two values
	attr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId: ns.GetId(),
		Name:        "test_attr",
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	})
	s.Require().NoError(err)

	v1, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attr.GetId(), &attributes.CreateAttributeValueRequest{
		Value: "value1",
	})
	s.Require().NoError(err)

	v2, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attr.GetId(), &attributes.CreateAttributeValueRequest{
		Value: "value2",
	})
	s.Require().NoError(err)

	// deactivate the namespace
	_, err = s.db.PolicyClient.DeactivateNamespace(s.ctx, ns.GetId())
	s.Require().NoError(err)

	// get the attribute by the value fqn for v1
	v, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{fqnBuilder(ns.GetName(), attr.GetName(), v1.GetValue())},
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	s.Require().Error(err)
	s.Nil(v)
	s.Require().ErrorIs(err, db.ErrNotFound)

	// get the attribute by the value fqn for v2
	v, err = s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{fqnBuilder(ns.GetName(), attr.GetName(), v2.GetValue())},
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	s.Require().Error(err)
	s.Nil(v)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributeFqnSuite) TestGetAttributesByValueFqns_Fails_WithDeactivatedAttributeDefinition() {
	// create a new namespace
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test_fqn_namespace.hello",
	})
	s.Require().NoError(err)

	// give it an attribute with two values
	attr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId: ns.GetId(),
		Name:        "deactivating_attr",
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	})
	s.Require().NoError(err)

	v1, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attr.GetId(), &attributes.CreateAttributeValueRequest{
		Value: "value1",
	})
	s.Require().NoError(err)

	v2, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, attr.GetId(), &attributes.CreateAttributeValueRequest{
		Value: "value2",
	})
	s.Require().NoError(err)

	// deactivate the attribute definition
	_, err = s.db.PolicyClient.DeactivateAttribute(s.ctx, attr.GetId())
	s.Require().NoError(err)

	// get the attribute by the value fqn for v1
	v, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{fqnBuilder(ns.GetName(), attr.GetName(), v1.GetValue())},
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	s.Require().Error(err)
	s.Nil(v)
	s.Require().ErrorIs(err, db.ErrNotFound)

	// get the attribute by the value fqn for v2
	v, err = s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{fqnBuilder(ns.GetName(), attr.GetName(), v2.GetValue())},
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	s.Require().Error(err)
	s.Nil(v)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributeFqnSuite) TestGetAttributesByValueFqns_Fails_WithDeactivatedAttributeValue() {
	// create a new namespace
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test_fqn_namespace.example",
	})
	s.Require().NoError(err)

	// give it an attribute with two values
	attr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId: ns.GetId(),
		Name:        "deactivating_attr",
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values:      []string{"value1", "value2"},
	})
	s.Require().NoError(err)
	got, _ := s.db.PolicyClient.GetAttribute(s.ctx, attr.GetId())
	s.Require().NoError(err)
	values := got.GetValues()
	s.Len(values, 2)
	v1 := values[0]
	v2 := values[1]

	// deactivate an attribute value
	_, err = s.db.PolicyClient.DeactivateAttributeValue(s.ctx, v1.GetId())
	s.Require().NoError(err)

	// get the attribute by the value fqn for v1
	v, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{fqnBuilder(ns.GetName(), attr.GetName(), v1.GetValue())},
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	s.Require().Error(err)
	s.Nil(v)
	s.Require().ErrorIs(err, db.ErrNotFound)

	// get the attribute by the value fqn for v2
	v, err = s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{fqnBuilder(ns.GetName(), attr.GetName(), v2.GetValue())},
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	s.Require().NoError(err)
	s.NotNil(v)
}

// UnsafeReactivateAttributevalue: active namespace, inactive definition, unsafely active value (fails)
func (s *AttributeFqnSuite) TestGetAttributesByValueFqns_Fails_InactiveDef_ActiveNsAndValue() {
	// create a new namespace
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test_namespace.uk",
	})
	s.Require().NoError(err)

	// give it an attribute with two values
	attr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId: ns.GetId(),
		Name:        "deactivating_attr",
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values:      []string{"value1", "value2"},
	})
	s.Require().NoError(err)
	got, _ := s.db.PolicyClient.GetAttribute(s.ctx, attr.GetId())
	s.Require().NoError(err)
	values := got.GetValues()
	s.Len(values, 2)
	v1 := values[0]

	// deactivate the attribute definition
	_, err = s.db.PolicyClient.DeactivateAttribute(s.ctx, attr.GetId())
	s.Require().NoError(err)

	// unsafely reactivate the first attribute value
	v, err := s.db.PolicyClient.UnsafeReactivateAttributeValue(s.ctx, v1.GetId())
	s.Require().NoError(err)
	s.NotNil(v)

	// get the attribute by the value fqn for v1
	retrieved, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{fqnBuilder(ns.GetName(), attr.GetName(), v1.GetValue())},
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	s.Require().Error(err)
	s.Nil(retrieved)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

// UnsafeReactivateAttributevalue: inactive namespace, inactive definition, unsafely active value (fails)
func (s *AttributeFqnSuite) TestGetAttributesByValueFqns_Fails_InactiveNsAndDef_ActiveValue() {
	// create a new namespace
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test_inactive_namespace.co",
	})
	s.Require().NoError(err)

	// give it an attribute with two values
	attr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId: ns.GetId(),
		Name:        "deactivating_attr",
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values:      []string{"value1", "value2"},
	})
	s.Require().NoError(err)
	got, _ := s.db.PolicyClient.GetAttribute(s.ctx, attr.GetId())
	s.Require().NoError(err)
	values := got.GetValues()
	s.Len(values, 2)
	v1 := values[0]

	// deactivate the namespace
	_, err = s.db.PolicyClient.DeactivateNamespace(s.ctx, ns.GetId())
	s.Require().NoError(err)

	// unsafely reactivate the first attribute value
	v, err := s.db.PolicyClient.UnsafeReactivateAttributeValue(s.ctx, v1.GetId())
	s.Require().NoError(err)
	s.NotNil(v)

	// get the attribute by the value fqn for v1
	retrieved, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{fqnBuilder(ns.GetName(), attr.GetName(), v1.GetValue())},
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	s.Require().Error(err)
	s.Nil(retrieved)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

// UnsafeReactivateNamespace: active namespace, inactive definition, inactive value (fails)
func (s *AttributeFqnSuite) TestGetAttributesByValueFqns_Fails_ActiveDef_InactiveNsAndValue() {
	// create a new namespace
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test_ns_active.uk",
	})
	s.Require().NoError(err)

	// give it an attribute with two values
	attr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId: ns.GetId(),
		Name:        "active_attr",
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values:      []string{"value1", "value2"},
	})
	s.Require().NoError(err)
	got, _ := s.db.PolicyClient.GetAttribute(s.ctx, attr.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	values := got.GetValues()
	s.Len(values, 2)
	v1 := values[0]

	// deactivate the namespace
	ns, err = s.db.PolicyClient.DeactivateNamespace(s.ctx, ns.GetId())
	s.Require().NoError(err)
	s.NotNil(ns)

	// reactivate the namespace (unsafely)
	ns, err = s.db.PolicyClient.UnsafeReactivateNamespace(s.ctx, ns.GetId())
	s.Require().NoError(err)
	s.NotNil(ns)

	gotNs, err := s.db.PolicyClient.GetNamespace(s.ctx, ns.GetId())
	s.Require().NoError(err)
	s.NotNil(gotNs)
	s.True(gotNs.GetActive().GetValue())

	// get the attribute by the value fqn for v1
	retrieved, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{fqnBuilder(ns.GetName(), attr.GetName(), v1.GetValue())},
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	s.Require().Error(err)
	s.Nil(retrieved)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributeFqnSuite) TestGetAttributesByValueFqns_Fails_WithNonValueFqns() {
	nsFqn := fqnBuilder("example.com", "", "")
	attrFqn := fqnBuilder("example.com", "attr1", "")
	v, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{nsFqn},
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	s.Require().Error(err)
	s.Nil(v)
	s.Require().ErrorIs(err, db.ErrFqnMissingValue)

	v, err = s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{attrFqn},
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	s.Require().Error(err)
	s.Nil(v)
	s.Require().ErrorIs(err, db.ErrFqnMissingValue)
}
