package integration

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/internal/fixtures"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type AttributeFqnSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context
}

func fqnBuilder(n string, a string, v string) string {
	fqn := "https://"
	if n != "" && a != "" && v != "" {
		return fqn + n + "/attr/" + a + "/value/" + v
	} else if n != "" && a != "" && v == "" {
		return fqn + n + "/attr/" + a
	} else if n != "" && a == "" {
		return fqn + n
	} else {
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
	c.DB.Schema = "opentdf" // TODO: put this back
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
	s.NoError(err)
	// Verify FQN
	fqn, err := s.db.PolicyClient.GetNamespace(s.ctx, n.Id)
	s.NoError(err)
	s.NotEmpty(fqn.Fqn)
	s.Equal(fqnBuilder(name, "", ""), fqn.Fqn)
}

// Test Create Attribute
func (s *AttributeFqnSuite) TestCreateAttribute() {
	n := s.f.GetNamespaceKey("example.com")
	name := "test_namespace"
	a, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId: n.Id,
		Name:        name,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	})
	s.NoError(err)
	// Verify FQN
	fqn, err := s.db.PolicyClient.GetAttribute(s.ctx, a.Id)
	s.NoError(err)
	s.NotEmpty(fqn.Fqn)
	s.Equal(fqnBuilder(n.Name, a.Name, ""), fqn.Fqn)
}

// Test Create Attribute Value
func (s *AttributeFqnSuite) TestCreateAttributeValue() {
	a := s.f.GetAttributeKey("example.com/attr/attr1")
	n := s.f.GetNamespaceKey("example.com")
	name := "test_namespace"
	v, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, a.Id, &attributes.CreateAttributeValueRequest{
		Value: name,
	})
	s.NoError(err)
	// Verify FQN
	fqn, err := s.db.PolicyClient.GetAttributeValue(s.ctx, v.Id)
	s.NoError(err)
	s.NotEmpty(fqn.Fqn)
	s.Equal(fqnBuilder(n.Name, a.Name, v.Value), fqn.Fqn)
}

// Test Get one attribute by the FQN of one of its values
func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithAttrValueFqn() {
	fqnFixtureKey := "example.com/attr/attr1/value/value1"
	fullFqn := fmt.Sprintf("https://%s", fqnFixtureKey)
	valueFixture := s.f.GetAttributeValueKey(fqnFixtureKey)

	attr, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.NoError(err)

	// there should be only one value
	s.Equal(1, len(attr.Values))

	// the value should match the fixture
	av := attr.Values[0]
	s.Equal(attr.Id, valueFixture.AttributeDefinitionId)
	s.Equal(av.Id, valueFixture.Id)
	s.Equal(av.Value, valueFixture.Value)
	// the value should contain subject mappings
	s.GreaterOrEqual(len(av.SubjectMappings), 3)
}

// Test Get one attribute by the FQN of the attribute definition
func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithAttrFqn() {
	fqnFixtureKey := "example.net/attr/attr1"
	fullFqn := fmt.Sprintf("https://%s", fqnFixtureKey)
	attrFixture := s.f.GetAttributeKey(fqnFixtureKey)

	attr, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.NoError(err)

	// the number of values should match the fixture
	s.Equal(2, len(attr.Values))

	// the attribute should match the fixture
	s.Equal(attr.Id, attrFixture.Id)
	s.Equal(attr.Name, attrFixture.Name)
	s.Equal(attr.Rule.String(), fmt.Sprintf("ATTRIBUTE_RULE_TYPE_ENUM_%s", attrFixture.Rule))
	s.Equal(attr.Active.Value, attrFixture.Active)
}

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
	assert.NoError(s.T(), err)

	// Create attribute
	a, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId: n.Id,
		Name:        attr,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	})
	assert.NoError(s.T(), err)

	// Create attribute value1
	v1, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, a.Id, &attributes.CreateAttributeValueRequest{
		Value: value1,
	})
	assert.NoError(s.T(), err)

	// Get attributes by fqns with a solo value
	fqns := []string{fqn1}
	attributeAndValue, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: fqns,
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	assert.NoError(s.T(), err)

	// Verify attribute1 is sole attribute
	assert.Len(s.T(), attributeAndValue, 1)
	val, ok := attributeAndValue[fqn1]
	assert.True(s.T(), ok)
	assert.Equal(s.T(), a.Id, val.Attribute.Id)

	assert.Equal(s.T(), v1.Id, val.Attribute.Values[0].Id)
	assert.Equal(s.T(), v1.Value, val.Value.Value)

	assert.Equal(s.T(), v1.Value, val.Attribute.Values[0].Value)
	assert.Equal(s.T(), v1.Id, val.Value.Id)

	// Create attribute value2
	v2, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, a.Id, &attributes.CreateAttributeValueRequest{
		Value: value2,
	})
	assert.NoError(s.T(), err)

	// Get attributes by fqns with two values
	fqns = []string{fqn1, fqn2}
	attributeAndValue, err = s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: fqns,
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	assert.NoError(s.T(), err)
	assert.Len(s.T(), attributeAndValue, 2)

	val, ok = attributeAndValue[fqn2]
	assert.True(s.T(), ok)
	assert.Equal(s.T(), a.Id, val.Attribute.Id)

	for _, v := range val.Attribute.Values {
		if v.Id == v1.Id {
			assert.Equal(s.T(), v1.Id, v.Id)
			assert.Equal(s.T(), v1.Value, v.Value)
		} else if v.Id == v2.Id {
			assert.Equal(s.T(), v2.Id, v.Id)
			assert.Equal(s.T(), v2.Value, v.Value)
		} else {
			assert.Fail(s.T(), "unexpected value", v)
		}
	}
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
	assert.Error(s.T(), err)
	assert.Nil(s.T(), v)
	assert.ErrorIs(s.T(), err, db.ErrFqnMissingValue)

	v, err = s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{attrFqn},
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	assert.Error(s.T(), err)
	assert.Nil(s.T(), v)
	assert.ErrorIs(s.T(), err, db.ErrFqnMissingValue)
}
