package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type AttributeFqnSuite struct {
	suite.Suite
	schema string
	f      Fixtures
	db     DBInterface
	ctx    context.Context
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
	suite.Run(t, new(AttributesSuite))
}

func (s *AttributeFqnSuite) SetupSuite() {
	slog.Info("setting up db.AttributeFqn test suite")
	s.ctx = context.Background()
	s.schema = "test_opentdf_attribute_fqn"
	s.db = NewDBInterface(s.schema)
	s.f = NewFixture(s.db)
	s.f.Provision()
}

func (s *AttributeFqnSuite) TearDownSuite() {
	slog.Info("tearing down db.AttributeFqn test suite")
	s.f.TearDown()
}

// Test Create Namespace
func (s *AttributeFqnSuite) TestCreateNamespace() {
	name := "test_namespace"
	id, err := s.db.PolicyClient.CreateNamespace(s.ctx, name)
	s.NoError(err)
	// Verify FQN
	fqn, err := s.db.PolicyClient.GetNamespace(s.ctx, id)
	s.NoError(err)
	s.NotEmpty(fqn.Fqn)
	s.Equal(fqnBuilder(name, "", ""), fqn.Fqn)
}

// Test Create Attribute
func (s *AttributeFqnSuite) TestCreateAttribute() {
	n := fixtures.GetNamespaceKey("example.com")
	name := "test_namespace"
	a, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.AttributeCreateUpdate{
		NamespaceId: n.Id,
		Name:        name,
		Rule:        attributes.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
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
	a := fixtures.GetAttributeKey("example.com/attr/attr1")
	n := fixtures.GetNamespaceKey(a.NamespaceId)
	name := "test_namespace"
	v, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, a.Id, &attributes.ValueCreateUpdate{
		Value: name,
	})
	s.NoError(err)
	// Verify FQN
	fqn, err := s.db.PolicyClient.GetAttributeValue(s.ctx, v.Id)
	s.NoError(err)
	s.NotEmpty(fqn.Fqn)
	s.Equal(fqnBuilder(n.Name, a.Name, v.Value), fqn.Fqn)
}

// Test Get one attribute by fqn
func (s *AttributeFqnSuite) TestGetAttributeByFqn() {
	fqnFixture := "example.com/attr/attr1/value/value1"
	a := fixtures.GetAttributeValueKey(fqnFixture)
	fqn, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, fqnFixture)
	s.NoError(err)
	s.Equal(a.Id, fqn.Id)
	s.Equal(fqnFixture, fqn.Fqn)
	s.Contains(fqn.Values, a.Value)
}

// Test multiple get attributes by multiple fqns
func (s *AttributeFqnSuite) TestGetAttributesByFqns() {
	namespace := "https://testing_multiple_fqns.get"
	attr := "test_attr"
	value := "test_value"
	fqn := fqnBuilder(namespace, attr, value)

	// Create namespace
	nsId, err := s.db.PolicyClient.CreateNamespace(s.ctx, namespace)
	assert.NoError(s.T(), err)

	// Create attribute
	a, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.AttributeCreateUpdate{
		NamespaceId: nsId,
		Name:        attr,
		Rule:        attributes.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	})
	assert.NoError(s.T(), err)

	// Create attribute value
	v, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, a.Id, &attributes.ValueCreateUpdate{
		Value: value,
	})
	assert.NoError(s.T(), err)

	// Get attributes by fqns
	fqns := []string{fqn}
	attrs, err := s.db.PolicyClient.GetAttributesByFqns(s.ctx, fqns)
	assert.NoError(s.T(), err)
	assert.Len(s.T(), attrs, 1)
	val, ok := attrs[fqn]
	assert.True(s.T(), ok)
	assert.Equal(s.T(), a.Id, val.Id)
	assert.Equal(s.T(), fqn, val.Fqn)
	assert.Equal(s.T(), a.Id, val.Values[0].AttributeId)
	assert.Equal(s.T(), v.Id, val.Values[0].Id)
	assert.Equal(s.T(), v.Value, val.Values[0].Value)
	assert.Equal(s.T(), fqn, val.Values[0].Fqn)
}
