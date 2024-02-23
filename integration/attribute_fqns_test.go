package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy/attributes"
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
	suite.Run(t, new(AttributeFqnSuite))
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
	n := fixtures.GetNamespaceKey("example.com")
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
