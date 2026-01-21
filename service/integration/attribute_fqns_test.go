package integration

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/resourcemapping"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	policydb "github.com/opentdf/platform/service/policy/db"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
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
	s.db = fixtures.NewDBInterface(s.ctx, c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision(s.ctx)
}

func (s *AttributeFqnSuite) TearDownSuite() {
	slog.Info("tearing down db.AttributeFqn test suite")
	s.f.TearDown(s.ctx)
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
	fullFqn := "https://" + fqnFixtureKey
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
	fullFqn := strings.ToUpper("https://" + fqnFixtureKey)
	valueFixture := s.f.GetAttributeValueKey(fqnFixtureKey)
	key := s.f.GetKasRegistryServerKeys("kas_key_1")

	grant, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &attributes.ValueKey{
		KeyId:   key.ID,
		ValueId: valueFixture.ID,
	})
	s.Require().NoError(err)
	s.NotNil(grant)

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
			// the value should contain the grant
			s.GreaterOrEqual(len(v.GetGrants()), 1)
			found := false
			for _, g := range v.GetGrants() {
				if g.GetId() == key.KeyAccessServerID {
					found = true
					break
				}
			}
			s.True(found)
		}
	}
}

// Test Get one attribute by the FQN of the attribute definition
func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithAttrFqn() {
	fqnFixtureKey := "example.net/attr/attr1"
	fullFqn := "https://" + fqnFixtureKey
	attrFixture := s.f.GetAttributeKey(fqnFixtureKey)

	attr, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.Require().NoError(err)

	// the number of values should match the fixture
	s.Len(attr.GetValues(), 2)

	// the attribute should match the fixture
	s.Equal(attr.GetId(), attrFixture.ID)
	s.Equal(attr.GetName(), attrFixture.Name)
	s.Equal(attr.GetRule().String(), "ATTRIBUTE_RULE_TYPE_ENUM_"+attrFixture.Rule)
	s.Equal(attr.GetActive().GetValue(), attrFixture.Active)
	s.Empty(attr.GetKasKeys())
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithAttributeDefKeysAssociated() {
	// Create a attribute
	namespace := "associate_attribute_with_key_namespace"
	attributeName := "associate_attribute_with_key_def"

	// Create namespace
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: namespace,
	})
	s.Require().NoError(err)
	s.NotNil(ns)

	// Create attribute
	attr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId: ns.GetId(),
		Name:        attributeName,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	})
	s.Require().NoError(err)
	s.NotNil(attr)

	fullFqn := fqnBuilder(namespace, attributeName, "")
	kasKeyFixture := s.f.GetKasRegistryServerKeys("kas_key_1")
	kasKey, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{
		Id: kasKeyFixture.ID,
	})
	s.Require().NoError(err)

	attr, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.Require().NoError(err)
	s.Empty(attr.GetKasKeys())

	keyResp, err := s.db.PolicyClient.AssignPublicKeyToAttribute(s.ctx, &attributes.AttributeKey{
		AttributeId: attr.GetId(),
		KeyId:       kasKey.GetKey().GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(keyResp)

	attr, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.Require().NoError(err)

	// Key checks
	s.Len(attr.GetKasKeys(), 1)
	s.Equal(kasKey.GetKey().GetKeyId(), attr.GetKasKeys()[0].GetPublicKey().GetKid())
	validateSimpleKasKey(&s.Suite, kasKey, attr.GetKasKeys()[0])

	// Remove association
	_, err = s.db.PolicyClient.RemovePublicKeyFromAttribute(s.ctx, &attributes.AttributeKey{
		AttributeId: attr.GetId(),
		KeyId:       kasKey.GetKey().GetId(),
	})
	s.Require().NoError(err)

	// cascade delete will remove namespaces and all associated attributes and values
	_, err = s.db.PolicyClient.UnsafeDeleteNamespace(s.ctx, ns, ns.GetFqn())
	s.Require().NoError(err)
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithAttributeValueKeysAssociated() {
	fqnFixtureKey := "example.net/attr/attr1"
	kasKeyFixture := s.f.GetKasRegistryServerKeys("kas_key_1")
	kasKey, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{
		Id: kasKeyFixture.ID,
	})
	s.Require().NoError(err)
	s.NotNil(kasKey)

	fullFqn := "https://" + fqnFixtureKey

	attr, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.Require().NoError(err)

	// the number of values should match the fixture
	s.Len(attr.GetValues(), 2)
	s.Empty(attr.GetKasKeys())
	for _, v := range attr.GetValues() {
		s.Empty(v.GetKasKeys())
	}

	// Associate key with attribute.
	keyResp, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &attributes.ValueKey{
		ValueId: attr.GetValues()[0].GetId(),
		KeyId:   kasKey.GetKey().GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(keyResp)

	// Associate value 2 with the same key
	keyResp, err = s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &attributes.ValueKey{
		ValueId: attr.GetValues()[1].GetId(),
		KeyId:   kasKey.GetKey().GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(keyResp)

	attr, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.Require().NoError(err)

	// the number of values should match the fixture
	s.Len(attr.GetValues(), 2)

	// Key checks
	s.Empty(attr.GetKasKeys())
	for _, v := range attr.GetValues() {
		s.Len(v.GetKasKeys(), 1)
		validateSimpleKasKey(&s.Suite, kasKey, v.GetKasKeys()[0])

		_, err = s.db.PolicyClient.RemovePublicKeyFromValue(s.ctx, &attributes.ValueKey{
			ValueId: v.GetId(),
			KeyId:   kasKey.GetKey().GetId(),
		})
		s.Require().NoError(err)
	}
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithKeysAssociatedWithNamespace() {
	fqnFixtureKey := "example.net/attr/attr1"
	kasKeyFixture := s.f.GetKasRegistryServerKeys("kas_key_1")
	kasKey, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{
		Id: kasKeyFixture.ID,
	})
	s.Require().NoError(err)
	fullFqn := "https://" + fqnFixtureKey

	attr, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.Require().NoError(err)

	// the number of values should match the fixture
	s.Len(attr.GetValues(), 2)
	s.Empty(attr.GetNamespace().GetKasKeys())

	// Associate key with attribute.
	keyResp, err := s.db.PolicyClient.AssignPublicKeyToNamespace(s.ctx, &namespaces.NamespaceKey{
		NamespaceId: attr.GetNamespace().GetId(),
		KeyId:       kasKey.GetKey().GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(keyResp)

	attr, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.Require().NoError(err)

	// the number of values should match the fixture
	s.Len(attr.GetValues(), 2)

	// Key checks
	s.Empty(attr.GetKasKeys())
	s.Len(attr.GetNamespace().GetKasKeys(), 1)
	validateSimpleKasKey(&s.Suite, kasKey, attr.GetNamespace().GetKasKeys()[0])

	_, err = s.db.PolicyClient.RemovePublicKeyFromNamespace(s.ctx, &namespaces.NamespaceKey{
		NamespaceId: attr.GetNamespace().GetId(),
		KeyId:       kasKey.GetKey().GetId(),
	})
	s.Require().NoError(err)
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithKeysAssociatedAttributes_MultipleAttributes() {
	fqnFixtureKey := "example.net/attr/attr1"
	fqnFixtureKeyTwo := "example.net/attr/attr2"
	fullFqn := "https://" + fqnFixtureKey
	fullFqn2 := "https://" + fqnFixtureKeyTwo

	kasKeyFixture1 := s.f.GetKasRegistryServerKeys("kas_key_1")
	kasKey, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{
		Id: kasKeyFixture1.ID,
	})
	s.Require().NoError(err)

	kasKeyFixture2 := s.f.GetKasRegistryServerKeys("kas_key_2")
	kasKey2, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{
		Id: kasKeyFixture2.ID,
	})
	s.Require().NoError(err)

	attr, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.Require().NoError(err)
	s.Len(attr.GetValues(), 2)
	s.Empty(attr.GetKasKeys())

	// Associate key with attribute.
	keyResp, err := s.db.PolicyClient.AssignPublicKeyToAttribute(s.ctx, &attributes.AttributeKey{
		AttributeId: attr.GetId(),
		KeyId:       kasKey.GetKey().GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(keyResp)

	attr, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn2)
	s.Require().NoError(err)
	s.Empty(attr.GetValues())
	s.Empty(attr.GetKasKeys())

	// Associate key with attribute.
	keyResp, err = s.db.PolicyClient.AssignPublicKeyToAttribute(s.ctx, &attributes.AttributeKey{
		AttributeId: attr.GetId(),
		KeyId:       kasKey2.GetKey().GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(keyResp)

	// Get attribute 1
	attr, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	attrOneID := attr.GetId()
	s.Require().NoError(err)
	s.Len(attr.GetKasKeys(), 1)
	validateSimpleKasKey(&s.Suite, kasKey, attr.GetKasKeys()[0])

	// Get attribute 2
	attr, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn2)
	attrTwoID := attr.GetId()
	s.Require().NoError(err)
	s.Len(attr.GetKasKeys(), 1)
	validateSimpleKasKey(&s.Suite, kasKey2, attr.GetKasKeys()[0])

	_, err = s.db.PolicyClient.RemovePublicKeyFromAttribute(s.ctx, &attributes.AttributeKey{
		AttributeId: attrOneID,
		KeyId:       kasKey.GetKey().GetId(),
	})
	s.Require().NoError(err)

	_, err = s.db.PolicyClient.RemovePublicKeyFromAttribute(s.ctx, &attributes.AttributeKey{
		AttributeId: attrTwoID,
		KeyId:       kasKey2.GetKey().GetId(),
	})
	s.Require().NoError(err)
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithKeyAccessGrants_Definitions() {
	key := s.f.GetKasRegistryServerKeys("kas_key_1")
	key2 := s.f.GetKasRegistryServerKeys("kas_key_2")
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

	// make a first grant association to the attribute definition
	keyMapping, err := s.db.PolicyClient.AssignPublicKeyToAttribute(s.ctx, &attributes.AttributeKey{
		KeyId:       key.ID,
		AttributeId: a.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(keyMapping)

	keyMapping2, err := s.db.PolicyClient.AssignPublicKeyToAttribute(s.ctx, &attributes.AttributeKey{
		KeyId:       key2.ID,
		AttributeId: a.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(keyMapping2)

	// get the attribute by the fqn of the attribute definition
	got, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, "https://example.org/attr/attr_with_grants")
	s.Require().NoError(err)
	s.NotNil(got)

	// ensure the attribute has the grants
	s.Len(got.GetGrants(), 1)
	// Ensure we get 2 public keys because it's the same KAS
	s.Len(got.GetGrants()[0].GetPublicKey().GetCached().GetKeys(), 2)
	keyIDs := []string{key.KeyID, key2.KeyID}
	s.Contains(keyIDs, got.GetGrants()[0].GetPublicKey().GetCached().GetKeys()[0].GetKid())
	s.Contains(keyIDs, got.GetGrants()[0].GetPublicKey().GetCached().GetKeys()[1].GetKid())
	grantIDs := []string{key.KeyAccessServerID, key2.KeyAccessServerID}
	s.Contains(grantIDs, got.GetGrants()[0].GetId())
	pemIsPresent := false

	for _, g := range got.GetGrants() {
		if g.GetId() == key2.KeyAccessServerID {
			decodedPubKey, err := base64.StdEncoding.DecodeString(key2.PublicKeyCtx)
			s.Require().NoError(err)
			s.JSONEq(
				strings.TrimRight(string(decodedPubKey), "\n"),
				fmt.Sprintf("{\"pem\":\"%s\"}", base64.StdEncoding.EncodeToString([]byte(g.GetPublicKey().GetCached().GetKeys()[0].GetPem()))),
			)
			s.Equal(g.GetId(), key2.KeyAccessServerID)
			pemIsPresent = true
		}
	}
	s.True(pemIsPresent)

	// get the attribute by the fqn of one of its values and ensure the grants are present on the definition
	got, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, "https://example.org/attr/attr_with_grants/value/value1")
	s.Require().NoError(err)
	s.NotNil(got)
	s.Len(got.GetGrants(), 1)

	// assign a KAS to the value and make sure it is not granted to the definition
	grant3, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &attributes.ValueKey{
		KeyId:   key.ID,
		ValueId: got.GetValues()[0].GetId(),
	})
	s.NotNil(grant3)
	s.Require().NoError(err)

	got, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, "https://example.org/attr/attr_with_grants/value/value1")
	s.Require().NoError(err)
	s.NotNil(got)
	s.Len(got.GetGrants(), 1)
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithKeyAccessGrants_Values() {
	key := s.f.GetKasRegistryServerKeys("kas_key_1")
	key2 := s.f.GetKasRegistryServerKeys("kas_key_2")
	attrName := "attr_with_values_grants"
	attrFqn := "https://example.org/attr/" + attrName
	// create attribute under fixture namespace id
	n := s.f.GetNamespaceKey("example.org")
	a, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId: n.ID,
		Name:        attrName,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values:      []string{"value1", "value2"},
	})
	s.Require().NoError(err)
	s.NotNil(a)
	valueFirst := a.GetValues()[0]
	valueSecond := a.GetValues()[1]

	// get each by FQN and ensure no grants are present for definition or values
	got, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, attrFqn)
	s.Require().NoError(err)
	s.NotNil(got)
	s.Empty(got.GetGrants())

	for _, v := range got.GetValues() {
		s.Empty(v.GetGrants())
	}

	val1Fqn := fmt.Sprintf("%s/value/%s", attrFqn, valueFirst.GetValue())
	val2Fqn := fmt.Sprintf("%s/value/%s", attrFqn, valueSecond.GetValue())

	got, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, val1Fqn)
	s.Require().NoError(err)
	s.NotNil(got)
	s.Empty(got.GetGrants())
	s.Empty(got.GetValues()[0].GetGrants())

	got, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, val2Fqn)
	s.Require().NoError(err)
	s.NotNil(got)
	s.Empty(got.GetGrants())
	s.Empty(got.GetValues()[0].GetGrants())

	// make a grant association to the first value
	grant, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &attributes.ValueKey{
		KeyId:   key.ID,
		ValueId: valueFirst.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(grant)

	grant2, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &attributes.ValueKey{
		KeyId:   key2.ID,
		ValueId: valueSecond.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(grant2)

	// get the attribute by the fqn of the attribute definition
	got, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, attrFqn)
	s.Require().NoError(err)
	s.NotNil(got)

	// ensure the attribute has no definition grants
	s.Empty(got.GetGrants())

	// get the attribute by the fqn of one of its values and ensure the grants are present
	got, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, val1Fqn)
	s.Require().NoError(err)
	s.NotNil(got)
	s.Len(got.GetValues(), 2)
	s.Empty(got.GetGrants())

	for _, v := range got.GetValues() {
		grants := v.GetGrants()
		s.Require().Len(grants, 1)
		firstGrant := grants[0]
		switch v.GetId() {
		case valueFirst.GetId():
			s.Equal(key.KeyAccessServerID, firstGrant.GetId())
		case valueSecond.GetId():
			s.Equal(key2.KeyAccessServerID, firstGrant.GetId())
		default:
			s.Fail("unexpected value", v)
		}
	}
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithKeyAccessGrants_DefAndValuesGrantsBoth() {
	key := s.f.GetKasRegistryServerKeys("kas_key_1")
	key2 := s.f.GetKasRegistryServerKeys("kas_key_2")
	key3 := s.f.GetKasRegistryServerKeys("kas_key_3")
	attrName := "def_and_vals_grants"
	attrFqn := "https://example.org/attr/" + attrName
	// create attribute under fixture namespace id
	n := s.f.GetNamespaceKey("example.org")
	a, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId: n.ID,
		Name:        attrName,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values:      []string{"value1", "value2"},
	})
	s.Require().NoError(err)
	s.NotNil(a)
	valueFirst := a.GetValues()[0]
	valueSecond := a.GetValues()[1]

	// get each by FQN and ensure no grants are present for definition or values
	got, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, attrFqn)
	s.Require().NoError(err)
	s.NotNil(got)
	s.Empty(got.GetGrants())

	for _, v := range got.GetValues() {
		s.Empty(v.GetGrants())
	}

	val1Fqn := fmt.Sprintf("%s/value/%s", attrFqn, valueFirst.GetValue())
	val2Fqn := fmt.Sprintf("%s/value/%s", attrFqn, valueSecond.GetValue())

	got, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, val1Fqn)
	s.Require().NoError(err)
	s.NotNil(got)
	s.Empty(got.GetGrants())
	s.Empty(got.GetValues()[0].GetGrants())

	got, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, val2Fqn)
	s.Require().NoError(err)
	s.NotNil(got)
	s.Empty(got.GetGrants())
	s.Empty(got.GetValues()[0].GetGrants())

	// make a grant association to the first value
	grant, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &attributes.ValueKey{
		KeyId:   key.ID,
		ValueId: valueFirst.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(grant)

	grant2, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &attributes.ValueKey{
		KeyId:   key2.ID,
		ValueId: valueSecond.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(grant2)

	defGrant, err := s.db.PolicyClient.AssignPublicKeyToAttribute(s.ctx, &attributes.AttributeKey{
		KeyId:       key3.ID,
		AttributeId: a.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(defGrant)

	// get the attribute by the fqn of the attribute definition
	got, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, attrFqn)
	s.Require().NoError(err)
	s.NotNil(got)

	// ensure the attribute has exactly one definition grant
	s.Len(got.GetGrants(), 1)
	s.Equal(key3.KeyAccessServerID, got.GetGrants()[0].GetId())

	// get the attribute by the fqn of one of its values and ensure the grants are present
	got, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, val1Fqn)
	s.Require().NoError(err)
	s.NotNil(got)
	s.Len(got.GetValues(), 2)
	s.Len(got.GetGrants(), 1)
	s.Equal(key3.KeyAccessServerID, got.GetGrants()[0].GetId())

	for _, v := range got.GetValues() {
		switch v.GetId() {
		case valueFirst.GetId():
			s.Require().Len(v.GetGrants(), 1)
			s.Equal(key.KeyAccessServerID, v.GetGrants()[0].GetId())
		case valueSecond.GetId():
			s.Require().Len(v.GetGrants(), 1)
			s.Equal(key2.KeyAccessServerID, v.GetGrants()[0].GetId())
		default:
			s.Fail("unexpected value", v)
		}
	}
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithKeyAccessGrants_NamespaceGrants() {
	key := s.f.GetKasRegistryServerKeys("kas_key_1")
	// create a new namespace
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test_fqn_namespace.net",
	})
	s.Require().NoError(err)
	s.NotNil(ns)

	// give it attributes and values
	attr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId: ns.GetId(),
		Name:        "test_attr",
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values:      []string{"value1", "value2"},
	})
	s.Require().NoError(err)
	s.NotNil(attr)

	// make a grant association to the namespace
	grant, err := s.db.PolicyClient.AssignPublicKeyToNamespace(s.ctx, &namespaces.NamespaceKey{
		KeyId:       key.ID,
		NamespaceId: ns.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(grant)

	// get the attribute by the fqn of the attribute definition
	got, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, "https://test_fqn_namespace.net/attr/test_attr")
	s.Require().NoError(err)
	s.NotNil(got)

	// ensure the namespace has the grants
	gotNs := got.GetNamespace()
	grants := gotNs.GetGrants()
	s.Len(grants, 1)
	s.Equal(key.KeyAccessServerID, grants[0].GetId())
}

// for all the big tests set up:
// attribute name is "test_attr", values are "value1" and "value2"
// kas uris granted to each are "https://testing_granted_<ns | attr | val1 | val1>.com/<ns>/kas",
type KasAssociations struct {
	kasID   string
	uri     string
	keyID   string
	keyUUID string
}
type bigSetup struct {
	attrFqn string
	nsID    string
	attrID  string
	val1ID  string
	val2ID  string
	rms     map[string]struct {
		Terms   []string
		GroupID string
	}
	kasAssociations map[string]*KasAssociations
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_SameResultsWhetherAttrOrValueFqnUsed() {
	ns := "test_fqn_all_consistent.gov"
	setup := s.bigTestSetup(ns)

	fqns := []string{
		setup.attrFqn,
		setup.attrFqn + "/value/value1",
		setup.attrFqn + "/value/value2",
	}

	retrieved := make([]*policy.Attribute, len(fqns))
	for i, fqn := range fqns {
		got, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, fqn)
		s.Require().NoError(err)
		s.NotNil(got)
		retrieved[i] = got
	}

	for i, single := range retrieved {
		for j := i + 1; j < len(retrieved); j++ {
			comparator := retrieved[j]
			s.True(proto.Equal(single, comparator))
		}
	}
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_AllIndividualFqnsSetOnResults() {
	ns := "every_fqn_populated.io"
	setup := s.bigTestSetup(ns)

	got, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, setup.attrFqn)
	s.Require().NoError(err)
	s.NotNil(got)

	s.True(strings.HasPrefix(got.GetFqn(), "https://"))
	s.Contains(got.GetFqn(), ns)
	s.Contains(got.GetFqn(), "attr/test_attr")
	s.Equal(got.GetNamespace().GetFqn(), "https://"+ns)
	s.Equal(got.GetValues()[0].GetFqn(), setup.attrFqn+"/value/value1")
	s.Equal(got.GetValues()[1].GetFqn(), setup.attrFqn+"/value/value2")
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithKeyAccessGrants_ProperOnAllObjects() {
	ns := "test_all_grants_all_fqns.gov"
	setup := s.bigTestSetup(ns)

	got, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, setup.attrFqn)
	s.Require().NoError(err)
	s.NotNil(got)

	// Note: see setup for the kas uri schema

	// ensure the namespace has the grants
	s.Len(got.GetNamespace().GetGrants(), 1)
	nsGrant := got.GetNamespace().GetGrants()[0]
	s.Equal(setup.kasAssociations[got.GetNamespace().GetId()].kasID, nsGrant.GetId())
	s.Equal(fmt.Sprintf("https://testing_granted_ns.com/%s/kas", ns), nsGrant.GetUri())

	// ensure the attribute has the grants
	s.Len(got.GetGrants(), 1)
	attrGrant := got.GetGrants()[0]
	s.Equal(setup.kasAssociations[got.GetId()].kasID, attrGrant.GetId())
	s.Equal(fmt.Sprintf("https://testing_granted_attr.com/%s/kas", ns), attrGrant.GetUri())

	// ensure the first value has the grants
	val1 := got.GetValues()[0]
	s.Len(val1.GetGrants(), 1)
	val1Grant := val1.GetGrants()[0]
	s.Equal(setup.kasAssociations[val1.GetId()].kasID, val1Grant.GetId())
	s.Equal(fmt.Sprintf("https://testing_granted_val.com/%s/kas", ns), val1Grant.GetUri())

	// ensure the second value has the grants
	val2 := got.GetValues()[1]
	s.Len(val2.GetGrants(), 1)
	val2Grant := val2.GetGrants()[0]
	s.Equal(setup.kasAssociations[val2.GetId()].kasID, val2Grant.GetId())
	s.Equal(fmt.Sprintf("https://testing_granted_val2.com/%s/kas", ns), val2Grant.GetUri())

	// remove grants from all objects
	_, err = s.db.PolicyClient.RemovePublicKeyFromNamespace(s.ctx, &namespaces.NamespaceKey{
		KeyId:       setup.kasAssociations[got.GetNamespace().GetId()].keyUUID,
		NamespaceId: got.GetNamespace().GetId(),
	})
	s.Require().NoError(err)

	_, err = s.db.PolicyClient.RemovePublicKeyFromAttribute(s.ctx, &attributes.AttributeKey{
		KeyId:       setup.kasAssociations[got.GetId()].keyUUID,
		AttributeId: got.GetId(),
	})
	s.Require().NoError(err)

	_, err = s.db.PolicyClient.RemovePublicKeyFromValue(s.ctx, &attributes.ValueKey{
		KeyId:   setup.kasAssociations[val1.GetId()].keyUUID,
		ValueId: val1.GetId(),
	})
	s.Require().NoError(err)

	_, err = s.db.PolicyClient.RemovePublicKeyFromValue(s.ctx, &attributes.ValueKey{
		KeyId:   setup.kasAssociations[val2.GetId()].keyUUID,
		ValueId: val2.GetId(),
	})
	s.Require().NoError(err)

	// ensure the grants are removed from all objects
	got, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, setup.attrFqn)
	s.Require().NoError(err)
	s.NotNil(got)
	s.Empty(got.GetNamespace().GetGrants())
	s.Empty(got.GetGrants())
	s.Empty(got.GetValues()[0].GetGrants())
	s.Empty(got.GetValues()[1].GetGrants())
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_SubjectMappingsOnAllValues() {
	ns := "test_all_subject_mappings.gov"
	setup := s.bigTestSetup(ns)

	got, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, setup.attrFqn)
	s.Require().NoError(err)
	s.NotNil(got)

	// ensure the first value has expected subject mappings
	val1 := got.GetValues()[0]
	s.Len(val1.GetSubjectMappings(), 1)
	val1SM := val1.GetSubjectMappings()[0]
	s.Equal(s.f.GetSubjectConditionSetKey("subject_condition_set1").ID, val1SM.GetSubjectConditionSet().GetId())
	s.Len(val1SM.GetActions(), 2)
	foundRead := false
	foundUpload := false
	for _, action := range val1SM.GetActions() {
		if action.GetId() == s.f.GetStandardAction("read").GetId() {
			foundRead = true
		}
		if action.GetName() == fixtureActionCustomUpload.GetName() {
			foundUpload = true
		}
	}
	s.True(foundRead)
	s.True(foundUpload)

	// ensure the second value has both expected subject mappings
	val2 := got.GetValues()[1]
	s.Len(val2.GetSubjectMappings(), 2)
	val2SM := val2.GetSubjectMappings()[0]
	s.Equal(s.f.GetSubjectConditionSetKey("subject_condition_set2").ID, val2SM.GetSubjectConditionSet().GetId())
	s.Len(val2SM.GetActions(), 1)
	s.Equal(val2SM.GetActions()[0].GetName(), s.f.GetStandardAction("create").GetName())

	val2SM2 := val2.GetSubjectMappings()[1]
	s.Equal(s.f.GetSubjectConditionSetKey("subject_condition_set3").ID, val2SM2.GetSubjectConditionSet().GetId())
	s.Len(val2SM2.GetActions(), 2)
	foundRead = false
	foundCreate := false
	for _, action := range val2SM2.GetActions() {
		if action.GetId() == s.f.GetStandardAction("read").GetId() {
			foundRead = true
		}
		if action.GetId() == s.f.GetStandardAction("create").GetId() {
			foundCreate = true
		}
	}
	s.True(foundRead)
	s.True(foundCreate)
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_ResourceMappingsReturned() {
	ns := "test_fqn_resource_mapping.gov"
	setup := s.bigTestSetup(ns)

	got, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, setup.attrFqn)
	s.Require().NoError(err)
	s.NotNil(got)

	// ensure the first value has expected resource mappings
	val1 := got.GetValues()[0]
	s.Len(val1.GetResourceMappings(), 2)
	for _, rm := range val1.GetResourceMappings() {
		expected, ok := setup.rms[rm.GetId()]
		s.True(ok)
		if expected.GroupID == "" {
			s.Nil(rm.GetGroup())
		} else {
			s.Equal(expected.GroupID, rm.GetGroup().GetId())
		}
		s.Len(rm.GetTerms(), len(expected.Terms))
		s.ElementsMatch(rm.GetTerms(), expected.Terms)
	}

	// ensure the second value has no resource mappings
	val2 := got.GetValues()[1]
	s.Empty(val2.GetResourceMappings())
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

func (s *AttributeFqnSuite) TestGetAttributesByValueFqns_FiltersInactiveValues_FromDefinition() {
	namespace := "filter_inactive_values.get"
	attr := "test_attr"
	value1 := "test_value"
	value2 := "test_value_2"
	fqn1 := fqnBuilder(namespace, attr, value1)

	// Create namespace
	n, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: namespace,
	})
	s.Require().NoError(err)

	// Create attribute
	a, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId:    n.GetId(),
		Name:           attr,
		Rule:           policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		AllowTraversal: wrapperspb.Bool(true),
	})
	s.Require().NoError(err)

	// Create attribute values
	v1, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, a.GetId(), &attributes.CreateAttributeValueRequest{
		Value: value1,
	})
	s.Require().NoError(err)

	v2, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, a.GetId(), &attributes.CreateAttributeValueRequest{
		Value: value2,
	})
	s.Require().NoError(err)

	// Deactivate the second value
	deactivated, err := s.db.PolicyClient.DeactivateAttributeValue(s.ctx, v2.GetId())
	s.Require().NoError(err)
	s.NotNil(deactivated)

	// Get attributes by FQN of the active value
	attributeAndValue, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{fqn1},
	})
	s.Require().NoError(err)
	s.Len(attributeAndValue, 1)

	val, ok := attributeAndValue[fqn1]
	s.True(ok)
	s.Equal(a.GetId(), val.GetAttribute().GetId())
	s.Equal(v1.GetId(), val.GetValue().GetId())

	values := val.GetAttribute().GetValues()
	s.Len(values, 1)
	s.Equal(v1.GetId(), values[0].GetId())
	s.Equal(v1.GetValue(), values[0].GetValue())
}

func (s *AttributeFqnSuite) TestGetAttributesByValueFqns_NormalizesLowerCase() {
	namespace := "TESTLOWERCASE.get"
	attr := "test_attr"
	value1 := "test_value"
	value2 := "test_value_2"
	upperNsFqn1 := fqnBuilder(namespace, attr, value1)
	upperNsFqn2 := fqnBuilder(namespace, attr, value2)

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
	fqns := []string{upperNsFqn1}
	attributeAndValue, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: fqns,
	})
	s.Require().NoError(err)

	// Verify attribute1 is sole attribute
	s.Len(attributeAndValue, 1)
	// upper case not found
	val, ok := attributeAndValue[upperNsFqn1]
	s.False(ok)
	s.Nil(val)
	// lower case found
	lower := strings.ToLower(upperNsFqn1)
	val, ok = attributeAndValue[lower]
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
	fqns = []string{upperNsFqn1, upperNsFqn2}
	attributeAndValue, err = s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: fqns,
	})
	s.Require().NoError(err)
	s.Len(attributeAndValue, 2)

	// upper case fqn not found
	val, ok = attributeAndValue[upperNsFqn2]
	s.False(ok)
	s.Nil(val)
	// lower case fqn found
	val, ok = attributeAndValue[strings.ToLower(upperNsFqn2)]
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
	})
	s.Require().Error(err)
	s.Nil(v)
	s.Require().ErrorIs(err, db.ErrNotFound)

	// get the attribute by the value fqn for v2
	v, err = s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{fqnBuilder(ns.GetName(), attr.GetName(), v2.GetValue())},
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
	})
	s.Require().Error(err)
	s.Nil(v)
	s.Require().ErrorIs(err, db.ErrNotFound)

	// get the attribute by the value fqn for v2
	v, err = s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{fqnBuilder(ns.GetName(), attr.GetName(), v2.GetValue())},
	})
	s.Require().Error(err)
	s.Nil(v)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributeFqnSuite) TestGetAttributesByValueFqns_MixedFoundAndMissingValue_DifferentDefinitions_Succeeds() {
	// create a new namespace
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test-fqn-namespace.active",
	})
	s.Require().NoError(err)

	// create attribute with one value (found)
	attrFound, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId:    ns.GetId(),
		Name:           "mixed_attr_found",
		Rule:           policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values:         []string{"value1"},
		AllowTraversal: wrapperspb.Bool(true),
	})
	s.Require().NoError(err)

	gotFound, err := s.db.PolicyClient.GetAttribute(s.ctx, attrFound.GetId())
	s.Require().NoError(err)
	s.Len(gotFound.GetValues(), 1)
	foundValue := gotFound.GetValues()[0]

	// create attribute with no values (missing)
	attrMissing, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId:    ns.GetId(),
		Name:           "mixed_attr_missing",
		Rule:           policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		AllowTraversal: wrapperspb.Bool(true),
	})
	s.Require().NoError(err)

	foundFqn := fqnBuilder(ns.GetName(), attrFound.GetName(), foundValue.GetValue())
	missingFqn := fqnBuilder(ns.GetName(), attrMissing.GetName(), "missing_value")

	retrieved, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{foundFqn, missingFqn},
	})
	s.Require().NoError(err)
	s.Len(retrieved, 2)

	found, ok := retrieved[foundFqn]
	s.True(ok)
	s.NotNil(found)
	s.Equal(attrFound.GetId(), found.GetAttribute().GetId())
	s.NotNil(found.GetValue())
	s.Equal(foundValue.GetId(), found.GetValue().GetId())

	missing, ok := retrieved[missingFqn]
	s.True(ok)
	s.NotNil(missing)
	s.Equal(attrMissing.GetId(), missing.GetAttribute().GetId())
	s.Nil(missing.GetValue())
}

func (s *AttributeFqnSuite) TestGetAttributesByValueFqns_MixedMissingValue_InactiveDefinition_Fails() {
	// create a new namespace
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test-fqn-namespace.inactive",
	})
	s.Require().NoError(err)

	// give it an attribute with two values
	attr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId:    ns.GetId(),
		Name:           "inactive_attr",
		Rule:           policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values:         []string{"value1", "value2"},
		AllowTraversal: wrapperspb.Bool(true),
	})
	s.Require().NoError(err)
	got, err := s.db.PolicyClient.GetAttribute(s.ctx, attr.GetId())
	s.Require().NoError(err)
	s.Len(got.GetValues(), 2)
	v1 := got.GetValues()[0]

	// deactivate the attribute definition
	_, err = s.db.PolicyClient.DeactivateAttribute(s.ctx, attr.GetId())
	s.Require().NoError(err)

	foundFqn := fqnBuilder(ns.GetName(), attr.GetName(), v1.GetValue())
	missingFqn := fqnBuilder(ns.GetName(), attr.GetName(), "missing_value")

	retrieved, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{foundFqn, missingFqn},
	})
	s.Require().Error(err)
	s.Nil(retrieved)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributeFqnSuite) TestGetAttributesByValueFqns_MixedMissingValue_AllowTraversalMismatch_Fails() {
	// create a new namespace
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test-fqn-namespace.mixed-traversal",
	})
	s.Require().NoError(err)

	// create attribute with allow_traversal=true
	attrAllow, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId:    ns.GetId(),
		Name:           "mixed_attr_allow",
		Rule:           policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		AllowTraversal: wrapperspb.Bool(true),
	})
	s.Require().NoError(err)

	// create attribute with allow_traversal=false
	attrDeny, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId: ns.GetId(),
		Name:        "mixed_attr_deny",
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	})
	s.Require().NoError(err)

	allowMissingFqn := fqnBuilder(ns.GetName(), attrAllow.GetName(), "missing_value")
	denyMissingFqn := fqnBuilder(ns.GetName(), attrDeny.GetName(), "missing_value")

	retrieved, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{allowMissingFqn, denyMissingFqn},
	})
	s.Require().Error(err)
	s.Nil(retrieved)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributeFqnSuite) TestGetAttributesByValueFqns_Fails_MissingValueAndDefinition() {
	// create a new namespace
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test-missing-attr.example",
	})
	s.Require().NoError(err)

	missingFqn := fqnBuilder(ns.GetName(), "missing_attr", "missing_value")
	retrieved, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{missingFqn},
	})
	s.Require().Error(err)
	s.Nil(retrieved)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributeFqnSuite) TestGetAttributesByValueFqns_Fails_WithInactiveValue_ActiveDefinition() {
	// create a new namespace
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: "test-fqn-namespace.inactive-value",
	})
	s.Require().NoError(err)

	// create attribute with two values
	attr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId:    ns.GetId(),
		Name:           "inactive_value_attr",
		Rule:           policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values:         []string{"value1", "value2"},
		AllowTraversal: wrapperspb.Bool(true),
	})
	s.Require().NoError(err)

	got, err := s.db.PolicyClient.GetAttribute(s.ctx, attr.GetId())
	s.Require().NoError(err)
	s.Len(got.GetValues(), 2)
	valueToDeactivate := got.GetValues()[0]

	// deactivate a value while leaving the definition active
	_, err = s.db.PolicyClient.DeactivateAttributeValue(s.ctx, valueToDeactivate.GetId())
	s.Require().NoError(err)

	fqn := fqnBuilder(ns.GetName(), attr.GetName(), valueToDeactivate.GetValue())
	retrieved, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{fqn},
	})
	s.Require().Error(err)
	s.Nil(retrieved)
	s.Require().ErrorIs(err, db.ErrAttributeValueInactive)
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
	})
	s.Require().Error(err)
	s.Nil(v)
	s.Require().ErrorIs(err, db.ErrAttributeValueInactive)

	// get the attribute by the value fqn for v2
	v, err = s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{fqnBuilder(ns.GetName(), attr.GetName(), v2.GetValue())},
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
		Fqns: []string{fqnBuilder(gotNs.GetName(), attr.GetName(), v1.GetValue())},
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
	})
	s.Require().Error(err)
	s.Nil(v)
	s.Require().ErrorIs(err, db.ErrNotFound)

	v, err = s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{attrFqn},
	})
	s.Require().Error(err)
	s.Nil(v)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *AttributeFqnSuite) TestGetAttributeByValueFqns_KAS_Keys_Returned() {
	kasKeyFixture := s.f.GetKasRegistryServerKeys("kas_key_1")
	kasKey, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{Id: kasKeyFixture.ID})
	s.Require().NoError(err)
	fqn := "https://keys.com/attr/kas-key/value/key1"

	// Create New Namespace
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "keys.com"})
	s.Require().NoError(err)
	s.NotNil(ns)

	// Create Attribute
	attr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		Name:        "kas-key",
		NamespaceId: ns.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values:      []string{"key1"},
	})
	s.Require().NoError(err)
	s.NotNil(attr)

	// Assign Kas Key to namespace
	nsKey, err := s.db.PolicyClient.AssignPublicKeyToNamespace(s.ctx, &namespaces.NamespaceKey{
		NamespaceId: ns.GetId(),
		KeyId:       kasKey.GetKey().GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(nsKey)

	// Get Attribute By Value Fqns. Check NS for key
	v, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{fqn},
	})
	s.Require().NoError(err)
	s.NotNil(v)
	s.Len(v, 1)

	for _, attr := range v {
		s.Len(attr.GetAttribute().GetNamespace().GetKasKeys(), 1)
		s.Empty(attr.GetAttribute().GetKasKeys())
		s.Empty(attr.GetValue().GetKasKeys())
		validateSimpleKasKey(&s.Suite, kasKey, attr.GetAttribute().GetNamespace().GetKasKeys()[0])
	}

	// Assign Kas Key to Attribute
	attrKey, err := s.db.PolicyClient.AssignPublicKeyToAttribute(s.ctx, &attributes.AttributeKey{
		AttributeId: attr.GetId(),
		KeyId:       kasKey.GetKey().GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(attrKey)

	// Get Attribute By Value Fqns. Check NS and Attribute for Key
	v, err = s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{fqn},
	})
	s.Require().NoError(err)
	s.NotNil(v)
	s.Len(v, 1)

	for _, attr := range v {
		s.Len(attr.GetAttribute().GetNamespace().GetKasKeys(), 1)
		s.Len(attr.GetAttribute().GetKasKeys(), 1)
		s.Empty(attr.GetValue().GetKasKeys())
		validateSimpleKasKey(&s.Suite, kasKey, attr.GetAttribute().GetNamespace().GetKasKeys()[0])
		validateSimpleKasKey(&s.Suite, kasKey, attr.GetAttribute().GetKasKeys()[0])
	}

	// Assign Kas Key to Value
	valueKey, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &attributes.ValueKey{
		ValueId: attr.GetValues()[0].GetId(),
		KeyId:   kasKey.GetKey().GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(valueKey)

	// Get Attribute By Value Fqns. Check NS ,Attribute and Value for Key
	v, err = s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{fqn},
	})
	s.Require().NoError(err)
	s.NotNil(v)
	s.Len(v, 1)

	for _, attr := range v {
		s.Len(attr.GetAttribute().GetNamespace().GetKasKeys(), 1)
		s.Len(attr.GetAttribute().GetKasKeys(), 1)
		s.Len(attr.GetValue().GetKasKeys(), 1)
		validateSimpleKasKey(&s.Suite, kasKey, attr.GetAttribute().GetNamespace().GetKasKeys()[0])
		validateSimpleKasKey(&s.Suite, kasKey, attr.GetAttribute().GetKasKeys()[0])
		validateSimpleKasKey(&s.Suite, kasKey, attr.GetValue().GetKasKeys()[0])
	}
}

func (s *AttributeFqnSuite) Test_GrantsAreReturned() {
	// Create New Namespace
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{Name: "grants.com"})
	s.Require().NoError(err)
	s.NotNil(ns)

	// Create Attribute
	attr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		Name:        "grants",
		NamespaceId: ns.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values:      []string{"value1", "value2"},
	})
	s.Require().NoError(err)
	s.NotNil(attr)

	// Create Kas Registry
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri: "https://grants.com/kas",
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Remote{
				Remote: "https://grants.com/kas/public_key",
			},
		},
	})
	s.Require().NoError(err)
	s.NotNil(kas)

	// Create NS Grant
	// use Pgx.Exec because INSERT is only for testing and should not be part of PolicyDBClient
	nsGrant, err := s.db.PolicyClient.Pgx.Exec(s.ctx,
		`INSERT INTO attribute_namespace_key_access_grants (namespace_id, key_access_server_id) VALUES ($1, $2)`,
		ns.GetId(), kas.GetId())
	s.Require().NoError(err)
	s.NotNil(nsGrant.RowsAffected())

	// Create Attribute Grant
	// use Pgx.Exec because INSERT is only for testing and should not be part of PolicyDBClient
	attrGrant, err := s.db.PolicyClient.Pgx.Exec(s.ctx,
		`INSERT INTO attribute_definition_key_access_grants (attribute_definition_id, key_access_server_id) VALUES ($1, $2)`,
		attr.GetId(), kas.GetId())
	s.Require().NoError(err)
	s.NotNil(attrGrant.RowsAffected())

	// Create Value Grant
	// use Pgx.Exec because INSERT is only for testing and should not be part of PolicyDBClient
	valueGrant, err := s.db.PolicyClient.Pgx.Exec(s.ctx,
		`INSERT INTO attribute_value_key_access_grants (attribute_value_id, key_access_server_id) VALUES ($1, $2)`,
		attr.GetValues()[0].GetId(), kas.GetId())
	s.Require().NoError(err)
	s.NotNil(valueGrant.RowsAffected())

	// Get Namespace check for grant
	nsGet, err := s.db.PolicyClient.GetNamespace(s.ctx, ns.GetId())
	s.Require().NoError(err)
	s.NotNil(nsGet)
	s.Len(nsGet.GetGrants(), 1)
	s.Equal(ns.GetId(), nsGet.GetId())
	s.Equal(kas.GetId(), nsGet.GetGrants()[0].GetId())

	// Get Attribute
	attrGet, err := s.db.PolicyClient.GetAttribute(s.ctx, attr.GetId())
	s.Require().NoError(err)
	s.NotNil(attrGet)
	s.Len(attrGet.GetGrants(), 1)
	s.Equal(attr.GetId(), attrGet.GetId())
	s.Equal(kas.GetId(), attrGet.GetGrants()[0].GetId())

	// Get Value
	valueGet, err := s.db.PolicyClient.GetAttributeValue(s.ctx, attr.GetValues()[0].GetId())
	s.Require().NoError(err)
	s.NotNil(valueGet)
	s.Len(valueGet.GetGrants(), 1)
	s.Equal(attr.GetValues()[0].GetId(), valueGet.GetId())
	s.Equal(kas.GetId(), valueGet.GetGrants()[0].GetId())

	// GetAttributeByFQN Values
	fqn := fqnBuilder(ns.GetName(), attr.GetName(), attr.GetValues()[0].GetValue())
	v, err := s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{fqn},
	})
	s.Require().NoError(err)
	s.NotNil(v)
	s.Len(v, 1)
	s.Len(v[fqn].GetAttribute().GetNamespace().GetGrants(), 1)
	s.Len(v[fqn].GetAttribute().GetGrants(), 1)
	s.Len(v[fqn].GetValue().GetGrants(), 1)
}

func validateSimpleKasKey(s *suite.Suite, expected *policy.KasKey, actual *policy.SimpleKasKey) {
	s.Equal(expected.GetKey().GetKeyId(), actual.GetPublicKey().GetKid())
	s.Equal(expected.GetKasUri(), actual.GetKasUri())
	s.Equal(expected.GetKey().GetKeyAlgorithm(), actual.GetPublicKey().GetAlgorithm())
	s.Equal(expected.GetKasId(), actual.GetKasId())
	unbase64EncodedPem, err := base64.StdEncoding.DecodeString(expected.GetKey().GetPublicKeyCtx().GetPem())
	s.Require().NoError(err)
	s.Equal(string(unbase64EncodedPem), actual.GetPublicKey().GetPem())
}

func (s *AttributeFqnSuite) bigTestSetup(namespaceName string) bigSetup {
	// create a new namespace
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: namespaceName,
	})
	s.Require().NoError(err)
	s.NotNil(ns)

	// create a resource mapping group for the namespace
	rmGrp, err := s.db.PolicyClient.CreateResourceMappingGroup(s.ctx, &resourcemapping.CreateResourceMappingGroupRequest{
		NamespaceId: ns.GetId(),
		Name:        "test_group",
	})
	s.Require().NoError(err)
	s.NotNil(rmGrp)

	// give it attributes and values
	attr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attributes.CreateAttributeRequest{
		NamespaceId: ns.GetId(),
		Name:        "test_attr",
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
		Values:      []string{"value1", "value2"},
	})
	s.Require().NoError(err)
	s.NotNil(attr)
	val1 := attr.GetValues()[0]
	val2 := attr.GetValues()[1]

	nsKasURI := fmt.Sprintf("https://testing_granted_ns.com/%s/kas", namespaceName)
	attrKasURI := fmt.Sprintf("https://testing_granted_attr.com/%s/kas", namespaceName)
	val1KasURI := fmt.Sprintf("https://testing_granted_val.com/%s/kas", namespaceName)
	val2KasURI := fmt.Sprintf("https://testing_granted_val2.com/%s/kas", namespaceName)

	kasAssociations := map[string]*KasAssociations{}
	// create new KASes
	for _, toAssociate := range []struct {
		id  string
		uri string
	}{
		{ns.GetId(), nsKasURI},
		{attr.GetId(), attrKasURI},
		{val1.GetId(), val1KasURI},
		{val2.GetId(), val2KasURI},
	} {
		kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
			Uri: toAssociate.uri,
			PublicKey: &policy.PublicKey{
				PublicKey: &policy.PublicKey_Remote{
					Remote: toAssociate.uri + "/public_key",
				},
			},
		})
		s.Require().NoError(err)
		s.NotNil(kas)

		req := kasregistry.CreateKeyRequest{
			KasId:        kas.GetId(),
			KeyId:        "big_test_key",
			KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
			KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
			PublicKeyCtx: &policy.PublicKeyCtx{Pem: keyCtx},
			PrivateKeyCtx: &policy.PrivateKeyCtx{
				WrappedKey: keyCtx,
			},
		}
		resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
		s.Require().NoError(err)
		s.NotNil(resp)

		kasAssociations[toAssociate.id] = &KasAssociations{
			kasID:   kas.GetId(),
			uri:     toAssociate.uri,
			keyID:   resp.GetKasKey().GetKey().GetKeyId(),
			keyUUID: resp.GetKasKey().GetKey().GetId(),
		}
	}

	// make a grant association to the namespace
	nsGrant, err := s.db.PolicyClient.AssignPublicKeyToNamespace(s.ctx, &namespaces.NamespaceKey{
		KeyId:       kasAssociations[ns.GetId()].keyUUID,
		NamespaceId: ns.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(nsGrant)

	// make a grant association to the attribute definition
	attrGrant, err := s.db.PolicyClient.AssignPublicKeyToAttribute(s.ctx, &attributes.AttributeKey{
		KeyId:       kasAssociations[attr.GetId()].keyUUID,
		AttributeId: attr.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(attrGrant)

	// make a grant association to the first value
	val1Grant, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &attributes.ValueKey{
		KeyId:   kasAssociations[val1.GetId()].keyUUID,
		ValueId: val1.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(val1Grant)

	// make a grant association to the second value
	val2Grant, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &attributes.ValueKey{
		KeyId:   kasAssociations[val2.GetId()].keyUUID,
		ValueId: val2.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(val2Grant)

	actionRead := s.f.GetStandardAction(policydb.ActionRead.String())
	actionCreate := s.f.GetStandardAction(policydb.ActionCreate.String())
	// give a subject mapping to the first value
	val1SM, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              val1.GetId(),
		ExistingSubjectConditionSetId: s.f.GetSubjectConditionSetKey("subject_condition_set1").ID,
		Actions:                       []*policy.Action{actionRead, fixtureActionCustomUpload},
	})
	s.Require().NoError(err)
	s.NotNil(val1SM)

	// give a subject mapping to the second value
	val2SM, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              val2.GetId(),
		ExistingSubjectConditionSetId: s.f.GetSubjectConditionSetKey("subject_condition_set2").ID,
		Actions:                       []*policy.Action{actionCreate},
	})
	s.Require().NoError(err)
	s.NotNil(val2SM)

	// give a second subject mapping to the second value
	val2SM2, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              val2.GetId(),
		ExistingSubjectConditionSetId: s.f.GetSubjectConditionSetKey("subject_condition_set3").ID,
		Actions:                       []*policy.Action{actionRead, actionCreate},
	})
	s.Require().NoError(err)
	s.NotNil(val2SM2)

	rms := map[string]struct {
		Terms   []string
		GroupID string
	}{}
	// make a resource mapping for first value with the group
	rm1, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, &resourcemapping.CreateResourceMappingRequest{
		GroupId:          rmGrp.GetId(),
		AttributeValueId: val1.GetId(),
		Terms:            []string{"term1", "term2"},
	})
	s.Require().NoError(err)
	s.NotNil(rm1)
	rms[rm1.GetId()] = struct {
		Terms   []string
		GroupID string
	}{
		Terms:   rm1.GetTerms(),
		GroupID: rmGrp.GetId(),
	}

	// make another resource mapping for first value without the group
	rm2, err := s.db.PolicyClient.CreateResourceMapping(s.ctx, &resourcemapping.CreateResourceMappingRequest{
		AttributeValueId: val1.GetId(),
		Terms:            []string{"otherterm1", "otherterm2"},
	})
	s.Require().NoError(err)
	s.NotNil(rm2)
	rms[rm2.GetId()] = struct {
		Terms   []string
		GroupID string
	}{
		Terms: rm2.GetTerms(),
	}

	return bigSetup{
		attrFqn:         fmt.Sprintf("https://%s/attr/test_attr", namespaceName),
		nsID:            ns.GetId(),
		attrID:          attr.GetId(),
		val1ID:          val1.GetId(),
		val2ID:          val2.GetId(),
		kasAssociations: kasAssociations,
		rms:             rms,
	}
}
