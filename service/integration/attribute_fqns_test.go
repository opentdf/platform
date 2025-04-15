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
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	policydb "github.com/opentdf/platform/service/policy/db"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/proto"
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

	// assign a KAS grant to the value
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri: "https://testing_granted_values.com/kas",
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Remote{
				Remote: "https://testing_granted_values.com/kas",
			},
		},
	})
	s.Require().NoError(err)
	s.NotNil(kas)

	grant, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, &attributes.ValueKeyAccessServer{
		KeyAccessServerId: kas.GetId(),
		ValueId:           valueFixture.ID,
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
				if g.GetId() == kas.GetId() {
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
	s.Empty(attr.GetKeys())
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithAttributeDefKeysAssocaited() {
	fqnFixtureKey := "example.net/attr/attr1"
	kasKey := s.f.GetKasRegistryServerKeys("kas_key_1")
	fullFqn := fmt.Sprintf("https://%s", fqnFixtureKey)
	attrFixture := s.f.GetAttributeKey(fqnFixtureKey)

	attr, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.Require().NoError(err)

	// the number of values should match the fixture
	s.Len(attr.GetValues(), 2)
	s.Empty(attr.GetKeys())

	// Associate key with attribute.
	keyResp, err := s.db.PolicyClient.AssignPublicKeyToAttribute(s.ctx, &attributes.AttributeKey{
		AttributeId: attrFixture.ID,
		KeyId:       kasKey.ID,
	})
	s.Require().NoError(err)
	s.NotNil(keyResp)

	attr, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.Require().NoError(err)

	// the number of values should match the fixture
	s.Len(attr.GetValues(), 2)

	// Key checks
	s.Len(attr.GetKeys(), 1)
	s.Equal(kasKey.ID, attr.GetKeys()[0].GetId())
	s.Equal(kasKey.ProviderConfigID, attr.GetKeys()[0].GetProviderConfig().GetId())

	// Remove association
	_, err = s.db.PolicyClient.RemovePublicKeyFromAttribute(s.ctx, &attributes.AttributeKey{
		AttributeId: attrFixture.ID,
		KeyId:       kasKey.ID,
	})
	s.Require().NoError(err)
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithAttributeValueKeysAssociated() {
	fqnFixtureKey := "example.net/attr/attr1"
	kasKey := s.f.GetKasRegistryServerKeys("kas_key_1")
	fullFqn := fmt.Sprintf("https://%s", fqnFixtureKey)

	attr, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.Require().NoError(err)

	// the number of values should match the fixture
	s.Len(attr.GetValues(), 2)
	s.Empty(attr.GetKeys())
	for _, v := range attr.GetValues() {
		s.Empty(v.GetKeys())
	}

	// Associate key with attribute.
	keyResp, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &attributes.ValueKey{
		ValueId: attr.GetValues()[0].GetId(),
		KeyId:   kasKey.ID,
	})
	s.Require().NoError(err)
	s.NotNil(keyResp)

	// Associate value 2 with the same key
	keyResp, err = s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &attributes.ValueKey{
		ValueId: attr.GetValues()[1].GetId(),
		KeyId:   kasKey.ID,
	})
	s.Require().NoError(err)
	s.NotNil(keyResp)

	attr, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.Require().NoError(err)

	// the number of values should match the fixture
	s.Len(attr.GetValues(), 2)

	// Key checks
	s.Empty(attr.GetKeys())
	for _, v := range attr.GetValues() {
		s.Len(v.GetKeys(), 1)
		s.Equal(kasKey.ID, v.GetKeys()[0].GetId())
		s.Equal(kasKey.ProviderConfigID, v.GetKeys()[0].GetProviderConfig().GetId())
		_, err := s.db.PolicyClient.RemovePublicKeyFromValue(s.ctx, &attributes.ValueKey{
			ValueId: v.GetId(),
			KeyId:   kasKey.ID,
		})
		s.Require().NoError(err)
	}
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithKeysAssociatedWithNamespace() {
	fqnFixtureKey := "example.net/attr/attr1"
	kasKey := s.f.GetKasRegistryServerKeys("kas_key_1")
	fullFqn := fmt.Sprintf("https://%s", fqnFixtureKey)

	attr, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.Require().NoError(err)

	// the number of values should match the fixture
	s.Len(attr.GetValues(), 2)
	s.Empty(attr.GetNamespace().GetKeys())

	// Associate key with attribute.
	keyResp, err := s.db.PolicyClient.AssignPublicKeyToNamespace(s.ctx, &namespaces.NamespaceKey{
		NamespaceId: attr.GetNamespace().GetId(),
		KeyId:       kasKey.ID,
	})
	s.Require().NoError(err)
	s.NotNil(keyResp)

	attr, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.Require().NoError(err)

	// the number of values should match the fixture
	s.Len(attr.GetValues(), 2)

	// Key checks
	s.Empty(attr.GetKeys())
	s.Len(attr.GetNamespace().GetKeys(), 1)
	s.Equal(kasKey.ID, attr.GetNamespace().GetKeys()[0].GetId())
	s.Equal(kasKey.ProviderConfigID, attr.GetNamespace().GetKeys()[0].GetProviderConfig().GetId())

	_, err = s.db.PolicyClient.RemovePublicKeyFromNamespace(s.ctx, &namespaces.NamespaceKey{
		NamespaceId: attr.GetNamespace().GetId(),
		KeyId:       kasKey.ID,
	})
	s.Require().NoError(err)
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithKeysAssociatedAttributes_MultipleAttributes() {
	fqnFixtureKey := "example.net/attr/attr1"
	fqnFixtureKeyTwo := "example.net/attr/attr2"
	kasKey := s.f.GetKasRegistryServerKeys("kas_key_1")
	kasKey2 := s.f.GetKasRegistryServerKeys("kas_key_2")
	fullFqn := fmt.Sprintf("https://%s", fqnFixtureKey)
	fullFqn2 := fmt.Sprintf("https://%s", fqnFixtureKeyTwo)

	attr, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	s.Require().NoError(err)
	s.Len(attr.GetValues(), 2)
	s.Empty(attr.GetKeys())

	// Associate key with attribute.
	keyResp, err := s.db.PolicyClient.AssignPublicKeyToAttribute(s.ctx, &attributes.AttributeKey{
		AttributeId: attr.GetId(),
		KeyId:       kasKey.ID,
	})
	s.Require().NoError(err)
	s.NotNil(keyResp)

	attr, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn2)
	s.Require().NoError(err)
	s.Empty(attr.GetValues())
	s.Empty(attr.GetKeys())

	// Associate key with attribute.
	keyResp, err = s.db.PolicyClient.AssignPublicKeyToAttribute(s.ctx, &attributes.AttributeKey{
		AttributeId: attr.GetId(),
		KeyId:       kasKey2.ID,
	})
	s.Require().NoError(err)
	s.NotNil(keyResp)

	// Get attribute 1
	attr, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn)
	attrOneID := attr.GetId()
	s.Require().NoError(err)
	s.Len(attr.GetKeys(), 1)
	s.Equal(kasKey.ID, attr.GetKeys()[0].GetId())
	s.Equal(kasKey.ProviderConfigID, attr.GetKeys()[0].GetProviderConfig().GetId())

	// Get attribute 2
	attr, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, fullFqn2)
	attrTwoID := attr.GetId()
	s.Require().NoError(err)
	s.Len(attr.GetKeys(), 1)
	s.Equal(kasKey2.ID, attr.GetKeys()[0].GetId())
	s.Equal(kasKey2.ProviderConfigID, attr.GetKeys()[0].GetProviderConfig().GetId())

	_, err = s.db.PolicyClient.RemovePublicKeyFromAttribute(s.ctx, &attributes.AttributeKey{
		AttributeId: attrOneID,
		KeyId:       kasKey.ID,
	})
	s.Require().NoError(err)

	_, err = s.db.PolicyClient.RemovePublicKeyFromAttribute(s.ctx, &attributes.AttributeKey{
		AttributeId: attrTwoID,
		KeyId:       kasKey2.ID,
	})
	s.Require().NoError(err)
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

	// make a first grant association to the attribute definition
	grant, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, &attributes.AttributeKeyAccessServer{
		KeyAccessServerId: remoteKAS.GetId(),
		AttributeId:       a.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(grant)

	// create a second kas registration and grant it to the attribute definition
	cachedKeyPem := "cached_key"
	cachedKASName := "test_kas_name"
	cachedKas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri: "https://example.org/kas2",
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Cached{
				Cached: &policy.KasPublicKeySet{
					Keys: []*policy.KasPublicKey{
						{
							Pem: cachedKeyPem,
						},
					},
				},
			},
		},
		Name: cachedKASName,
	})
	s.Require().NoError(err)
	s.NotNil(cachedKas)

	grant2, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, &attributes.AttributeKeyAccessServer{
		KeyAccessServerId: cachedKas.GetId(),
		AttributeId:       a.GetId(),
	})
	cachedKasID := grant2.GetKeyAccessServerId()
	s.Require().NoError(err)
	s.NotNil(grant2)

	// get the attribute by the fqn of the attribute definition
	got, err := s.db.PolicyClient.GetAttributeByFqn(s.ctx, "https://example.org/attr/attr_with_grants")
	s.Require().NoError(err)
	s.NotNil(got)

	// ensure the attribute has the grants
	s.Len(got.GetGrants(), 2)
	grantIDs := []string{remoteKAS.GetId(), cachedKas.GetId()}
	s.Contains(grantIDs, got.GetGrants()[0].GetId())
	s.Contains(grantIDs, got.GetGrants()[1].GetId())
	s.NotEqual(got.GetGrants()[0].GetId(), got.GetGrants()[1].GetId())
	// ensure grant has cached key pem
	pemIsPresent := false
	for _, g := range got.GetGrants() {
		if g.GetId() == cachedKasID {
			s.Equal(g.GetPublicKey().GetCached().GetKeys()[0].GetPem(), cachedKeyPem)
			s.Equal(g.GetName(), cachedKASName)
			pemIsPresent = true
		}
	}
	s.True(pemIsPresent)

	// get the attribute by the fqn of one of its values and ensure the grants are present on the definition
	got, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, "https://example.org/attr/attr_with_grants/value/value1")
	s.Require().NoError(err)
	s.NotNil(got)
	s.Len(got.GetGrants(), 2)

	// assign a KAS to the value and make sure it is not granted to the definition
	grant3, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, &attributes.ValueKeyAccessServer{
		KeyAccessServerId: s.f.GetKasRegistryKey("key_access_server_1").ID,
		ValueId:           got.GetValues()[0].GetId(),
	})
	s.NotNil(grant3)
	s.Require().NoError(err)

	got, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, "https://example.org/attr/attr_with_grants/value/value1")
	s.Require().NoError(err)
	s.NotNil(got)
	s.Len(got.GetGrants(), 2)
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithKeyAccessGrants_Values() {
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

	// create a new kas registration
	remoteKASName := "testing-io-remote"
	remoteKAS, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri: "https://testing.io/kas",
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Remote{
				Remote: "https://testing.org/kas",
			},
		},
		Name: remoteKASName,
	})
	s.Require().NoError(err)
	s.NotNil(remoteKAS)

	// make a grant association to the first value
	grant, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, &attributes.ValueKeyAccessServer{
		KeyAccessServerId: remoteKAS.GetId(),
		ValueId:           valueFirst.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(grant)

	// create a second kas registration and grant it to the second value
	cachedKASName := "testion-io-local"
	cachedKAS, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri: "https://testing.io/kas2",
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Cached{
				Cached: &policy.KasPublicKeySet{
					Keys: []*policy.KasPublicKey{
						{
							Pem: "local_key",
						},
					},
				},
			},
		},
		Name: cachedKASName,
	})
	s.Require().NoError(err)
	s.NotNil(cachedKAS)

	grant2, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, &attributes.ValueKeyAccessServer{
		KeyAccessServerId: cachedKAS.GetId(),
		ValueId:           valueSecond.GetId(),
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
			s.Equal(remoteKAS.GetId(), firstGrant.GetId())
			s.Equal(remoteKASName, firstGrant.GetName())
		case valueSecond.GetId():
			s.Equal(cachedKAS.GetId(), firstGrant.GetId())
			s.Equal(cachedKASName, firstGrant.GetName())
		default:
			s.Fail("unexpected value", v)
		}
	}
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithKeyAccessGrants_DefAndValuesGrantsBoth() {
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

	// create a new kas registration
	valKAS1, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri: "https://testing.org/kas",
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Remote{
				Remote: "https://testing.org/kas",
			},
		},
	})
	s.Require().NoError(err)
	s.NotNil(valKAS1)

	// make a grant association to the first value
	grant, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, &attributes.ValueKeyAccessServer{
		KeyAccessServerId: valKAS1.GetId(),
		ValueId:           valueFirst.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(grant)

	// create a second kas registration and grant it to the second value
	valKAS2, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri: "https://testing.org/kas2",
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Cached{
				Cached: &policy.KasPublicKeySet{
					Keys: []*policy.KasPublicKey{
						{
							Pem: "local_key",
						},
					},
				},
			},
		},
	})
	s.Require().NoError(err)
	s.NotNil(valKAS2)

	grant2, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, &attributes.ValueKeyAccessServer{
		KeyAccessServerId: valKAS2.GetId(),
		ValueId:           valueSecond.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(grant2)

	// create a third kas registration and grant it to the attribute definition
	defKAS, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri: "https://testing.org/kas3",
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Cached{
				Cached: &policy.KasPublicKeySet{
					Keys: []*policy.KasPublicKey{
						{
							Pem: "local_key",
						},
					},
				},
			},
		},
	})
	s.Require().NoError(err)
	s.NotNil(defKAS)

	defGrant, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, &attributes.AttributeKeyAccessServer{
		KeyAccessServerId: defKAS.GetId(),
		AttributeId:       a.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(defGrant)

	// get the attribute by the fqn of the attribute definition
	got, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, attrFqn)
	s.Require().NoError(err)
	s.NotNil(got)

	// ensure the attribute has exactly one definition grant
	s.Len(got.GetGrants(), 1)
	s.Equal(defKAS.GetId(), got.GetGrants()[0].GetId())

	// get the attribute by the fqn of one of its values and ensure the grants are present
	got, err = s.db.PolicyClient.GetAttributeByFqn(s.ctx, val1Fqn)
	s.Require().NoError(err)
	s.NotNil(got)
	s.Len(got.GetValues(), 2)
	s.Len(got.GetGrants(), 1)
	s.Equal(defKAS.GetId(), got.GetGrants()[0].GetId())

	for _, v := range got.GetValues() {
		switch v.GetId() {
		case valueFirst.GetId():
			s.Require().Len(v.GetGrants(), 1)
			s.Equal(valKAS1.GetId(), v.GetGrants()[0].GetId())
		case valueSecond.GetId():
			s.Require().Len(v.GetGrants(), 1)
			s.Equal(valKAS2.GetId(), v.GetGrants()[0].GetId())
		default:
			s.Fail("unexpected value", v)
		}
	}
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_WithKeyAccessGrants_NamespaceGrants() {
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

	// create a new kas registration
	nsKASName := "namespace-kas1"
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri: "https://testing_granted_namespace.com/kas",
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Remote{
				Remote: "https://testing_granted_namespace.com/kas",
			},
		},
		Name: nsKASName,
	})
	s.Require().NoError(err)
	s.NotNil(kas)

	// make a grant association to the namespace
	grant, err := s.db.PolicyClient.AssignKeyAccessServerToNamespace(s.ctx, &namespaces.NamespaceKeyAccessServer{
		KeyAccessServerId: kas.GetId(),
		NamespaceId:       ns.GetId(),
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
	s.Equal(kas.GetId(), grants[0].GetId())
	s.Equal(nsKASName, grants[0].GetName())
}

// for all the big tests set up:
// attribute name is "test_attr", values are "value1" and "value2"
// kas uris granted to each are "https://testing_granted_<ns | attr | val1 | val1>.com/<ns>/kas",
type bigSetup struct {
	attrFqn         string
	nsID            string
	attrID          string
	val1ID          string
	val2ID          string
	kasAssociations map[string]string
}

func (s *AttributeFqnSuite) bigTestSetup(namespaceName string) bigSetup {
	// create a new namespace
	ns, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: namespaceName,
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
	val1 := attr.GetValues()[0]
	val2 := attr.GetValues()[1]

	nsKasURI := fmt.Sprintf("https://testing_granted_ns.com/%s/kas", namespaceName)
	attrKasURI := fmt.Sprintf("https://testing_granted_attr.com/%s/kas", namespaceName)
	val1KasURI := fmt.Sprintf("https://testing_granted_val.com/%s/kas", namespaceName)
	val2KasURI := fmt.Sprintf("https://testing_granted_val2.com/%s/kas", namespaceName)

	kasAssociations := map[string]string{}
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
		kasAssociations[toAssociate.id] = kas.GetId()
	}

	// make a grant association to the namespace
	nsGrant, err := s.db.PolicyClient.AssignKeyAccessServerToNamespace(s.ctx, &namespaces.NamespaceKeyAccessServer{
		KeyAccessServerId: kasAssociations[ns.GetId()],
		NamespaceId:       ns.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(nsGrant)

	// make a grant association to the attribute definition
	attrGrant, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, &attributes.AttributeKeyAccessServer{
		KeyAccessServerId: kasAssociations[attr.GetId()],
		AttributeId:       attr.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(attrGrant)

	// make a grant association to the first value
	val1Grant, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, &attributes.ValueKeyAccessServer{
		KeyAccessServerId: kasAssociations[val1.GetId()],
		ValueId:           val1.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(val1Grant)

	// make a grant association to the second value
	val2Grant, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, &attributes.ValueKeyAccessServer{
		KeyAccessServerId: kasAssociations[val2.GetId()],
		ValueId:           val2.GetId(),
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

	return bigSetup{
		attrFqn:         fmt.Sprintf("https://%s/attr/test_attr", namespaceName),
		nsID:            ns.GetId(),
		attrID:          attr.GetId(),
		val1ID:          val1.GetId(),
		val2ID:          val2.GetId(),
		kasAssociations: kasAssociations,
	}
}

func (s *AttributeFqnSuite) TestGetAttributeByFqn_SameResultsWhetherAttrOrValueFqnUsed() {
	ns := "test_fqn_all_consistent.gov"
	setup := s.bigTestSetup(ns)

	fqns := []string{
		setup.attrFqn,
		fmt.Sprintf("%s/value/value1", setup.attrFqn),
		fmt.Sprintf("%s/value/value2", setup.attrFqn),
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
	s.Equal(got.GetNamespace().GetFqn(), fmt.Sprintf("https://%s", ns))
	s.Equal(got.GetValues()[0].GetFqn(), fmt.Sprintf("%s/value/value1", setup.attrFqn))
	s.Equal(got.GetValues()[1].GetFqn(), fmt.Sprintf("%s/value/value2", setup.attrFqn))
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
	s.Equal(setup.kasAssociations[got.GetNamespace().GetId()], nsGrant.GetId())
	s.Equal(fmt.Sprintf("https://testing_granted_ns.com/%s/kas", ns), nsGrant.GetUri())

	// ensure the attribute has the grants
	s.Len(got.GetGrants(), 1)
	attrGrant := got.GetGrants()[0]
	s.Equal(setup.kasAssociations[got.GetId()], attrGrant.GetId())
	s.Equal(fmt.Sprintf("https://testing_granted_attr.com/%s/kas", ns), attrGrant.GetUri())

	// ensure the first value has the grants
	val1 := got.GetValues()[0]
	s.Len(val1.GetGrants(), 1)
	val1Grant := val1.GetGrants()[0]
	s.Equal(setup.kasAssociations[val1.GetId()], val1Grant.GetId())
	s.Equal(fmt.Sprintf("https://testing_granted_val.com/%s/kas", ns), val1Grant.GetUri())

	// ensure the second value has the grants
	val2 := got.GetValues()[1]
	s.Len(val2.GetGrants(), 1)
	val2Grant := val2.GetGrants()[0]
	s.Equal(setup.kasAssociations[val2.GetId()], val2Grant.GetId())
	s.Equal(fmt.Sprintf("https://testing_granted_val2.com/%s/kas", ns), val2Grant.GetUri())

	// remove grants from all objects
	_, err = s.db.PolicyClient.RemoveKeyAccessServerFromNamespace(s.ctx, &namespaces.NamespaceKeyAccessServer{
		KeyAccessServerId: nsGrant.GetId(),
		NamespaceId:       got.GetNamespace().GetId(),
	})
	s.Require().NoError(err)

	_, err = s.db.PolicyClient.RemoveKeyAccessServerFromAttribute(s.ctx, &attributes.AttributeKeyAccessServer{
		KeyAccessServerId: attrGrant.GetId(),
		AttributeId:       got.GetId(),
	})
	s.Require().NoError(err)

	_, err = s.db.PolicyClient.RemoveKeyAccessServerFromValue(s.ctx, &attributes.ValueKeyAccessServer{
		KeyAccessServerId: val1Grant.GetId(),
		ValueId:           val1.GetId(),
	})
	s.Require().NoError(err)

	_, err = s.db.PolicyClient.RemoveKeyAccessServerFromValue(s.ctx, &attributes.ValueKeyAccessServer{
		KeyAccessServerId: val2Grant.GetId(),
		ValueId:           val2.GetId(),
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
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
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
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
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
		Fqns: []string{fqnBuilder(gotNs.GetName(), attr.GetName(), v1.GetValue())},
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
	s.Require().ErrorIs(err, db.ErrNotFound)

	v, err = s.db.PolicyClient.GetAttributesByValueFqns(s.ctx, &attributes.GetAttributeValuesByFqnsRequest{
		Fqns: []string{attrFqn},
		WithValue: &policy.AttributeValueSelector{
			WithSubjectMaps: true,
		},
	})
	s.Require().Error(err)
	s.Nil(v)
	s.Require().ErrorIs(err, db.ErrNotFound)
}
