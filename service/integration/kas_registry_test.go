package integration

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"

	"github.com/stretchr/testify/suite"
)

var nonExistentKasRegistryID = "78909865-8888-9999-9999-000000654321"

type KasRegistrySuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context //nolint:containedctx // context is used in the test suite
}

func (s *KasRegistrySuite) SetupSuite() {
	slog.Info("setting up db.KasRegistry test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_kas_registry"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
}

func (s *KasRegistrySuite) TearDownSuite() {
	slog.Info("tearing down db.KasRegistry test suite")
	s.f.TearDown()
}

func (s *KasRegistrySuite) getKasRegistryFixtures() []fixtures.FixtureDataKasRegistry {
	return []fixtures.FixtureDataKasRegistry{
		s.f.GetKasRegistryKey("key_access_server_1"),
		s.f.GetKasRegistryKey("key_access_server_2"),
	}
}

func (s *KasRegistrySuite) Test_ListKeyAccessServers() {
	fixtures := s.getKasRegistryFixtures()
	list, err := s.db.PolicyClient.ListKeyAccessServers(s.ctx)
	s.Require().NoError(err)
	s.NotNil(list)
	for _, fixture := range fixtures {
		for _, kas := range list {
			if kas.GetId() == fixture.ID {
				if kas.GetPublicKey().GetRemote() != "" {
					s.Equal(fixture.PubKey.Remote, kas.GetPublicKey().GetRemote())
				} else {
					s.Equal(fixture.PubKey.Cached, kas.GetPublicKey().GetCached())
				}
				s.Equal(fixture.URI, kas.GetUri())
				s.Equal(fixture.Name, kas.GetName())
			}
		}
	}
}

func (s *KasRegistrySuite) Test_GetKeyAccessServer() {
	remoteFixture := s.f.GetKasRegistryKey("key_access_server_1")
	localFixture := s.f.GetKasRegistryKey("key_access_server_2")

	remote, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, remoteFixture.ID)
	s.Require().NoError(err)
	s.NotNil(remote)
	s.Equal(remoteFixture.ID, remote.GetId())
	s.Equal(remoteFixture.URI, remote.GetUri())
	s.Equal(remoteFixture.Name, remote.GetName())
	s.Equal(remoteFixture.PubKey.Remote, remote.GetPublicKey().GetRemote())

	local, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, localFixture.ID)
	s.Require().NoError(err)
	s.NotNil(local)
	s.Equal(localFixture.ID, local.GetId())
	s.Equal(localFixture.URI, local.GetUri())
	s.Equal(localFixture.Name, local.GetName())
	s.Equal(localFixture.PubKey.Cached, local.GetPublicKey().GetCached())
}

func (s *KasRegistrySuite) Test_GetKeyAccessServer_WithNonExistentId_Fails() {
	resp, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, nonExistentKasRegistryID)
	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *KasRegistrySuite) Test_GetKeyAccessServer_WithInvalidID_Fails() {
	resp, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, "hello")
	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
}

func (s *KasRegistrySuite) Test_CreateKeyAccessServer_Remote() {
	metadata := &common.MetadataMutable{
		Labels: map[string]string{
			"name": "this is the test name of my key access server",
		},
	}

	pubKey := &policy.PublicKey{
		PublicKey: &policy.PublicKey_Remote{
			Remote: "https://remote.com/key",
		},
	}

	kasRegistry := &kasregistry.CreateKeyAccessServerRequest{
		Uri:       "kas.uri",
		PublicKey: pubKey,
		Metadata:  metadata,
		// Leave off 'name' to test optionality
	}
	r, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	s.Require().NoError(err)
	s.NotNil(r)
	s.NotEqual("", r.GetId())
}

func (s *KasRegistrySuite) Test_CreateKeyAccessServer_UriConflict_Fails() {
	uri := "testingCreationConflict.com"
	pubKey := &policy.PublicKey{
		PublicKey: &policy.PublicKey_Remote{
			Remote: "https://something.somewhere/key",
		},
	}

	kasRegistry := &kasregistry.CreateKeyAccessServerRequest{
		Uri:       uri,
		PublicKey: pubKey,
	}
	k, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	s.Require().NoError(err)
	s.NotNil(k)
	s.NotEqual("", k.GetId())

	// try to create another KAS with the same URI
	k, err = s.db.PolicyClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
	s.Nil(k)
}

func (s *KasRegistrySuite) Test_CreateKeyAccessServer_NameConflict_Fails() {
	uri := "acmecorp.com"
	pubKey := &policy.PublicKey{
		PublicKey: &policy.PublicKey_Remote{
			Remote: "https://acmecorp.somewhere/key",
		},
	}
	name1 := "key-access-server-acme"

	kasRegistry := &kasregistry.CreateKeyAccessServerRequest{
		Uri:       uri,
		Name:      name1,
		PublicKey: pubKey,
	}
	k, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	s.Require().NoError(err)
	s.NotNil(k)
	s.NotEqual("", k.GetId())

	// try to create another KAS with the same Name
	kasRegistry.Uri = "acmecorp2.com"
	k, err = s.db.PolicyClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
	s.Nil(k)
}

func (s *KasRegistrySuite) Test_CreateKeyAccessServer_Name_LowerCased() {
	uri := "somekas.com"
	pubKey := &policy.PublicKey{
		PublicKey: &policy.PublicKey_Remote{
			Remote: "https://acmecorp.somewhere/key",
		},
	}
	name := "1MiXEDCASEkas-name"

	kasRegistry := &kasregistry.CreateKeyAccessServerRequest{
		Uri:       uri,
		Name:      name,
		PublicKey: pubKey,
	}
	k, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	s.Require().NoError(err)
	s.NotNil(k)
	s.NotEqual("", k.GetId())

	got, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, k.GetId())
	s.NotNil(got)
	s.Require().NoError(err)
	s.Equal(strings.ToLower(name), got.GetName())
}

func (s *KasRegistrySuite) Test_CreateKeyAccessServer_Cached() {
	metadata := &common.MetadataMutable{
		Labels: map[string]string{
			"name": "cached KAS",
		},
	}
	cachedKeyPem := "some_local_public_key_in_base64"
	pubKey := &policy.PublicKey{
		PublicKey: &policy.PublicKey_Cached{
			Cached: &policy.KasPublicKeySet{
				Keys: []*policy.KasPublicKey{
					{
						Pem: cachedKeyPem,
					},
				},
			},
		},
	}

	kasRegistry := &kasregistry.CreateKeyAccessServerRequest{
		Uri:       "testingCreation.uri.com",
		PublicKey: pubKey,
		Metadata:  metadata,
		// Leave off 'name' to test optionality
	}
	r, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	s.Require().NoError(err)
	s.NotNil(r)
	s.NotZero(r.GetId())
	s.Equal(r.GetPublicKey().GetCached().GetKeys()[0].GetPem(), cachedKeyPem)
}

func (s *KasRegistrySuite) Test_UpdateKeyAccessServer_Everything() {
	fixedLabel := "fixed label"
	updateLabel := "update label"
	updatedLabel := "true"
	newLabel := "new label"

	uri := "beforeURI_everything.com"
	pubKeyRemote := "https://remote.com/key"
	updatedURI := "afterURI_everything.com"
	updatedPubKeyRemote := "https://remote2.com/key"
	// name is optional - test only adds name during update
	updatedName := "key-access-updated"

	// create a test KAS
	created, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri: uri,
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Remote{
				Remote: pubKeyRemote,
			},
		},
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"fixed":  fixedLabel,
				"update": updateLabel,
			},
		},
		// Leave off 'name' to test optionality
	})
	s.Require().NoError(err)
	s.NotNil(created)

	initialGot, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(initialGot)

	// update it with new values and metadata
	updated, err := s.db.PolicyClient.UpdateKeyAccessServer(s.ctx, created.GetId(), &kasregistry.UpdateKeyAccessServerRequest{
		Uri: updatedURI,
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Remote{
				Remote: updatedPubKeyRemote,
			},
		},
		Name: updatedName,
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"update": updatedLabel,
				"new":    newLabel,
			},
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	s.Require().NoError(err)
	s.NotNil(updated)

	// get after update to validate changes were successful
	got, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Equal(updatedURI, got.GetUri())
	s.Equal(updatedName, got.GetName())
	s.Equal(updatedPubKeyRemote, got.GetPublicKey().GetRemote())
	s.Zero(got.GetPublicKey().GetCached())
	s.Equal(fixedLabel, got.GetMetadata().GetLabels()["fixed"])
	s.Equal(updatedLabel, got.GetMetadata().GetLabels()["update"])
	s.Equal(newLabel, got.GetMetadata().GetLabels()["new"])
	creationTime := initialGot.GetMetadata().GetCreatedAt().AsTime()
	updatedTime := got.GetMetadata().GetUpdatedAt().AsTime()
	s.True(updatedTime.After(creationTime))
}

func (s *KasRegistrySuite) Test_UpdateKeyAccessServer_Metadata_DoesNotAlterOtherValues() {
	uri := "before_metadata_only.com"
	pubKeyRemote := "https://remote.com/key"
	name := "kas-name-not-changed"

	// create a test KAS
	created, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri: uri,
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Remote{
				Remote: pubKeyRemote,
			},
		},
		Name: name,
	})
	s.Require().NoError(err)
	s.NotNil(created)

	// update it with new metadata
	updated, err := s.db.PolicyClient.UpdateKeyAccessServer(s.ctx, created.GetId(), &kasregistry.UpdateKeyAccessServerRequest{
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"new": "new label",
			},
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE,
	})
	s.Require().NoError(err)
	s.NotNil(updated)

	// get after update to validate changes were to metadata alone
	got, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Equal(uri, got.GetUri())
	s.Equal(name, got.GetName())
	s.Equal(pubKeyRemote, got.GetPublicKey().GetRemote())
	s.Zero(got.GetPublicKey().GetCached())
	s.Equal("new label", got.GetMetadata().GetLabels()["new"])
}

func (s *KasRegistrySuite) Test_UpdateKeyAccessServer_Uri_DoesNotAlterOtherValues() {
	uri := "before_uri_only.com"
	pubKeyRemote := "https://remote.com/key"
	updatedURI := "after_uri_only.com"
	name := "kas-unaltered"

	// create a test KAS
	created, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri: uri,
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Remote{
				Remote: pubKeyRemote,
			},
		},
		Name: name,
	})
	s.Require().NoError(err)
	s.NotNil(created)

	// update it with new uri
	updated, err := s.db.PolicyClient.UpdateKeyAccessServer(s.ctx, created.GetId(), &kasregistry.UpdateKeyAccessServerRequest{
		Uri: updatedURI,
	})
	s.Require().NoError(err)
	s.NotNil(updated)

	// get after update to validate changes were successful
	got, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Equal(updatedURI, got.GetUri())
	s.Equal(name, got.GetName())
	s.Equal(pubKeyRemote, got.GetPublicKey().GetRemote())
	s.Zero(got.GetPublicKey().GetCached())
	s.Nil(got.GetMetadata().GetLabels())
}

// the same test but only altering the key
func (s *KasRegistrySuite) Test_UpdateKeyAccessServer_PublicKey_DoesNotAlterOtherValues() {
	uri := "before_pubkey_only.com"
	pubKeyRemote := "https://remote.com/key"
	updatedKeySet := &policy.KasPublicKeySet{
		Keys: []*policy.KasPublicKey{
			{
				Pem: "some-pem-data",
				Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048,
				Kid: "r1",
			},
		},
	}
	updatedPubKey := &policy.PublicKey{
		PublicKey: &policy.PublicKey_Cached{
			Cached: updatedKeySet,
		},
	}

	// create a test KAS
	created, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri: uri,
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Remote{
				Remote: pubKeyRemote,
			},
		},
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"unchanged": "unchanged label",
			},
		},
		// Leave off 'name' to test optionality
	})
	s.Require().NoError(err)
	s.NotNil(created)

	// update it with new key
	updated, err := s.db.PolicyClient.UpdateKeyAccessServer(s.ctx, created.GetId(), &kasregistry.UpdateKeyAccessServerRequest{
		PublicKey: updatedPubKey,
	})
	s.Require().NoError(err)
	s.NotNil(updated)

	// get after update to validate changes were successful
	got, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Equal(uri, got.GetUri())
	s.Empty(got.GetName()) // name not given to KAS in create or update
	s.Equal(updatedKeySet, got.GetPublicKey().GetCached())
	s.Zero(got.GetPublicKey().GetRemote())
	s.Equal("unchanged label", got.GetMetadata().GetLabels()["unchanged"])
}

func (s *KasRegistrySuite) Test_UpdateKeyAccessServer_WithNonExistentId_Fails() {
	pubKey := &policy.PublicKey{
		PublicKey: &policy.PublicKey_Cached{
			Cached: &policy.KasPublicKeySet{
				Keys: []*policy.KasPublicKey{
					{
						Pem: "this_is_a_local_key",
					},
				},
			},
		},
	}
	updatedKas := &kasregistry.UpdateKeyAccessServerRequest{
		Uri:       "someKasUri.com",
		PublicKey: pubKey,
	}
	resp, err := s.db.PolicyClient.UpdateKeyAccessServer(s.ctx, nonExistentKasRegistryID, updatedKas)
	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *KasRegistrySuite) Test_UpdateKeyAccessServer_WithInvalidID_Fails() {
	resp, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, "not-a-uuid")
	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
}

func (s *KasRegistrySuite) Test_DeleteKeyAccessServer() {
	// create a test KAS
	pubKey := &policy.PublicKey{
		PublicKey: &policy.PublicKey_Remote{
			Remote: "https://remote.com/key",
		},
	}
	testKas := &kasregistry.CreateKeyAccessServerRequest{
		Uri:       "deleting.net",
		PublicKey: pubKey,
	}
	createdKas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, testKas)
	s.Require().NoError(err)
	s.NotNil(createdKas)

	// delete it
	deleted, err := s.db.PolicyClient.DeleteKeyAccessServer(s.ctx, createdKas.GetId())
	s.Require().NoError(err)
	s.NotNil(deleted)

	// get after delete to validate it's gone
	resp, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, createdKas.GetId())
	s.Require().Error(err)
	s.Nil(resp)
}

func (s *KasRegistrySuite) Test_DeleteKeyAccessServer_WithNonExistentId_Fails() {
	resp, err := s.db.PolicyClient.DeleteKeyAccessServer(s.ctx, nonExistentKasRegistryID)
	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *KasRegistrySuite) Test_DeleteKeyAccessServer_WithInvalidId_Fails() {
	resp, err := s.db.PolicyClient.DeleteKeyAccessServer(s.ctx, "definitely-not-a-uuid")
	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
}

func (s *KasRegistrySuite) Test_ListKeyAccessServerGrants_KasId() {
	// create an attribute
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__list_key_access_server_grants_by_kas_id",
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)

	// create a value
	val := &attributes.CreateAttributeValueRequest{
		AttributeId: createdAttr.GetId(),
		Value:       "value2",
	}
	createdVal, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, createdAttr.GetId(), val)
	s.Require().NoError(err)
	s.NotNil(createdVal)

	firstKAS, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri: "https://firstkas.com/kas/uri",
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Cached{
				Cached: &policy.KasPublicKeySet{
					Keys: []*policy.KasPublicKey{
						{
							Pem: "public",
						},
					},
				},
			},
		},
		Name: "first_kas",
	})
	s.Require().NoError(err)
	s.NotNil(firstKAS)
	firstKAS, _ = s.db.PolicyClient.GetKeyAccessServer(s.ctx, firstKAS.GetId())

	otherKAS, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri: "https://otherkas.com/kas/uri",
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Cached{
				Cached: &policy.KasPublicKeySet{
					Keys: []*policy.KasPublicKey{
						{
							Pem: "public",
						},
					},
				},
			},
		},
		// Leave off 'name' to test optionality
	})
	s.Require().NoError(err)
	otherKAS, _ = s.db.PolicyClient.GetKeyAccessServer(s.ctx, otherKAS.GetId())

	// assign a KAS to the attribute
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       createdAttr.GetId(),
		KeyAccessServerId: firstKAS.GetId(),
	}
	createdGrant, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, aKas)
	s.Require().NoError(err)
	s.NotNil(createdGrant)

	// assign a KAS to the value
	bKas := &attributes.ValueKeyAccessServer{
		ValueId:           createdVal.GetId(),
		KeyAccessServerId: otherKAS.GetId(),
	}
	valGrant, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, bKas)
	s.Require().NoError(err)
	s.NotNil(valGrant)

	// list grants by KAS ID
	listedGrants, err := s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, firstKAS.GetId(), "", "")
	s.Require().NoError(err)
	s.NotNil(listedGrants)
	s.Len(listedGrants, 1)
	g := listedGrants[0]
	s.Equal(firstKAS.GetId(), g.GetKeyAccessServer().GetId())
	s.Equal(firstKAS.GetUri(), g.GetKeyAccessServer().GetUri())
	s.Equal(firstKAS.GetName(), g.GetKeyAccessServer().GetName())
	s.Len(g.GetAttributeGrants(), 1)
	s.Empty(g.GetValueGrants())
	s.Empty(g.GetNamespaceGrants())

	// list grants by the other KAS ID
	listedGrants, err = s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, otherKAS.GetId(), "", "")
	s.Require().NoError(err)
	s.NotNil(listedGrants)
	s.Len(listedGrants, 1)
	g = listedGrants[0]
	s.Equal(otherKAS.GetId(), g.GetKeyAccessServer().GetId())
	s.Equal(otherKAS.GetUri(), g.GetKeyAccessServer().GetUri())
	s.Empty(g.GetKeyAccessServer().GetName())
	s.Empty(g.GetAttributeGrants())
	s.Len(g.GetValueGrants(), 1)
	s.Empty(g.GetNamespaceGrants())
}

func (s *KasRegistrySuite) Test_ListKeyAccessServerGrants_KasId_NoResultsIfNotFound() {
	// list grants by KAS ID
	listedGrants, err := s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, nonExistentKasRegistryID, "", "")
	s.Require().NoError(err)
	s.Empty(listedGrants)
}

func (s *KasRegistrySuite) Test_ListKeyAccessServerGrants_KasUri() {
	fixtureKAS := s.f.GetKasRegistryKey("key_access_server_1")

	// create an attribute
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__list_key_access_server_grants_by_kas_uri",
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)

	// add a KAS to the attribute
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       createdAttr.GetId(),
		KeyAccessServerId: fixtureKAS.ID,
	}
	createdGrant, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, aKas)
	s.Require().NoError(err)
	s.NotNil(createdGrant)

	// list grants by KAS URI
	listedGrants, err := s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, "", fixtureKAS.URI, "")

	s.Require().NoError(err)
	s.NotNil(listedGrants)
	s.GreaterOrEqual(len(listedGrants), 1)
	for _, g := range listedGrants {
		s.Equal(fixtureKAS.ID, g.GetKeyAccessServer().GetId())
		s.Equal(fixtureKAS.URI, g.GetKeyAccessServer().GetUri())
		s.Equal(fixtureKAS.Name, g.GetKeyAccessServer().GetName())
	}
}

func (s *KasRegistrySuite) Test_ListKeyAccessServerGrants_KasUri_NoResultsIfNotFound() {
	// list grants by KAS ID
	listedGrants, err := s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, "", "https://notfound.com/kas/uri", "")
	s.Require().NoError(err)
	s.Empty(listedGrants)
}

func (s *KasRegistrySuite) Test_ListKeyAccessServerGrants_KasName() {
	fixtureKAS := s.f.GetKasRegistryKey("key_access_server_acme")

	// create an attribute
	attr := &attributes.CreateAttributeRequest{
		Name:        "test__list_key_access_server_grants_by_kas_name",
		NamespaceId: fixtureNamespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF,
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)

	// add a KAS to the attribute
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       createdAttr.GetId(),
		KeyAccessServerId: fixtureKAS.ID,
	}
	createdGrant, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, aKas)
	s.Require().NoError(err)
	s.NotNil(createdGrant)

	// list grants by KAS URI
	listedGrants, err := s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, "", "", fixtureKAS.Name)

	s.Require().NoError(err)
	s.NotNil(listedGrants)
	s.GreaterOrEqual(len(listedGrants), 1)
	for _, g := range listedGrants {
		s.Equal(fixtureKAS.ID, g.GetKeyAccessServer().GetId())
		s.Equal(fixtureKAS.URI, g.GetKeyAccessServer().GetUri())
		s.Equal(fixtureKAS.Name, g.GetKeyAccessServer().GetName())
	}
}

func (s *KasRegistrySuite) Test_ListKeyAccessServerGrants_KasName_NoResultsIfNotFound() {
	// list grants by KAS ID
	listedGrants, err := s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, "", "", "unknown_kas")
	s.Require().NoError(err)
	s.Empty(listedGrants)
}

func (s *KasRegistrySuite) Test_ListAllKeyAccessServerGrants() {
	// create a KAS
	kas := &kasregistry.CreateKeyAccessServerRequest{
		Uri: "https://listingkasgrants.com/kas/uri",
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Cached{
				Cached: &policy.KasPublicKeySet{
					Keys: []*policy.KasPublicKey{
						{
							Pem: "public",
						},
					},
				},
			},
		},
		Name: "listingkasgrants",
	}
	firstKAS, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, kas)
	s.Require().NoError(err)
	s.NotNil(firstKAS)

	// create a second KAS
	second := &kasregistry.CreateKeyAccessServerRequest{
		Uri: "https://listingkasgrants.com/another/kas/uri",
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Cached{
				Cached: &policy.KasPublicKeySet{
					Keys: []*policy.KasPublicKey{
						{
							Pem: "public",
						},
					},
				},
			},
		},
		Name: "listingkasgrants_second",
	}
	secondKAS, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, second)
	s.Require().NoError(err)
	s.NotNil(secondKAS)

	// create a new namespace
	ns := &namespaces.CreateNamespaceRequest{
		Name: "test__list_all_kas_grants",
	}
	createdNs, err := s.db.PolicyClient.CreateNamespace(s.ctx, ns)
	s.Require().NoError(err)
	s.NotNil(createdNs)
	nsFQN := fmt.Sprintf("https://%s", ns.GetName())

	// create an attribute
	attr := &attributes.CreateAttributeRequest{
		Name:        "test_attr_list_all_kas_grants",
		NamespaceId: createdNs.GetId(),
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
		Values:      []string{"value1"},
	}
	createdAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, attr)
	s.Require().NoError(err)
	s.NotNil(createdAttr)
	attrFQN := fmt.Sprintf("%s/attr/%s", nsFQN, attr.GetName())

	got, err := s.db.PolicyClient.GetAttribute(s.ctx, createdAttr.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	value := got.GetValues()[0]
	valueFQN := fmt.Sprintf("%s/value/%s", attrFQN, value.GetValue())

	// add first KAS to the attribute
	aKas := &attributes.AttributeKeyAccessServer{
		AttributeId:       createdAttr.GetId(),
		KeyAccessServerId: firstKAS.GetId(),
	}
	createdGrant, err := s.db.PolicyClient.AssignKeyAccessServerToAttribute(s.ctx, aKas)
	s.Require().NoError(err)
	s.NotNil(createdGrant)

	// assign a grant of the second KAS to the value
	bKas := &attributes.ValueKeyAccessServer{
		ValueId:           value.GetId(),
		KeyAccessServerId: secondKAS.GetId(),
	}
	valGrant, err := s.db.PolicyClient.AssignKeyAccessServerToValue(s.ctx, bKas)
	s.Require().NoError(err)
	s.NotNil(valGrant)

	// grant each KAS to the namespace
	nsKas := &namespaces.NamespaceKeyAccessServer{
		NamespaceId:       createdNs.GetId(),
		KeyAccessServerId: firstKAS.GetId(),
	}
	nsGrant, err := s.db.PolicyClient.AssignKeyAccessServerToNamespace(s.ctx, nsKas)
	s.Require().NoError(err)
	s.NotNil(nsGrant)

	nsAnotherKas := &namespaces.NamespaceKeyAccessServer{
		NamespaceId:       createdNs.GetId(),
		KeyAccessServerId: secondKAS.GetId(),
	}
	nsAnotherGrant, err := s.db.PolicyClient.AssignKeyAccessServerToNamespace(s.ctx, nsAnotherKas)
	s.Require().NoError(err)
	s.NotNil(nsAnotherGrant)

	// list all grants
	listedGrants, err := s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, "", "", "")
	s.Require().NoError(err)
	s.NotNil(listedGrants)
	s.GreaterOrEqual(len(listedGrants), 2)

	for _, g := range listedGrants {
		switch g.GetKeyAccessServer().GetId() {
		case firstKAS.GetId():
			// should have expected sole attribute grant
			s.Len(g.GetAttributeGrants(), 1)
			s.Equal(createdAttr.GetId(), g.GetAttributeGrants()[0].GetId())
			s.Equal(attrFQN, g.GetAttributeGrants()[0].GetFqn())
			// should have expected sole namespace grant
			s.Len(g.GetNamespaceGrants(), 1)
			s.Equal(createdNs.GetId(), g.GetNamespaceGrants()[0].GetId())
			s.Equal(nsFQN, g.GetNamespaceGrants()[0].GetFqn())
		case secondKAS.GetId():
			// should have expected value grant
			s.Len(g.GetValueGrants(), 1)
			s.Equal(value.GetId(), g.GetValueGrants()[0].GetId())
			s.Equal(valueFQN, g.GetValueGrants()[0].GetFqn())
			// should have expected namespace grant
			s.Len(g.GetNamespaceGrants(), 1)
			s.Equal(createdNs.GetId(), g.GetNamespaceGrants()[0].GetId())
			s.Equal(nsFQN, g.GetNamespaceGrants()[0].GetFqn())
		}
	}
}

func TestKasRegistrySuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping db.KasRegistry integration tests")
	}
	suite.Run(t, new(KasRegistrySuite))
}
