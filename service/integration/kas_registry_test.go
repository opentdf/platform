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
	"google.golang.org/protobuf/proto"

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

func (s *KasRegistrySuite) Test_ListKeyAccessServers_NoPagination_Succeeds() {
	fixtures := s.getKasRegistryFixtures()
	listRsp, err := s.db.PolicyClient.ListKeyAccessServers(s.ctx, &kasregistry.ListKeyAccessServersRequest{})
	s.Require().NoError(err)
	s.NotNil(listRsp)

	listed := listRsp.GetKeyAccessServers()
	s.NotEmpty(listed)

	// ensure we find each fixture in the list response
	for _, f := range fixtures {
		found := false
		for _, kasr := range listed {
			if kasr.GetId() == f.ID {
				found = true
			}
		}
		s.True(found)
	}
}

func (s *KasRegistrySuite) Test_ListKeyAccessServers_Limit_Succeeds() {
	var limit int32 = 2
	listRsp, err := s.db.PolicyClient.ListKeyAccessServers(s.ctx, &kasregistry.ListKeyAccessServersRequest{
		Pagination: &policy.PageRequest{
			Limit: limit,
		},
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)

	listed := listRsp.GetKeyAccessServers()
	s.Equal(len(listed), int(limit))

	for _, kas := range listed {
		s.NotEmpty(kas.GetId())
		s.NotEmpty(kas.GetUri())
		s.NotNil(kas.GetPublicKey())
	}

	// request with one below maximum
	listRsp, err = s.db.PolicyClient.ListKeyAccessServers(s.ctx, &kasregistry.ListKeyAccessServersRequest{
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax - 1,
		},
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)
}

func (s *NamespacesSuite) Test_ListKeyAccessServers_Limit_TooLarge_Fails() {
	listRsp, err := s.db.PolicyClient.ListKeyAccessServers(s.ctx, &kasregistry.ListKeyAccessServersRequest{
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax + 1,
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrListLimitTooLarge)
	s.Nil(listRsp)
}

func (s *KasRegistrySuite) Test_ListKeyAccessServers_Offset_Succeeds() {
	req := &kasregistry.ListKeyAccessServersRequest{}
	// make initial list request to compare against
	listRsp, err := s.db.PolicyClient.ListKeyAccessServers(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(listRsp)
	listed := listRsp.GetKeyAccessServers()

	// set the offset pagination
	offset := 1
	req.Pagination = &policy.PageRequest{
		Offset: int32(offset),
	}
	offsetListRsp, err := s.db.PolicyClient.ListKeyAccessServers(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(offsetListRsp)
	offsetListed := offsetListRsp.GetKeyAccessServers()

	// length is reduced by the offset amount
	s.Equal(len(offsetListed), len(listed)-offset)

	// objects are equal between offset and original list beginning at offset index
	for i, val := range offsetListed {
		s.True(proto.Equal(val, listed[i+offset]))
	}
}

func (s *KasRegistrySuite) Test_GetKeyAccessServer() {
	remoteFixture := s.f.GetKasRegistryKey("key_access_server_1")
	localFixture := s.f.GetKasRegistryKey("key_access_server_2")

	testCases := []struct {
		name           string
		input          interface{} // Can be string or struct
		expected       fixtures.FixtureDataKasRegistry
		identifierType string // For clearer test case names
	}{
		{
			name:           "Deprecated ID - Remote",
			input:          remoteFixture.ID,
			expected:       remoteFixture,
			identifierType: "ID",
		},
		{
			name:           "Deprecated ID - Local",
			input:          localFixture.ID,
			expected:       localFixture,
			identifierType: "ID",
		},
		{
			name:           "Name Identifier - Remote",
			input:          &kasregistry.GetKeyAccessServerRequest_Name{Name: remoteFixture.Name},
			expected:       remoteFixture,
			identifierType: "Name",
		},
		{
			name:           "Name Identifier - Local",
			input:          &kasregistry.GetKeyAccessServerRequest_Name{Name: localFixture.Name},
			expected:       localFixture,
			identifierType: "Name",
		},
		{
			name:           "URI Identifier - Remote",
			input:          &kasregistry.GetKeyAccessServerRequest_Uri{Uri: remoteFixture.URI},
			expected:       remoteFixture,
			identifierType: "URI",
		},
		{
			name:           "URI Identifier - Local",
			input:          &kasregistry.GetKeyAccessServerRequest_Uri{Uri: localFixture.URI},
			expected:       localFixture,
			identifierType: "URI",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			resp, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, tc.input)
			s.Require().NoError(err, "Failed to get KeyAccessServer by %s: %v", tc.identifierType, tc.input)
			s.Require().NotNil(resp, "Expected non-nil response for %s: %v", tc.identifierType, tc.input)

			s.Equal(tc.expected.ID, resp.GetId(), "ID mismatch for %s: %v", tc.identifierType, tc.input)
			s.Equal(tc.expected.URI, resp.GetUri(), "URI mismatch for %s: %v", tc.identifierType, tc.input)
			s.Equal(tc.expected.Name, resp.GetName(), "Name mismatch for %s: %v", tc.identifierType, tc.input)

			switch tc.expected {
			case remoteFixture:
				s.Equal(tc.expected.PubKey.Remote, resp.GetPublicKey().GetRemote(), "PublicKey.Remote mismatch for %s: %v", tc.identifierType, tc.input)
			case localFixture:
				s.Equal(tc.expected.PubKey.Cached, resp.GetPublicKey().GetCached(), "PublicKey.Cached mismatch for %s: %v", tc.identifierType, tc.input)
			default:
				s.Fail("Unexpected fixture in test case: %s", tc.name) // Should not happen, but good to have for safety
			}
		})
	}
}

func (s *KasRegistrySuite) Test_GetKeyAccessServer_WithNonExistentId_Fails() {
	testCases := []struct {
		name  string
		input interface{}
	}{
		{
			name:  "string non-existent UUID",
			input: nonExistentKasRegistryID,
		},
		{
			name: "struct non-existent UUID",
			input: &kasregistry.GetKeyAccessServerRequest_KasId{
				KasId: nonExistentKasRegistryID,
			},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			resp, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, tc.input)
			s.Require().Error(err, "Expected an error for input: %s", tc.input)
			s.Nil(resp, "Expected nil response for input: %s", tc.input)
			s.Require().ErrorIs(err, db.ErrNotFound, "Expected ErrNotFound for input: %s", tc.input)
		})
	}
}

func (s *KasRegistrySuite) Test_GetKeyAccessServer_WithInvalidID_Fails() {
	testCases := []struct {
		name  string
		input interface{}
	}{
		{
			name:  "string invalid UUID",
			input: "hello",
		},
		{
			name:  "struct invalid UUID",
			input: &kasregistry.GetKeyAccessServerRequest_KasId{KasId: "hello"},
		},
		{
			name:  "empty string",
			input: "",
		},
		{
			name:  "struct empty string",
			input: &kasregistry.GetKeyAccessServerRequest_KasId{KasId: ""},
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			resp, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, tc.input)
			s.Require().Error(err)
			s.Nil(resp)
			s.Require().ErrorIs(err, db.ErrUUIDInvalid)
		})
	}
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
	listRsp, err := s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, &kasregistry.ListKeyAccessServerGrantsRequest{
		KasId: firstKAS.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)

	listedGrants := listRsp.GetGrants() //nolint:staticcheck // still needed for testing
	s.Len(listedGrants, 1)
	g := listedGrants[0]
	s.Equal(firstKAS.GetId(), g.GetKeyAccessServer().GetId())
	s.Equal(firstKAS.GetUri(), g.GetKeyAccessServer().GetUri())
	s.Equal(firstKAS.GetName(), g.GetKeyAccessServer().GetName())
	s.Len(g.GetAttributeGrants(), 1)
	s.Empty(g.GetValueGrants())
	s.Empty(g.GetNamespaceGrants())

	// list grants by the other KAS ID
	listRsp, err = s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, &kasregistry.ListKeyAccessServerGrantsRequest{
		KasId: otherKAS.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)

	listedGrants = listRsp.GetGrants() //nolint:staticcheck // still needed for testing
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
	listRsp, err := s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, &kasregistry.ListKeyAccessServerGrantsRequest{
		KasId: nonExistentKasRegistryID,
	})
	s.Require().NoError(err)
	s.Empty(listRsp.GetGrants()) //nolint:staticcheck // still needed for testing
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
	listGrantsRsp, err := s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, &kasregistry.ListKeyAccessServerGrantsRequest{
		KasUri: fixtureKAS.URI,
	})
	s.Require().NoError(err)
	s.NotNil(listGrantsRsp)
	listedGrants := listGrantsRsp.GetGrants() //nolint:staticcheck // still needed for testing
	s.GreaterOrEqual(len(listedGrants), 1)
	for _, g := range listedGrants {
		s.Equal(fixtureKAS.ID, g.GetKeyAccessServer().GetId())
		s.Equal(fixtureKAS.URI, g.GetKeyAccessServer().GetUri())
		s.Equal(fixtureKAS.Name, g.GetKeyAccessServer().GetName())
	}
}

func (s *KasRegistrySuite) Test_ListKeyAccessServerGrants_KasUri_NoResultsIfNotFound() {
	// list grants by KAS ID
	listGrantsRsp, err := s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, &kasregistry.ListKeyAccessServerGrantsRequest{
		KasUri: "https://notfound.com/kas/uri",
	})
	s.Require().NoError(err)
	s.Empty(listGrantsRsp.GetGrants()) //nolint:staticcheck // still needed for testing
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
	listedGrantsRsp, err := s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx,
		&kasregistry.ListKeyAccessServerGrantsRequest{
			KasName: fixtureKAS.Name,
		})

	s.Require().NoError(err)
	s.NotNil(listedGrantsRsp)
	listedGrants := listedGrantsRsp.GetGrants() //nolint:staticcheck // still needed for testing
	s.GreaterOrEqual(len(listedGrants), 1)
	found := false
	for _, g := range listedGrants {
		if g.GetKeyAccessServer().GetId() == fixtureKAS.ID {
			s.Equal(fixtureKAS.URI, g.GetKeyAccessServer().GetUri())
			s.Equal(fixtureKAS.Name, g.GetKeyAccessServer().GetName())
			for _, attrGrant := range g.GetAttributeGrants() {
				if attrGrant.GetId() == createdAttr.GetId() {
					found = true
					s.Equal(attrGrant.GetFqn(), createdAttr.GetFqn())
				}
			}
		}
	}
	s.True(found)
}

func (s *KasRegistrySuite) Test_ListKeyAccessServerGrants_KasName_NoResultsIfNotFound() {
	// list grants by KAS ID
	listGrantsRsp, err := s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, &kasregistry.ListKeyAccessServerGrantsRequest{
		KasName: "unknown-name",
	})
	s.Require().NoError(err)
	s.Empty(listGrantsRsp.GetGrants()) //nolint:staticcheck // still needed for testing
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
	listGrantsRsp, err := s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, &kasregistry.ListKeyAccessServerGrantsRequest{})
	s.Require().NoError(err)
	s.NotNil(listGrantsRsp)
	listedGrants := listGrantsRsp.GetGrants() //nolint:staticcheck // still needed for testing
	s.GreaterOrEqual(len(listedGrants), 1)

	s.GreaterOrEqual(len(listedGrants), 2)
	foundCount := 0
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

			foundCount++

		case secondKAS.GetId():
			// should have expected value grant
			s.Len(g.GetValueGrants(), 1)
			s.Equal(value.GetId(), g.GetValueGrants()[0].GetId())
			s.Equal(valueFQN, g.GetValueGrants()[0].GetFqn())
			// should have expected namespace grant
			s.Len(g.GetNamespaceGrants(), 1)
			s.Equal(createdNs.GetId(), g.GetNamespaceGrants()[0].GetId())
			s.Equal(nsFQN, g.GetNamespaceGrants()[0].GetFqn())

			foundCount++
		}
	}
	s.Equal(2, foundCount)
}

func (s *KasRegistrySuite) Test_ListKeyAccessServerGrants_Limit_Succeeds() {
	var limit int32 = 2
	listRsp, err := s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, &kasregistry.ListKeyAccessServerGrantsRequest{
		Pagination: &policy.PageRequest{
			Limit: limit,
		},
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)

	listed := listRsp.GetGrants() //nolint:staticcheck // still needed for testing
	s.Equal(len(listed), int(limit))

	for _, grant := range listed {
		s.NotNil(grant.GetKeyAccessServer())
	}

	// request with one below maximum
	listRsp, err = s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, &kasregistry.ListKeyAccessServerGrantsRequest{
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax - 1,
		},
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)
}

func (s *NamespacesSuite) Test_ListKeyAccessServerGrants_Limit_TooLarge_Fails() {
	listRsp, err := s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, &kasregistry.ListKeyAccessServerGrantsRequest{
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax + 1,
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrListLimitTooLarge)
	s.Nil(listRsp)
}

func (s *KasRegistrySuite) Test_ListKeyAccessServerGrants_Offset_Succeeds() {
	req := &kasregistry.ListKeyAccessServerGrantsRequest{}
	// make initial list request to compare against
	listRsp, err := s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(listRsp)
	listed := listRsp.GetGrants() //nolint:staticcheck // still needed for testing

	// set the offset pagination
	offset := 1
	req.Pagination = &policy.PageRequest{
		Offset: int32(offset),
	}
	offsetListRsp, err := s.db.PolicyClient.ListKeyAccessServerGrants(s.ctx, req)
	s.Require().NoError(err)
	s.NotNil(offsetListRsp)
	offsetListed := offsetListRsp.GetGrants() //nolint:staticcheck // still needed for testing

	// length is reduced by the offset amount
	s.Equal(len(offsetListed), len(listed)-offset)

	// objects are equal between offset and original list beginning at offset index
	for i, val := range offsetListed {
		s.True(proto.Equal(val, listed[i+offset]))
	}
}

func TestKasRegistrySuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping db.KasRegistry integration tests")
	}
	suite.Run(t, new(KasRegistrySuite))
}
