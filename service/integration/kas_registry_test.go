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

// Public Key Tests

func (s *KasRegistrySuite) Test_Create_Public_Key() {
	var publicKeyTestUUID string

	// The initial rsa2048 public key is created in the fixture and should be active
	kID := s.f.GetPublicKey("key_1").ID
	r1, err := s.db.PolicyClient.GetPublicKey(s.ctx, &kasregistry.GetPublicKeyRequest{
		Identifier: &kasregistry.GetPublicKeyRequest_Id{Id: kID},
	})
	s.Require().NoError(err)
	s.NotNil(r1)
	s.True(r1.GetKey().GetIsActive().GetValue())

	kasID := s.f.GetKasRegistryKey("key_access_server_1").ID
	kasRegistry := &kasregistry.CreatePublicKeyRequest{
		KasId: kasID,
		Key: &policy.KasPublicKey{
			Pem: "public",
			Kid: "key-id",
			Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048,
		},
	}

	r2, err := s.db.PolicyClient.CreatePublicKey(s.ctx, kasRegistry)
	s.Require().NoError(err)
	s.NotNil(r2)
	s.Equal(kasID, r2.GetKey().GetKas().GetId())
	s.Equal("public", r2.GetKey().GetPublicKey().GetPem())
	s.True(r2.GetKey().GetIsActive().GetValue())
	publicKeyTestUUID = r2.GetKey().GetId()

	// Now the old key should be inactive
	r3, err := s.db.PolicyClient.GetPublicKey(s.ctx, &kasregistry.GetPublicKeyRequest{
		Identifier: &kasregistry.GetPublicKeyRequest_Id{Id: kID},
	})
	s.Require().NoError(err)
	s.NotNil(r3)
	s.False(r3.GetKey().GetIsActive().GetValue())

	// Check to make sure the new key was mapped to namespaces, definitions and values
	vkms := s.f.GetValueMap(kID)
	dkms := s.f.GetDefinitionKeyMap(kID)
	nkms := s.f.GetNamespaceKeyMap(kID)

	for _, vk := range vkms {
		r, err := s.db.PolicyClient.GetAttributeValue(s.ctx, vk.ValueID)
		s.Require().NoError(err)
		s.NotNil(r)
		s.True(slices.ContainsFunc(r.GetKeys(), func(key *policy.Key) bool {
			return key.GetId() == publicKeyTestUUID
		}))
		s.False(slices.ContainsFunc(r.GetKeys(), func(key *policy.Key) bool {
			return key.GetId() == kID
		}))
	}

	for _, dk := range dkms {
		r, err := s.db.PolicyClient.GetAttribute(s.ctx, dk.DefinitionID)
		s.Require().NoError(err)
		s.NotNil(r)
		s.True(slices.ContainsFunc(r.GetKeys(), func(key *policy.Key) bool {
			return key.GetId() == publicKeyTestUUID
		}))
		s.False(slices.ContainsFunc(r.GetKeys(), func(key *policy.Key) bool {
			return key.GetId() == kID
		}))
	}

	for _, nk := range nkms {
		r, err := s.db.PolicyClient.GetNamespace(s.ctx, nk.NamespaceID)
		s.Require().NoError(err)
		s.NotNil(r)
		s.True(slices.ContainsFunc(r.GetKeys(), func(key *policy.Key) bool {
			return key.GetId() == publicKeyTestUUID
		}))
		s.False(slices.ContainsFunc(r.GetKeys(), func(key *policy.Key) bool {
			return key.GetId() == kID
		}))
	}
}

func (s *KasRegistrySuite) Test_Create_Pulblic_Key_Unique_Constraint() {
	// We can't have a duplicate public keys with the same (key_access_server_id, kid, alg) set
	kasID := s.f.GetKasRegistryKey("key_access_server_1").ID
	kasRegistry := &kasregistry.CreatePublicKeyRequest{
		KasId: kasID,
		Key: &policy.KasPublicKey{
			Pem: "public",
			Kid: "key-unique",
			Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048,
		},
	}

	r, err := s.db.PolicyClient.CreatePublicKey(s.ctx, kasRegistry)
	s.Require().NoError(err)
	s.NotNil(r)

	// Try to create the same key again
	r, err = s.db.PolicyClient.CreatePublicKey(s.ctx, kasRegistry)
	s.Require().Error(err)
	s.Nil(r)
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
}

func (s *KasRegistrySuite) Test_Create_Public_Key_WithInvalidKasID_Fails() {
	kasRegistry := &kasregistry.CreatePublicKeyRequest{
		KasId: "invalid-kas-id",
		Key: &policy.KasPublicKey{
			Pem: "public",
			Kid: "key-id",
			Alg: policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048,
		},
	}

	r, err := s.db.PolicyClient.CreatePublicKey(s.ctx, kasRegistry)
	s.Require().Error(err)
	s.Nil(r)
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
}

func (s *KasRegistrySuite) Test_Update_Public_Key() {
	kID := s.f.GetPublicKey("key_2").ID
	labels := map[string]string{
		"update": "updated label",
	}
	resp, err := s.db.PolicyClient.UpdatePublicKey(s.ctx, &kasregistry.UpdatePublicKeyRequest{
		Id: kID,
		Metadata: &common.MetadataMutable{
			Labels: labels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE,
	})
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(labels, resp.GetKey().GetMetadata().GetLabels())

	// Get Key to validate update
	r, err := s.db.PolicyClient.GetPublicKey(s.ctx, &kasregistry.GetPublicKeyRequest{
		Identifier: &kasregistry.GetPublicKeyRequest_Id{Id: kID},
	})
	s.Require().NoError(err)
	s.NotNil(r)
	s.Equal(labels, r.GetKey().GetMetadata().GetLabels())
}

func (s *KasRegistrySuite) Test_Get_Public_Key() {
	kasID := s.f.GetPublicKey("key_1").KasID
	keyID := s.f.GetPublicKey("key_1").Key.Kid
	id := s.f.GetPublicKey("key_1").ID

	r, err := s.db.PolicyClient.GetPublicKey(s.ctx, &kasregistry.GetPublicKeyRequest{
		Identifier: &kasregistry.GetPublicKeyRequest_Id{Id: id},
	})

	s.Require().NoError(err)
	s.NotNil(r)
	s.Equal(kasID, r.GetKey().GetKas().GetId())
	s.Equal(keyID, r.GetKey().GetPublicKey().GetKid())
	s.Equal(id, r.GetKey().GetId())
}

func (s *KasRegistrySuite) Test_Get_Public_Key_WithInvalidID_Fails() {
	r, err := s.db.PolicyClient.GetPublicKey(s.ctx, &kasregistry.GetPublicKeyRequest{
		Identifier: &kasregistry.GetPublicKeyRequest_Id{Id: "invalid-id"},
	})

	s.Require().Error(err)
	s.Nil(r)
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
}

func (s *KasRegistrySuite) Test_Get_Public_Key_WithNotFoundID_Fails() {
	r, err := s.db.PolicyClient.GetPublicKey(s.ctx, &kasregistry.GetPublicKeyRequest{
		Identifier: &kasregistry.GetPublicKeyRequest_Id{Id: nonExistentKasRegistryID},
	})

	s.Require().Error(err)
	s.Nil(r)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *KasRegistrySuite) Test_List_Public_Keys() {
	r, err := s.db.PolicyClient.ListPublicKeys(s.ctx, &kasregistry.ListPublicKeysRequest{})
	s.Require().NoError(err)
	s.NotNil(r)
	s.GreaterOrEqual(len(r.GetKeys()), 2)
}

func (s *KasRegistrySuite) Test_List_Public_Keys_By_KAS() {
	rAllKeys, err := s.db.PolicyClient.ListPublicKeys(s.ctx, &kasregistry.ListPublicKeysRequest{})
	s.Require().NoError(err)
	s.NotNil(rAllKeys)
	totalKeys := rAllKeys.GetPagination().GetTotal()

	kas1 := s.f.GetKasRegistryKey("key_access_server_1")

	testCases := []struct {
		name           string
		req            *kasregistry.ListPublicKeysRequest
		identifierType string
	}{
		{
			name: "List by KAS ID",
			req: &kasregistry.ListPublicKeysRequest{
				KasFilter: &kasregistry.ListPublicKeysRequest_KasId{
					KasId: kas1.ID,
				},
			},
			identifierType: "KAS ID",
		},
		{
			name: "List by KAS URI",
			req: &kasregistry.ListPublicKeysRequest{
				KasFilter: &kasregistry.ListPublicKeysRequest_KasUri{
					KasUri: kas1.URI,
				},
			},
			identifierType: "KAS URI",
		},
		{
			name: "List by KAS Name",
			req: &kasregistry.ListPublicKeysRequest{
				KasFilter: &kasregistry.ListPublicKeysRequest_KasName{
					KasName: kas1.Name,
				},
			},
			identifierType: "KAS Name",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			rFilteredKeys, err := s.db.PolicyClient.ListPublicKeys(s.ctx, tc.req)
			s.Require().NoError(err, "Failed to list keys by %s", tc.identifierType)
			s.Require().NotNil(rFilteredKeys, "Expected non-nil response when listing keys by %s", tc.identifierType)
			s.GreaterOrEqual(len(rFilteredKeys.GetKeys()), 1, "Expected at least 1 key when listing by %s", tc.identifierType)

			for _, key := range rFilteredKeys.GetKeys() {
				s.Equal(kas1.ID, key.GetKas().GetId(), "Key KAS ID mismatch when listing by %s", tc.identifierType)
			}

			filteredTotalKeys := rFilteredKeys.GetPagination().GetTotal()
			s.NotEqual(totalKeys, filteredTotalKeys, "Total keys should be different after filtering by %s", tc.identifierType)
		})
	}
}

func (s *KasRegistrySuite) Test_List_Public_Keys_WithLimit_1() {
	r, err := s.db.PolicyClient.ListPublicKeys(s.ctx, &kasregistry.ListPublicKeysRequest{
		Pagination: &policy.PageRequest{
			Limit: 1,
		},
	})
	s.Require().NoError(err)
	s.NotNil(r)
	s.Len(r.GetKeys(), 1)
}

func (s *KasRegistrySuite) Test_List_Public_Keys_WithNonExistentKasID() {
	r, err := s.db.PolicyClient.ListPublicKeys(s.ctx, &kasregistry.ListPublicKeysRequest{
		KasFilter: &kasregistry.ListPublicKeysRequest_KasId{
			KasId: nonExistentKasRegistryID,
		},
	})
	s.Require().NoError(err)
	s.NotNil(r)
	s.Empty(r.GetKeys())
}

func (s *KasRegistrySuite) Test_List_Public_Key_Mappings() {
	kasid := s.f.GetPublicKey("key_1").KasID
	id := s.f.GetPublicKey("key_1").ID
	r, err := s.db.PolicyClient.ListPublicKeyMappings(s.ctx, &kasregistry.ListPublicKeyMappingRequest{
		KasFilter: &kasregistry.ListPublicKeyMappingRequest_KasId{
			KasId: kasid,
		},
	})
	s.Require().NoError(err)
	s.NotNil(r)
	s.Len(r.GetPublicKeyMappings(), 1)
	for _, m := range r.GetPublicKeyMappings() {
		s.True(slices.ContainsFunc(m.GetPublicKeys(), func(key *kasregistry.ListPublicKeyMappingResponse_PublicKey) bool {
			return key.GetKey().GetId() == id
		}))
		for _, k := range m.GetPublicKeys() {
			if k.GetKey().GetId() == id {
				s.True(slices.ContainsFunc(k.GetValues(), func(value *kasregistry.ListPublicKeyMappingResponse_Association) bool {
					return value.GetId() == s.f.GetValueMap(id)[0].ValueID
				}))
				s.True(slices.ContainsFunc(k.GetDefinitions(), func(definition *kasregistry.ListPublicKeyMappingResponse_Association) bool {
					return definition.GetId() == s.f.GetDefinitionKeyMap(id)[0].DefinitionID
				}))
				s.True(slices.ContainsFunc(k.GetNamespaces(), func(namespace *kasregistry.ListPublicKeyMappingResponse_Association) bool {
					return namespace.GetId() == s.f.GetNamespaceKeyMap(id)[0].NamespaceID
				}))
			}
		}
	}
}

func (s *KasRegistrySuite) Test_List_Public_Key_Mappings_WithLimit_1() {
	r, err := s.db.PolicyClient.ListPublicKeyMappings(s.ctx, &kasregistry.ListPublicKeyMappingRequest{
		Pagination: &policy.PageRequest{
			Limit: 1,
		},
	})
	s.Require().NoError(err)
	s.NotNil(r)
	s.Len(r.GetPublicKeyMappings(), 1)
}

func (s *KasRegistrySuite) Test_List_Public_Key_Mappings_By_KAS() {
	kas := s.f.GetKasRegistryKey("key_access_server_1")
	pk := s.f.GetPublicKey("key_1")

	testCases := []struct {
		name           string
		req            *kasregistry.ListPublicKeyMappingRequest
		identifierType string
	}{
		{
			name: "List by KAS ID",
			req: &kasregistry.ListPublicKeyMappingRequest{
				KasFilter: &kasregistry.ListPublicKeyMappingRequest_KasId{
					KasId: kas.ID,
				},
			},
			identifierType: "KAS ID",
		},
		{
			name: "List by KAS URI",
			req: &kasregistry.ListPublicKeyMappingRequest{
				KasFilter: &kasregistry.ListPublicKeyMappingRequest_KasUri{
					KasUri: kas.URI,
				},
			},
			identifierType: "KAS URI",
		},
		{
			name: "List by KAS Name",
			req: &kasregistry.ListPublicKeyMappingRequest{
				KasFilter: &kasregistry.ListPublicKeyMappingRequest_KasName{
					KasName: kas.Name,
				},
			},
			identifierType: "KAS Name",
		},
	}

	for _, tc := range testCases {
		s.Run(tc.name, func() {
			r, err := s.db.PolicyClient.ListPublicKeyMappings(s.ctx, tc.req)
			s.Require().NoError(err, "Failed to list mappings by %s", tc.identifierType)
			s.Require().NotNil(r, "Expected non-nil response when listing mappings by %s", tc.identifierType)
			s.Len(r.GetPublicKeyMappings(), 1, "Expected 1 mapping when listing by %s", tc.identifierType) // Assuming fixture setup ensures 1 mapping

			for _, m := range r.GetPublicKeyMappings() {
				s.Equal(kas.ID, m.GetKasId(), "KasId mismatch when listing by %s", tc.identifierType)
				s.Equal(kas.URI, m.GetKasUri(), "KasUri mismatch when listing by %s", tc.identifierType)
				s.Equal(kas.Name, m.GetKasName(), "KasName mismatch when listing by %s", tc.identifierType)
				s.True(slices.ContainsFunc(m.GetPublicKeys(), func(key *kasregistry.ListPublicKeyMappingResponse_PublicKey) bool {
					return key.GetKey().GetId() == pk.ID
				}), "PublicKey not found in mappings when listing by %s", tc.identifierType)
			}
		})
	}
}

func (s *KasRegistrySuite) Test_List_Public_Key_Mapping_By_PublicKey_ID() {
	id := s.f.GetPublicKey("key_1").ID
	r, err := s.db.PolicyClient.ListPublicKeyMappings(s.ctx, &kasregistry.ListPublicKeyMappingRequest{PublicKeyId: id})
	s.Require().NoError(err)
	s.NotNil(r)

	for _, m := range r.GetPublicKeyMappings() {
		s.True(slices.ContainsFunc(m.GetPublicKeys(), func(key *kasregistry.ListPublicKeyMappingResponse_PublicKey) bool {
			return key.GetKey().GetId() == id
		}))
	}
}

func (s *KasRegistrySuite) Test_Deactivate_Public_Key() {
	id := s.f.GetPublicKey("key_4").ID
	r, err := s.db.PolicyClient.DeactivatePublicKey(s.ctx, &kasregistry.DeactivatePublicKeyRequest{Id: id})
	s.Require().NoError(err)
	s.NotNil(r)
	s.Equal(id, r.GetKey().GetId())

	rr, err := s.db.PolicyClient.GetPublicKey(s.ctx, &kasregistry.GetPublicKeyRequest{
		Identifier: &kasregistry.GetPublicKeyRequest_Id{Id: id},
	})
	s.Require().NoError(err)
	s.NotNil(rr)
	s.False(rr.GetKey().GetIsActive().GetValue())
}

func (s *KasRegistrySuite) Test_Deactivate_Public_Key_WithInvalidID_Fails() {
	r, err := s.db.PolicyClient.DeactivatePublicKey(s.ctx, &kasregistry.DeactivatePublicKeyRequest{Id: "invalid-id"})
	s.Require().Error(err)
	s.Nil(r)
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
}

func (s *KasRegistrySuite) Test_Activate_Public_Key() {
	id := s.f.GetPublicKey("key_4").ID
	r, err := s.db.PolicyClient.ActivatePublicKey(s.ctx, &kasregistry.ActivatePublicKeyRequest{Id: id})
	s.Require().NoError(err)
	s.NotNil(r)
	s.Equal(id, r.GetKey().GetId())

	rr, err := s.db.PolicyClient.GetPublicKey(s.ctx, &kasregistry.GetPublicKeyRequest{
		Identifier: &kasregistry.GetPublicKeyRequest_Id{Id: id},
	})
	s.Require().NoError(err)
	s.NotNil(rr)
	s.True(rr.GetKey().GetIsActive().GetValue())
}

func (s *KasRegistrySuite) Test_Activate_Public_Key_WithInvalidID_Fails() {
	r, err := s.db.PolicyClient.ActivatePublicKey(s.ctx, &kasregistry.ActivatePublicKeyRequest{Id: "invalid-id"})
	s.Require().Error(err)
	s.Nil(r)
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
}

func (s *KasRegistrySuite) Test_UnsafeDelete_Public_Key() {
	id := s.f.GetPublicKey("key_1").ID
	r, err := s.db.PolicyClient.UnsafeDeleteKey(s.ctx, &unsafe.UnsafeDeletePublicKeyRequest{Id: id})
	s.Require().NoError(err)
	s.NotNil(r)
	s.Equal(id, r.GetId())

	rr, err := s.db.PolicyClient.GetPublicKey(s.ctx, &kasregistry.GetPublicKeyRequest{
		Identifier: &kasregistry.GetPublicKeyRequest_Id{Id: id},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
	s.Nil(rr)
}

func (s *KasRegistrySuite) Test_Assign_and_Unassign_Public_Key() {
	value := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value1")
	def := s.f.GetAttributeKey("example.net/attr/attr1")
	ns := s.f.GetNamespaceKey("example.net")

	id := s.f.GetPublicKey("key_1").ID

	// Assign to value
	err := s.db.PolicyClient.AssignPublicKeyToNamespace(s.ctx, &namespaces.NamespaceKey{NamespaceId: ns.ID, KeyId: id})
	s.Require().NoError(err)

	err = s.db.PolicyClient.AssignPublicKeyToAttribute(s.ctx, &attributes.AttributeKey{AttributeId: def.ID, KeyId: id})
	s.Require().NoError(err)

	err = s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &attributes.ValueKey{ValueId: value.ID, KeyId: id})
	s.Require().NoError(err)

	// Get Namespace to validate assignment
	n, err := s.db.PolicyClient.GetNamespace(s.ctx, ns.ID)
	s.Require().NoError(err)
	s.NotNil(n)
	s.True(slices.ContainsFunc(n.GetKeys(), func(key *policy.Key) bool {
		return key.GetId() == id
	}))

	// Get Attribute to validate assignment
	d, err := s.db.PolicyClient.GetAttribute(s.ctx, def.ID)
	s.Require().NoError(err)
	s.NotNil(d)
	s.True(slices.ContainsFunc(d.GetKeys(), func(key *policy.Key) bool {
		return key.GetId() == id
	}))

	// Get Value to validate assignment
	v, err := s.db.PolicyClient.GetAttributeValue(s.ctx, value.ID)
	s.Require().NoError(err)
	s.NotNil(v)
	s.True(slices.ContainsFunc(v.GetKeys(), func(key *policy.Key) bool {
		return key.GetId() == id
	}))

	// Unassign from value
	vk, err := s.db.PolicyClient.RemovePublicKeyFromValue(s.ctx, &attributes.ValueKey{ValueId: value.ID, KeyId: id})
	s.Require().NoError(err)
	s.NotNil(vk)

	// Unassign from attribute
	dk, err := s.db.PolicyClient.RemovePublicKeyFromAttribute(s.ctx, &attributes.AttributeKey{AttributeId: def.ID, KeyId: id})
	s.Require().NoError(err)
	s.NotNil(dk)

	// Unassign from namespace
	nk, err := s.db.PolicyClient.RemovePublicKeyFromNamespace(s.ctx, &namespaces.NamespaceKey{NamespaceId: ns.ID, KeyId: id})
	s.Require().NoError(err)
	s.NotNil(nk)

	// Get Namespace to validate unassignment
	n, err = s.db.PolicyClient.GetNamespace(s.ctx, ns.ID)
	s.Require().NoError(err)
	s.NotNil(n)
	s.False(slices.ContainsFunc(n.GetKeys(), func(key *policy.Key) bool {
		return key.GetId() == id
	}))

	// Get Attribute to validate unassignment
	d, err = s.db.PolicyClient.GetAttribute(s.ctx, def.ID)
	s.Require().NoError(err)
	s.NotNil(d)
	s.False(slices.ContainsFunc(d.GetKeys(), func(key *policy.Key) bool {
		return key.GetId() == id
	}))

	// Get Value to validate unassignment
	v, err = s.db.PolicyClient.GetAttributeValue(s.ctx, value.ID)
	s.Require().NoError(err)
	s.NotNil(v)
	s.False(slices.ContainsFunc(v.GetKeys(), func(key *policy.Key) bool {
		return key.GetId() == id
	}))
}

func TestKasRegistrySuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping db.KasRegistry integration tests")
	}
	suite.Run(t, new(KasRegistrySuite))
}
