package integration

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"

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
				s.validateKasRegistryKeys(kasr)
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
		s.validateKasRegistryKeys(kas)
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
			s.validateKasRegistryKeys(resp)

			switch tc.expected {
			case remoteFixture:
				s.Equal(tc.expected.PubKey.Remote, resp.GetPublicKey().GetRemote(), "PublicKey.Remote mismatch for %s: %v", tc.identifierType, tc.input)
			case localFixture:
				s.Equal(tc.expected.PubKey.Cached, resp.GetPublicKey().GetCached(), "PublicKey.Cached mismatch for %s: %v", tc.identifierType, tc.input)
			default:
				s.Fail("Unexpected fixture in test case: " + tc.name) // Should not happen, but good to have for safety
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

	sourceType := policy.SourceType_SOURCE_TYPE_INTERNAL

	kasRegistry := &kasregistry.CreateKeyAccessServerRequest{
		Uri:        "kas.uri",
		PublicKey:  pubKey,
		Metadata:   metadata,
		SourceType: sourceType,
		// Leave off 'name' to test optionality
	}
	r, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	s.Require().NoError(err)
	s.NotNil(r)
	s.NotEmpty(r.GetId())
	s.Equal(sourceType, r.GetSourceType())
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
	s.NotEmpty(k.GetId())

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
	s.NotEmpty(k.GetId())

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
	s.NotEmpty(k.GetId())

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
	s.NotEmpty(r.GetId())
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
	sourceType := policy.SourceType_SOURCE_TYPE_INTERNAL

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
		SourceType: sourceType,
		// Leave off 'name' to test optionality
	})
	s.Require().NoError(err)
	s.NotNil(created)

	initialGot, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(initialGot)

	updatedSourceType := policy.SourceType_SOURCE_TYPE_EXTERNAL

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
		SourceType:             updatedSourceType,
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
	s.Equal(updatedSourceType, got.GetSourceType())
}

func (s *KasRegistrySuite) Test_UpdateKeyAccessServer_Metadata_DoesNotAlterOtherValues() {
	uri := "before_metadata_only.com"
	pubKeyRemote := "https://remote.com/key"
	name := "kas-name-not-changed"
	sourceType := policy.SourceType_SOURCE_TYPE_INTERNAL

	// create a test KAS
	created, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri: uri,
		PublicKey: &policy.PublicKey{
			PublicKey: &policy.PublicKey_Remote{
				Remote: pubKeyRemote,
			},
		},
		Name:       name,
		SourceType: sourceType,
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
	s.Equal(sourceType, got.GetSourceType())
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
	s.Empty(got.GetPublicKey().GetRemote())
	s.Equal("unchanged label", got.GetMetadata().GetLabels()["unchanged"])
}

func (s *KasRegistrySuite) Test_UpdateKeyAccessServer_UpdatingSourceTypeUnspecified_Fails() {
	uri := "random_uri.com"
	sourceType := policy.SourceType_SOURCE_TYPE_INTERNAL

	// create a test KAS
	created, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri: uri,
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"unchanged": "unchanged label",
			},
		},
		SourceType: sourceType,
		// Leave off 'name' to test optionality
	})
	s.Require().NoError(err)
	s.NotNil(created)

	// update it with new key
	_, err = s.db.PolicyClient.UpdateKeyAccessServer(s.ctx, created.GetId(), &kasregistry.UpdateKeyAccessServerRequest{
		SourceType: policy.SourceType_SOURCE_TYPE_UNSPECIFIED,
	})
	s.Require().Error(err)
	s.Require().ErrorContains(err, db.ErrorTextUpdateToUnspecified)

	// get after update to validate changes were successful
	got, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Equal(uri, got.GetUri())
	s.Empty(got.GetName())
	s.Empty(got.GetPublicKey().GetRemote())
	s.Equal("unchanged label", got.GetMetadata().GetLabels()["unchanged"])
	s.Equal(sourceType, got.GetSourceType())
}

func (s *KasRegistrySuite) Test_UpdateKeyAccessServer_UnspecifiedSourceType_DoesNotAlterSourceType() {
	uri := "another_random.com"
	sourceType := policy.SourceType_SOURCE_TYPE_INTERNAL
	name := "kas-name-random"
	nameChanged := "name-changed"

	// create a test KAS
	created, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri:  uri,
		Name: name,
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"unchanged": "unchanged label",
			},
		},
		SourceType: sourceType,
		// Leave off 'name' to test optionality
	})
	s.Require().NoError(err)
	s.NotNil(created)

	// update it with new key
	updated, err := s.db.PolicyClient.UpdateKeyAccessServer(s.ctx, created.GetId(), &kasregistry.UpdateKeyAccessServerRequest{
		Name:       nameChanged,
		SourceType: policy.SourceType_SOURCE_TYPE_UNSPECIFIED,
	})
	s.Require().NoError(err)
	s.NotNil(updated)

	// get after update to validate changes were successful
	got, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.Equal(sourceType, got.GetSourceType())
	s.Equal(nameChanged, got.GetName())
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

func (s *KasRegistrySuite) Test_DeleteKeyAccessServer_WithChildKeys_Fails() {
	pubKey := &policy.PublicKey{
		PublicKey: &policy.PublicKey_Remote{
			Remote: "https://remote.com/key",
		},
	}
	testKas := &kasregistry.CreateKeyAccessServerRequest{
		Uri:       "trying-to-delete.net",
		PublicKey: pubKey,
	}
	createdKas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, testKas)
	s.Require().NoError(err)
	s.NotNil(createdKas)

	// create a child key
	keyID := "a-random-key-id"
	createdKey, err := s.db.PolicyClient.CreateKey(s.ctx, &kasregistry.CreateKeyRequest{
		KasId:        createdKas.GetId(),
		KeyId:        keyID,
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P521,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{
			Pem: keyCtx,
		},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			KeyId:      keyID,
			WrappedKey: keyCtx,
		},
	})

	s.Require().NoError(err)
	s.NotNil(createdKey)

	resp, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, createdKas.GetId())
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Len(resp.GetKasKeys(), 1)

	deleted, err := s.db.PolicyClient.DeleteKeyAccessServer(s.ctx, createdKas.GetId())
	s.Require().Error(err)
	s.Require().ErrorContains(err, db.ErrForeignKeyViolation.Error())
	s.Nil(deleted)

	// Remove key to clean up
	_, err = s.db.PolicyClient.DeleteKey(s.ctx, createdKey.GetKasKey().GetKey().GetId())
	s.Require().NoError(err)

	// Delete the KAS
	_, err = s.db.PolicyClient.DeleteKeyAccessServer(s.ctx, createdKas.GetId())
	s.Require().NoError(err)
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

func (s *KasRegistrySuite) getKasRegistryFixtures() []fixtures.FixtureDataKasRegistry {
	return []fixtures.FixtureDataKasRegistry{
		s.f.GetKasRegistryKey("key_access_server_1"),
		s.f.GetKasRegistryKey("key_access_server_2"),
	}
}

func (s *KasRegistrySuite) getKasRegistryServerKeysFixtures() []fixtures.FixtureDataKasRegistryKey {
	return []fixtures.FixtureDataKasRegistryKey{
		s.f.GetKasRegistryServerKeys("kas_key_1"),
		s.f.GetKasRegistryServerKeys("kas_key_2"),
	}
}

func (s *KasRegistrySuite) getKasToKeysFixtureMap() map[string][]*policy.KasKey {
	// map kas id to keys
	kasToKeys := make(map[string][]*policy.KasKey)
	for _, k := range s.getKasRegistryServerKeysFixtures() {
		if kasToKeys[k.KeyAccessServerID] == nil {
			kasToKeys[k.KeyAccessServerID] = make([]*policy.KasKey, 0)
		}
		key, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{Id: k.ID})
		s.Require().NoError(err)
		kasToKeys[k.KeyAccessServerID] = append(kasToKeys[k.KeyAccessServerID], key)
	}
	return kasToKeys
}

func (s *KasRegistrySuite) validateKasRegistryKeys(kasr *policy.KeyAccessServer) {
	kasToKeysFixtures := s.getKasToKeysFixtureMap()
	// Check that key is present.
	expectedKasKeys := kasToKeysFixtures[kasr.GetId()]
	s.GreaterOrEqual(len(kasr.GetKasKeys()), len(expectedKasKeys))
	// Check for expected key ids.
	matchingKeysCount := 0
	for _, kasKey := range kasr.GetKasKeys() {
		for _, f := range expectedKasKeys {
			if kasKey.GetPublicKey().GetKid() == f.GetKey().GetKeyId() {
				validateSimpleKasKey(&s.Suite, f, kasKey)
				matchingKeysCount++
			}
		}
	}
	s.Len(expectedKasKeys, matchingKeysCount)
}

func TestKasRegistrySuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping db.KasRegistry integration tests")
	}
	suite.Run(t, new(KasRegistrySuite))
}
