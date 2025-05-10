package integration

import (
	"context"
	"encoding/base64"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/keymanagement"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	validProviderConfigName  = "provider_config_name"
	validProviderConfigName2 = "provider_config_name_2"
	validProviderConfigName3 = "provider_config_name_3"
	validKeyID1              = "key_id_1"
	validKeyID2              = "key_id_2"
	validKeyID3              = "key_id_3"
	keyID4                   = "key_id_4"
	notFoundKasUUID          = "123e4567-e89b-12d3-a456-426614174000"
	keyCtx                   = `eyJrZXkiOiJ2YWx1ZSJ9Cg==`
	providerConfigID         = "123e4567-e89b-12d3-a456-426614174000"
	rotateKey                = "rotate_key"
	nonRotateKey             = "non_rotate_key"
	rotatePrefix             = "rotate_"
	nonRotatePrefix          = "non_rotate_"
)

type KasRegistryKeySuite struct {
	suite.Suite
	f           fixtures.Fixtures
	db          fixtures.DBInterface
	kasFixtures []fixtures.FixtureDataKasRegistry
	kasKeys     []fixtures.FixtureDataKasRegistryKey
	ctx         context.Context //nolint:containedctx // context is used in the test suite
}

func (s *KasRegistryKeySuite) SetupSuite() {
	slog.Info("setting up db.KasKeys test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_kas_keys"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
	s.kasFixtures = s.getKasRegistryFixtures()
	s.kasKeys = s.getKasRegistryServerKeysFixtures()
}

func (s *KasRegistryKeySuite) TearDownSuite() {
	slog.Info("tearing down db.KasKeys test suite")
	s.f.TearDown()
}

func TestKasRegistryKeysSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping db.KasRegistryKeys integration tests")
	}
	suite.Run(t, new(KasRegistryKeySuite))
}

func validatePublicKeyCtx(s *suite.Suite, expectedPubCtx []byte, actual *policy.KasKey) {
	decodedExpectedPubCtx, err := base64.StdEncoding.DecodeString(string(expectedPubCtx))
	s.Require().NoError(err)

	var expectedPub policy.KasPublicKeyCtx
	err = protojson.Unmarshal(decodedExpectedPubCtx, &expectedPub)
	s.Require().NoError(err)
	s.Equal(expectedPub.GetPem(), actual.GetKey().GetPublicKeyCtx().GetPem())
}

func validatePrivatePublicCtx(s *suite.Suite, expectedPrivCtx, expectedPubCtx []byte, actual *policy.KasKey) {
	decodedExpectedPrivCtx, err := base64.StdEncoding.DecodeString(string(expectedPrivCtx))
	s.Require().NoError(err)

	var expectedPriv policy.KasPrivateKeyCtx
	err = protojson.Unmarshal(decodedExpectedPrivCtx, &expectedPriv)
	s.Require().NoError(err)

	s.Equal(expectedPriv.GetKeyId(), actual.GetKey().GetPrivateKeyCtx().GetKeyId())
	s.Equal(expectedPriv.GetWrappedKey(), actual.GetKey().GetPrivateKeyCtx().GetWrappedKey())
	validatePublicKeyCtx(s, expectedPubCtx, actual)
}

func (s *KasRegistryKeySuite) Test_CreateKasKey_InvalidKasId_Fail() {
	req := kasregistry.CreateKeyRequest{
		KasId:        notFoundKasUUID,
		KeyId:        validKeyID1,
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_4096,
		KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
		PublicKeyCtx: &policy.KasPublicKeyCtx{
			Pem: keyCtx,
		},
	}
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().Error(err)
	s.Require().ErrorContains(err, db.ErrForeignKeyViolation.Error())
	s.Nil(resp)
}

func (s *KasRegistryKeySuite) Test_CreateKasKey_ProviderConfigInvalid_Fail() {
	req := kasregistry.CreateKeyRequest{
		KasId:            s.kasKeys[0].KeyAccessServerID,
		KeyId:            validKeyID1,
		KeyAlgorithm:     policy.Algorithm_ALGORITHM_RSA_4096,
		KeyMode:          policy.KeyMode_KEY_MODE_REMOTE,
		PublicKeyCtx:     &policy.KasPublicKeyCtx{Pem: keyCtx},
		ProviderConfigId: providerConfigID,
	}
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorContains(err, db.ErrTextNotFound)
}

func (s *KasRegistryKeySuite) Test_CreateKasKey_ActiveKeyForAlgoExists_Fail() {
	req := kasregistry.CreateKeyRequest{
		KasId:        s.kasKeys[0].KeyAccessServerID,
		KeyId:        validKeyID1,
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
		PublicKeyCtx: &policy.KasPublicKeyCtx{Pem: keyCtx},
	}
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().Error(err)
	s.Require().ErrorContains(err, "cannot create a new key")
	s.Nil(resp)
}

func (s *KasRegistryKeySuite) Test_CreateKasKey_NonBase64Ctx_Fail() {
	nonBase64Ctx := `{"pem: "value"}`
	req := kasregistry.CreateKeyRequest{
		KasId:        s.kasKeys[0].KeyAccessServerID,
		KeyId:        validKeyID1,
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
		PublicKeyCtx: &policy.KasPublicKeyCtx{Pem: nonBase64Ctx},
	}
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().Error(err)
	s.Require().ErrorContains(err, db.ErrExpectedBase64EncodedValue.Error())
	s.Nil(resp)

	req = kasregistry.CreateKeyRequest{
		KasId:         s.kasKeys[0].KeyAccessServerID,
		KeyId:         validKeyID1,
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
		PublicKeyCtx:  &policy.KasPublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.KasPrivateKeyCtx{WrappedKey: nonBase64Ctx, KeyId: validKeyID1},
	}
	resp, err = s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().Error(err)
	s.Require().ErrorContains(err, db.ErrExpectedBase64EncodedValue.Error())
	s.Nil(resp)
}

func (s *KasRegistryKeySuite) Test_CreateKasKey_Success() {
	// Create KAS server
	req := kasregistry.CreateKeyRequest{
		KasId:        s.kasKeys[0].KeyAccessServerID,
		KeyId:        keyID4,
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
		PublicKeyCtx: &policy.KasPublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.KasPrivateKeyCtx{
			WrappedKey: keyCtx,
			KeyId:      validKeyID1,
		},
	}
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(s.kasKeys[0].KeyAccessServerID, resp.GetKasKey().GetKasId())
	s.Equal(keyCtx, resp.GetKasKey().GetKey().GetPublicKeyCtx().GetPem())
	s.Equal(keyCtx, resp.GetKasKey().GetKey().GetPrivateKeyCtx().GetWrappedKey())
	s.Equal(validKeyID1, resp.GetKasKey().GetKey().GetPrivateKeyCtx().GetKeyId())
	s.Nil(resp.GetKasKey().GetKey().GetProviderConfig())

	_, err = s.db.PolicyClient.DeleteKey(s.ctx, resp.GetKasKey().GetKey().GetId())
	s.Require().NoError(err)
}

func (s *KasRegistryKeySuite) Test_GetKasKey_InvalidId_Fail() {
	resp, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{
		Id: "invalid-uuid",
	})
	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorContains(err, db.ErrUUIDInvalid.Error())
}

func (s *KasRegistryKeySuite) Test_GetKasKey_InvalidIdentifier_Fail() {
	resp, err := s.db.PolicyClient.GetKey(s.ctx, &keymanagement.GetProviderConfigRequest_Id{
		Id: "",
	})
	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorContains(err, db.ErrUnknownSelectIdentifier.Error())
}

func (s *KasRegistryKeySuite) Test_GetKasKeyById_Success() {
	resp, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{
		Id: s.kasKeys[0].ID,
	})
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(s.kasKeys[0].KeyAccessServerID, resp.GetKasId())
	s.Equal(s.kasKeys[0].ID, resp.GetKey().GetId())
	s.Equal(s.kasKeys[0].ProviderConfigID, resp.GetKey().GetProviderConfig().GetId())
}

func (s *KasRegistryKeySuite) Test_GetKasKeyByKey_WrongKas_Fail() {
	kasReq := kasregistry.CreateKeyAccessServerRequest{
		Name: "test",
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasReq)
	s.Require().NoError(err)
	s.NotNil(kas)
	resp, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Key{
		Key: &kasregistry.KasKeyIdentifier{
			Identifier: &kasregistry.KasKeyIdentifier_KasId{
				KasId: kas.GetId(),
			},
			Kid: s.kasKeys[0].KeyID,
		},
	})
	s.Require().ErrorContains(err, db.ErrNotFound.Error())
	s.Nil(resp)

	_, err = s.db.PolicyClient.DeleteKeyAccessServer(s.ctx, kas.GetId())
	s.Require().NoError(err)
}

func (s *KasRegistryKeySuite) Test_GetKasKeyByKey_NoKeyIdInKas_Fail() {
	resp, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Key{
		Key: &kasregistry.KasKeyIdentifier{
			Identifier: &kasregistry.KasKeyIdentifier_KasId{
				KasId: s.kasKeys[0].KeyAccessServerID,
			},
			Kid: "a-random-key-id",
		},
	})
	s.Require().ErrorContains(err, db.ErrNotFound.Error())
	s.Nil(resp)
}

func (s *KasRegistryKeySuite) Test_GetKasKeyByKeyId_Success() {
	resp, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Key{
		Key: &kasregistry.KasKeyIdentifier{
			Identifier: &kasregistry.KasKeyIdentifier_KasId{
				KasId: s.kasKeys[0].KeyAccessServerID,
			},
			Kid: s.kasKeys[0].KeyID,
		},
	})
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(s.kasKeys[0].KeyAccessServerID, resp.GetKasId())
	s.Equal(s.kasKeys[0].ID, resp.GetKey().GetId())
	validatePrivatePublicCtx(&s.Suite, []byte(s.kasKeys[0].PrivateKeyCtx), []byte(s.kasKeys[0].PublicKeyCtx), resp)
	s.Equal(s.kasKeys[0].ProviderConfigID, resp.GetKey().GetProviderConfig().GetId())
}

func (s *KasRegistryKeySuite) Test_GetKasKey_WithKasName_Success() {
	kasServer, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, &kasregistry.GetKeyAccessServerRequest_KasId{
		KasId: s.kasKeys[0].KeyAccessServerID,
	})
	s.Require().NoError(err)
	s.Require().NotNil(kasServer)

	resp, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Key{
		Key: &kasregistry.KasKeyIdentifier{
			Identifier: &kasregistry.KasKeyIdentifier_Name{
				Name: kasServer.GetName(),
			},
			Kid: s.kasKeys[0].KeyID,
		},
	})
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(s.kasKeys[0].KeyAccessServerID, resp.GetKasId())
	s.Equal(s.kasKeys[0].ID, resp.GetKey().GetId())
	validatePrivatePublicCtx(&s.Suite, []byte(s.kasKeys[0].PrivateKeyCtx), []byte(s.kasKeys[0].PublicKeyCtx), resp)
	s.Equal(s.kasKeys[0].ProviderConfigID, resp.GetKey().GetProviderConfig().GetId())
}

func (s *KasRegistryKeySuite) Test_GetKasKey_WithKasUri_Success() {
	kasServer, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, &kasregistry.GetKeyAccessServerRequest_KasId{
		KasId: s.kasKeys[0].KeyAccessServerID,
	})
	s.Require().NoError(err)
	s.Require().NotNil(kasServer)

	resp, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Key{
		Key: &kasregistry.KasKeyIdentifier{
			Identifier: &kasregistry.KasKeyIdentifier_Uri{
				Uri: kasServer.GetUri(),
			},
			Kid: s.kasKeys[0].KeyID,
		},
	})
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(s.kasKeys[0].KeyAccessServerID, resp.GetKasId())
	s.Equal(s.kasKeys[0].ID, resp.GetKey().GetId())
	validatePrivatePublicCtx(&s.Suite, []byte(s.kasKeys[0].PrivateKeyCtx), []byte(s.kasKeys[0].PublicKeyCtx), resp)
	s.Require().NoError(err)
	s.Equal(s.kasKeys[0].ProviderConfigID, resp.GetKey().GetProviderConfig().GetId())
}

func (s *KasRegistryKeySuite) Test_UpdateKey_InvalidKeyId_Fails() {
	req := kasregistry.UpdateKeyRequest{
		Id: "",
	}
	resp, err := s.db.PolicyClient.UpdateKey(s.ctx, &req)
	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorContains(err, db.ErrUUIDInvalid.Error())
}

func (s *KasRegistryKeySuite) Test_UpdateKey_AlreadyActiveKeyWithSameAlgo_Fails() {
	req := kasregistry.UpdateKeyRequest{
		Id:        s.kasKeys[1].ID,
		KeyStatus: policy.KeyStatus_KEY_STATUS_ACTIVE,
	}
	resp, err := s.db.PolicyClient.UpdateKey(s.ctx, &req)
	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorContains(err, "key cannot be updated")
}

func (s *KasRegistryKeySuite) Test_UpdateKeyStatus_Success() {
	req := kasregistry.UpdateKeyRequest{
		Id:        s.kasKeys[1].ID,
		KeyStatus: policy.KeyStatus_KEY_STATUS_COMPROMISED,
	}
	resp, err := s.db.PolicyClient.UpdateKey(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(s.kasKeys[1].ID, resp.GetKey().GetId())
}

func (s *KasRegistryKeySuite) Test_UpdateKeyMetadata_Success() {
	req := kasregistry.UpdateKeyRequest{
		Id: s.kasKeys[1].ID,
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{"key": "value"},
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	}
	resp, err := s.db.PolicyClient.UpdateKey(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(s.kasKeys[1].ID, resp.GetKey().GetId())
}

func (s *KasRegistryKeySuite) Test_ListKeys_InvalidLimit_Fail() {
	req := kasregistry.ListKeysRequest{
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax + 1,
		},
	}
	resp, err := s.db.PolicyClient.ListKeys(s.ctx, &req)
	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorContains(err, db.ErrListLimitTooLarge.Error())
}

func (s *KasRegistryKeySuite) validateListKeysResponse(resp *kasregistry.ListKeysResponse, err error) {
	s.Require().NoError(err)
	s.NotNil(resp)
	s.GreaterOrEqual(len(resp.GetKasKeys()), 2)
	s.GreaterOrEqual(int32(2), resp.GetPagination().GetTotal())

	for _, key := range resp.GetKasKeys() {
		var fixtureKey *fixtures.FixtureDataKasRegistryKey

		for _, kasKey := range s.kasKeys {
			if kasKey.ID == key.GetKey().GetId() {
				fixtureKey = &kasKey
				break
			}
		}

		s.Require().NotNil(fixtureKey, "No matching KAS key found for ID: %s", key.GetKey().GetId())
		s.Equal(fixtureKey.KeyAccessServerID, key.GetKasId())
		s.Equal(fixtureKey.ID, key.GetKey().GetId())
		s.Equal(fixtureKey.ProviderConfigID, key.GetKey().GetProviderConfig().GetId())
		validatePrivatePublicCtx(&s.Suite, []byte(fixtureKey.PrivateKeyCtx), []byte(fixtureKey.PublicKeyCtx), key)
		s.Require().NoError(err)
	}
}

func (s *KasRegistryKeySuite) Test_ListKeys_KasID_Success() {
	req := kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasId{
			KasId: s.kasKeys[0].KeyAccessServerID,
		},
	}
	resp, err := s.db.PolicyClient.ListKeys(s.ctx, &req)
	s.validateListKeysResponse(resp, err)
}

func (s *KasRegistryKeySuite) Test_ListKeys_KasName_Success() {
	req := kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasName{
			KasName: s.kasFixtures[0].Name,
		},
	}
	resp, err := s.db.PolicyClient.ListKeys(s.ctx, &req)
	s.validateListKeysResponse(resp, err)
}

func (s *KasRegistryKeySuite) Test_ListKeys_KasURI_Success() {
	req := kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasUri{
			KasUri: s.kasFixtures[0].URI,
		},
	}
	resp, err := s.db.PolicyClient.ListKeys(s.ctx, &req)
	s.validateListKeysResponse(resp, err)
}

func (s *KasRegistryKeySuite) Test_ListKeys_FilterAlgo_NoKeysWithAlgo_Success() {
	req := kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasId{
			KasId: s.kasFixtures[0].ID,
		},
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P521,
	}
	resp, err := s.db.PolicyClient.ListKeys(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Empty(resp.GetKasKeys())
}

func (s *KasRegistryKeySuite) Test_ListKeys_FilterAlgo_TwoKeys_Success() {
	req := kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasUri{
			KasUri: s.kasFixtures[0].URI,
		},
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
	}
	resp, err := s.db.PolicyClient.ListKeys(s.ctx, &req)
	s.validateListKeysResponse(resp, err)
}

func (s *KasRegistryKeySuite) Test_ListKeys_KasID_Limit_Success() {
	req := kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasUri{
			KasUri: s.kasFixtures[0].URI,
		},
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		Pagination: &policy.PageRequest{
			Limit: 1,
		},
	}
	resp, err := s.db.PolicyClient.ListKeys(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Len(resp.GetKasKeys(), 1)
	s.GreaterOrEqual(int32(2), resp.GetPagination().GetTotal())
	s.Equal(int32(1), resp.GetPagination().GetNextOffset())
	s.Equal(int32(0), resp.GetPagination().GetCurrentOffset())
}

func (s *KasRegistryKeySuite) setupNamespaceForRotate(numNSToRotate, numNSToNotRotate int, keyToRotate, secondKey *policy.AsymmetricKey) map[string][]*policy.Namespace {
	namespacesToRotate := make([]*policy.Namespace, numNSToRotate)
	namespacesToNotRotate := make([]*policy.Namespace, numNSToNotRotate)

	for i := 0; i < numNSToRotate+numNSToNotRotate; i++ {
		if i < numNSToRotate {
			// Create a namespace
			nsReq := namespaces.CreateNamespaceRequest{
				Name: rotatePrefix + uuid.New().String(),
			}
			namespaceWithKeyToRotate, err := s.db.PolicyClient.CreateNamespace(s.ctx, &nsReq)
			s.Require().NoError(err)
			s.NotNil(namespaceWithKeyToRotate)

			assignKeyReq := namespaces.NamespaceKey{
				NamespaceId: namespaceWithKeyToRotate.GetId(),
				KeyId:       keyToRotate.GetId(),
			}
			namespace, err := s.db.PolicyClient.AssignPublicKeyToNamespace(s.ctx, &assignKeyReq)
			s.Require().NoError(err)
			s.NotNil(namespace)

			namespacesToRotate[i] = namespaceWithKeyToRotate
		} else {
			nsReq2 := namespaces.CreateNamespaceRequest{
				Name: nonRotatePrefix + uuid.New().String(),
			}
			namespaceWithoutKeyToRotate, err := s.db.PolicyClient.CreateNamespace(s.ctx, &nsReq2)
			s.Require().NoError(err)
			s.NotNil(namespaceWithoutKeyToRotate)

			assignKeyReq2 := namespaces.NamespaceKey{
				NamespaceId: namespaceWithoutKeyToRotate.GetId(),
				KeyId:       secondKey.GetId(),
			}
			namespace2, err := s.db.PolicyClient.AssignPublicKeyToNamespace(s.ctx, &assignKeyReq2)
			s.Require().NoError(err)
			s.NotNil(namespace2)
			namespacesToNotRotate[i-numNSToRotate] = namespaceWithoutKeyToRotate
		}
	}
	return map[string][]*policy.Namespace{
		rotateKey:    namespacesToRotate,
		nonRotateKey: namespacesToNotRotate,
	}
}

func (s *KasRegistryKeySuite) setupKeysForRotate(kasID string) map[string]*policy.KasKey {
	// Create a key for the KAS
	keyReq := kasregistry.CreateKeyRequest{
		KasId:        kasID,
		KeyId:        "original_key_id_to_rotate",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
		PublicKeyCtx: &policy.KasPublicKeyCtx{
			Pem: keyCtx,
		},
		PrivateKeyCtx: &policy.KasPrivateKeyCtx{
			KeyId:      validKeyID1,
			WrappedKey: keyCtx,
		},
	}
	keyToRotate, err := s.db.PolicyClient.CreateKey(s.ctx, &keyReq)
	s.Require().NoError(err)
	s.NotNil(rotateKey)

	keyReq2 := kasregistry.CreateKeyRequest{
		KasId:        kasID,
		KeyId:        "second_original_key_id",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
		PublicKeyCtx: &policy.KasPublicKeyCtx{
			Pem: keyCtx,
		},
		PrivateKeyCtx: &policy.KasPrivateKeyCtx{
			KeyId:      validKeyID2,
			WrappedKey: keyCtx,
		},
	}
	secondKey, err := s.db.PolicyClient.CreateKey(s.ctx, &keyReq2)
	s.Require().NoError(err)
	s.NotNil(secondKey)

	return map[string]*policy.KasKey{
		rotateKey:    keyToRotate.GetKasKey(),
		nonRotateKey: secondKey.GetKasKey(),
	}
}

func (s *KasRegistryKeySuite) setupAttributesForRotate(numAttrsToRotate, numAttrsToNotRotate, numAttrValuesToRotate, numAttrsValuesToNotRotate int, namespaceMap map[string][]*policy.Namespace, keyToRotate, keyNotRotated *policy.AsymmetricKey) map[string][]*policy.Attribute {
	attributesToRotate := make([]*policy.Attribute, numAttrsToRotate)
	attributesToNotRotate := make([]*policy.Attribute, numAttrsToNotRotate)

	if (numAttrValuesToRotate > 1 && numAttrsToRotate == 0) || (numAttrsValuesToNotRotate > 1 && numAttrsToNotRotate == 0) {
		s.Fail("Invalid test setup: if there are multiple attribute values, there must be at least on attribute")
	}

	if len(namespaceMap[rotateKey]) == 0 || len(namespaceMap[nonRotateKey]) == 0 {
		s.Fail("Should at least have one namespace for rotating and non-rotating")
	}

	for i := 0; i < numAttrsToRotate+numAttrsToNotRotate; i++ {
		if i < numAttrsToRotate {
			attrValueNames := make([]string, 0)
			if i == 0 {
				// Create all the attribute values for the first attribute
				for j := 0; j < numAttrValuesToRotate; j++ {
					attrValueNames = append(attrValueNames, rotatePrefix+uuid.NewString())
				}
			}

			// Create a namespace
			attrReq := attributes.CreateAttributeRequest{
				NamespaceId: namespaceMap[rotateKey][0].GetId(),
				Name:        rotatePrefix + uuid.NewString(),
				Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
				Values:      attrValueNames,
			}
			rotateAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attrReq)
			s.Require().NoError(err)
			s.NotNil(rotateAttr)

			assignKeyToAttrReq := attributes.AttributeKey{
				AttributeId: rotateAttr.GetId(),
				KeyId:       keyToRotate.GetId(),
			}
			attribute, err := s.db.PolicyClient.AssignPublicKeyToAttribute(s.ctx, &assignKeyToAttrReq)
			s.Require().NoError(err)
			s.NotNil(attribute)

			attributesToRotate[i] = rotateAttr
		} else {
			attrValueNames := make([]string, 0)
			if i-numAttrValuesToRotate == 0 {
				// Create all the attribute values for the first attribute
				for j := 0; j < numAttrValuesToRotate; j++ {
					attrValueNames = append(attrValueNames, nonRotatePrefix+uuid.NewString())
				}
			}
			attrReq := attributes.CreateAttributeRequest{
				NamespaceId: namespaceMap[nonRotateKey][0].GetId(),
				Name:        nonRotatePrefix + uuid.NewString(),
				Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
				Values:      attrValueNames,
			}
			noRotateAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attrReq)
			s.Require().NoError(err)
			s.NotNil(noRotateAttr)

			assignKeyToAttrReq := attributes.AttributeKey{
				AttributeId: noRotateAttr.GetId(),
				KeyId:       keyNotRotated.GetId(),
			}
			attribute, err := s.db.PolicyClient.AssignPublicKeyToAttribute(s.ctx, &assignKeyToAttrReq)
			s.Require().NoError(err)
			s.NotNil(attribute)
			attributesToNotRotate[i-numAttrsToNotRotate] = noRotateAttr
		}
	}
	// Go through and assing the values to public keys
	for _, value := range attributesToRotate[0].GetValues() {
		if value.GetId() == "" {
			continue
		}
		assignKeyToAttrValueReq := attributes.ValueKey{
			ValueId: value.GetId(),
			KeyId:   keyToRotate.GetId(),
		}
		_, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &assignKeyToAttrValueReq)
		s.Require().NoError(err)
	}
	for _, value := range attributesToNotRotate[0].GetValues() {
		if value.GetId() == "" {
			continue
		}
		assignKeyToAttrValueReq := attributes.ValueKey{
			ValueId: value.GetId(),
			KeyId:   keyNotRotated.GetId(),
		}
		_, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &assignKeyToAttrValueReq)
		s.Require().NoError(err)
	}

	return map[string][]*policy.Attribute{
		rotateKey:    attributesToRotate,
		nonRotateKey: attributesToNotRotate,
	}
}

func (s *KasRegistryKeySuite) cleanupRotate(attrValueIDs []string, namespaceIDs []string, attributeIDs []string, keyIDs []string, keyAccessServerIDs []string) {
	for _, id := range attrValueIDs {
		_, err := s.db.PolicyClient.DeleteAttributeValue(s.ctx, id)
		s.Require().NoError(err)
	}
	for _, id := range namespaceIDs {
		_, err := s.db.PolicyClient.DeleteNamespace(s.ctx, id)
		s.Require().NoError(err)
	}
	for _, id := range attributeIDs {
		_, err := s.db.PolicyClient.DeleteAttribute(s.ctx, id)
		s.Require().NoError(err)
	}
	for _, id := range keyIDs {
		_, err := s.db.PolicyClient.DeleteKey(s.ctx, id)
		s.Require().NoError(err)
	}
	for _, id := range keyAccessServerIDs {
		_, err := s.db.PolicyClient.DeleteKeyAccessServer(s.ctx, id)
		s.Require().NoError(err)
	}
}

func (s *KasRegistryKeySuite) Test_RotateKey_Multiple_Attributes_Values_Namespaces_Success() {
	// Create a new KAS server
	kasReq := kasregistry.CreateKeyAccessServerRequest{
		Name: "test_rotate_key_kas",
		Uri:  "https://test-rotate-key.opentdf.io",
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasReq)
	s.Require().NoError(err)
	s.NotNil(kas)

	keyMap := s.setupKeysForRotate(kas.GetId())
	namespaceMap := s.setupNamespaceForRotate(1, 1, keyMap[rotateKey].GetKey(), keyMap[nonRotateKey].GetKey())
	attributeMap := s.setupAttributesForRotate(1, 1, 1, 1, namespaceMap, keyMap[rotateKey].GetKey(), keyMap[nonRotateKey].GetKey())

	newKey := kasregistry.RotateKeyRequest_NewKey{
		KeyId:        "new_key_id",
		Algorithm:    policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
		PublicKeyCtx: &policy.KasPublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.KasPrivateKeyCtx{
			KeyId:      validKeyID1,
			WrappedKey: keyCtx,
		},
	}

	rotatedInKey, err := s.db.PolicyClient.RotateKey(s.ctx, keyMap[rotateKey], &newKey)
	s.Require().NoError(err)
	s.NotNil(rotatedInKey)

	// Validate the rotated key
	s.Equal(newKey.GetKeyId(), rotatedInKey.GetKasKey().GetKey().GetKeyId())
	s.Equal(newKey.GetAlgorithm(), rotatedInKey.GetKasKey().GetKey().GetKeyAlgorithm())
	s.Equal(newKey.GetKeyMode(), rotatedInKey.GetKasKey().GetKey().GetKeyMode())
	s.Equal(newKey.GetPublicKeyCtx().GetPem(), rotatedInKey.GetKasKey().GetKey().GetPublicKeyCtx().GetPem())
	s.Equal(newKey.GetPrivateKeyCtx().GetKeyId(), rotatedInKey.GetKasKey().GetKey().GetPrivateKeyCtx().GetKeyId())
	s.Equal(newKey.GetPrivateKeyCtx().GetWrappedKey(), rotatedInKey.GetKasKey().GetKey().GetPrivateKeyCtx().GetWrappedKey())
	s.Equal(policy.KeyStatus_KEY_STATUS_ACTIVE, rotatedInKey.GetKasKey().GetKey().GetKeyStatus())

	// Validate the rotated resources in the response.
	s.Equal(rotatedInKey.GetRotatedResources().GetRotatedOutKey().GetKey().GetId(), keyMap[rotateKey].GetKey().GetId())
	s.Len(rotatedInKey.GetRotatedResources().GetAttributeDefinitionMappings(), 1)
	s.Len(rotatedInKey.GetRotatedResources().GetNamespaceMappings(), 1)
	s.Len(rotatedInKey.GetRotatedResources().GetAttributeValueMappings(), 1)
	s.Equal(attributeMap[rotateKey][0].GetId(), rotatedInKey.GetRotatedResources().GetAttributeDefinitionMappings()[0].GetId())
	s.Equal(attributeMap[rotateKey][0].GetFqn(), rotatedInKey.GetRotatedResources().GetAttributeDefinitionMappings()[0].GetFqn())
	s.Equal(namespaceMap[rotateKey][0].GetId(), rotatedInKey.GetRotatedResources().GetNamespaceMappings()[0].GetId())
	s.Equal(namespaceMap[rotateKey][0].GetFqn(), rotatedInKey.GetRotatedResources().GetNamespaceMappings()[0].GetFqn())
	s.Equal(attributeMap[rotateKey][0].GetValues()[0].GetId(), rotatedInKey.GetRotatedResources().GetAttributeValueMappings()[0].GetId())
	s.Equal(attributeMap[rotateKey][0].GetValues()[0].GetFqn(), rotatedInKey.GetRotatedResources().GetAttributeValueMappings()[0].GetFqn())

	// Verify that the old key is now inactive
	oldKey, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{
		Id: keyMap[rotateKey].GetKey().GetId(),
	})
	s.Require().NoError(err)
	s.Equal(policy.KeyStatus_KEY_STATUS_INACTIVE, oldKey.GetKey().GetKeyStatus())

	// Verify that namespace has the new key
	updatedNs, err := s.db.PolicyClient.GetNamespace(s.ctx, namespaceMap[rotateKey][0].GetId())
	s.Require().NoError(err)
	s.Len(updatedNs.GetKasKeys(), 1)
	s.Equal(rotatedInKey.GetKasKey().GetKey().GetId(), updatedNs.GetKasKeys()[0].GetKey().GetId())

	// Verify that namespace which was assigned a key that was not rotated is still intact
	nonUpdatedNs, err := s.db.PolicyClient.GetNamespace(s.ctx, namespaceMap[nonRotateKey][0].GetId())
	s.Require().NoError(err)
	s.Len(nonUpdatedNs.GetKasKeys(), 1)
	s.Equal(keyMap[nonRotateKey].GetKey().GetId(), nonUpdatedNs.GetKasKeys()[0].GetKey().GetId())

	// Verify that attribute has the new key
	updatedAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, &attributes.GetAttributeRequest_AttributeId{
		AttributeId: attributeMap[rotateKey][0].GetId(),
	})
	s.Require().NoError(err)
	s.Len(updatedAttr.GetKasKeys(), 1)
	s.Equal(rotatedInKey.GetKasKey().GetKey().GetId(), updatedAttr.GetKasKeys()[0].GetKey().GetId())

	// Verify that attribute definition which was assigned a key that was not rotated is still intact
	nonUpdatedAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, &attributes.GetAttributeRequest_AttributeId{
		AttributeId: attributeMap[nonRotateKey][0].GetId(),
	})
	s.Require().NoError(err)
	s.Len(nonUpdatedAttr.GetKasKeys(), 1)
	s.Equal(keyMap[nonRotateKey].GetKey().GetId(), nonUpdatedAttr.GetKasKeys()[0].GetKey().GetId())

	// Verify that attribute value has the new key
	attrValue, err := s.db.PolicyClient.GetAttributeValue(s.ctx, &attributes.GetAttributeValueRequest_ValueId{
		ValueId: attributeMap[rotateKey][0].GetValues()[0].GetId(),
	})
	s.Require().NoError(err)
	s.Len(attrValue.GetKasKeys(), 1)
	s.Equal(rotatedInKey.GetKasKey().GetKey().GetId(), attrValue.GetKasKeys()[0].GetKey().GetId())

	// Verify that attribute value which was assigned a key that was not rotated is still intact
	nonUpdatedAttrValue, err := s.db.PolicyClient.GetAttributeValue(s.ctx, &attributes.GetAttributeValueRequest_ValueId{
		ValueId: attributeMap[nonRotateKey][0].GetValues()[0].GetId(),
	})
	s.Require().NoError(err)
	s.Len(nonUpdatedAttrValue.GetKasKeys(), 1)
	s.Equal(keyMap[nonRotateKey].GetKey().GetId(), nonUpdatedAttrValue.GetKasKeys()[0].GetKey().GetId())

	// Clean up
	s.cleanupRotate(
		[]string{attrValue.GetId(), nonUpdatedAttrValue.GetId()},
		[]string{namespaceMap[rotateKey][0].GetId(), namespaceMap[nonRotateKey][0].GetId()},
		[]string{attributeMap[rotateKey][0].GetId(), attributeMap[nonRotateKey][0].GetId()},
		[]string{keyMap[rotateKey].GetKey().GetId(), keyMap[nonRotateKey].GetKey().GetId(), rotatedInKey.GetKasKey().GetKey().GetId()},
		[]string{kas.GetId()},
	)
}

// Should probably add a test where there are more than one of each attribute granularity to be rotated and make sure I get them
// For example, 2 attributes, 0 namespaces, 1 attribute value.
func (s *KasRegistryKeySuite) Test_RotateKey_Two_Attribute_Two_Namespace_0_AttributeValue_Success() {
	// Create a new KAS server
	kasReq := kasregistry.CreateKeyAccessServerRequest{
		Name: "test_rotate_key_kas",
		Uri:  "https://test-rotate-key.opentdf.io",
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasReq)
	s.Require().NoError(err)
	s.NotNil(kas)

	keyMap := s.setupKeysForRotate(kas.GetId())
	namespaceMap := s.setupNamespaceForRotate(2, 2, keyMap[rotateKey].GetKey(), keyMap[nonRotateKey].GetKey())
	attributeMap := s.setupAttributesForRotate(2, 2, 0, 0, namespaceMap, keyMap[rotateKey].GetKey(), keyMap[nonRotateKey].GetKey())

	newKey := kasregistry.RotateKeyRequest_NewKey{
		KeyId:        "new_key_id",
		Algorithm:    policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
		PublicKeyCtx: &policy.KasPublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.KasPrivateKeyCtx{
			KeyId:      validKeyID1,
			WrappedKey: keyCtx,
		},
	}

	rotatedInKey, err := s.db.PolicyClient.RotateKey(s.ctx, keyMap[rotateKey], &newKey)
	s.Require().NoError(err)
	s.NotNil(rotatedInKey)

	// Validate the rotated key
	s.Equal(newKey.GetKeyId(), rotatedInKey.GetKasKey().GetKey().GetKeyId())
	s.Equal(newKey.GetAlgorithm(), rotatedInKey.GetKasKey().GetKey().GetKeyAlgorithm())
	s.Equal(newKey.GetKeyMode(), rotatedInKey.GetKasKey().GetKey().GetKeyMode())
	s.Equal(newKey.GetPublicKeyCtx().GetPem(), rotatedInKey.GetKasKey().GetKey().GetPublicKeyCtx().GetPem())
	s.Equal(newKey.GetPrivateKeyCtx().GetKeyId(), rotatedInKey.GetKasKey().GetKey().GetPrivateKeyCtx().GetKeyId())
	s.Equal(newKey.GetPrivateKeyCtx().GetWrappedKey(), rotatedInKey.GetKasKey().GetKey().GetPrivateKeyCtx().GetWrappedKey())
	s.Equal(policy.KeyStatus_KEY_STATUS_ACTIVE, rotatedInKey.GetKasKey().GetKey().GetKeyStatus())

	// Validate the rotated resources in the response.
	s.Equal(rotatedInKey.GetRotatedResources().GetRotatedOutKey().GetKey().GetId(), keyMap[rotateKey].GetKey().GetId())
	s.Len(rotatedInKey.GetRotatedResources().GetAttributeDefinitionMappings(), 2)
	s.Len(rotatedInKey.GetRotatedResources().GetNamespaceMappings(), 2)
	s.Empty(rotatedInKey.GetRotatedResources().GetAttributeValueMappings())

	rotatedAttributeIDs := make([]string, 0)
	rotatedAttributeFQNs := make([]string, 0)
	for _, rotatedAttribute := range rotatedInKey.GetRotatedResources().GetAttributeDefinitionMappings() {
		rotatedAttributeIDs = append(rotatedAttributeIDs, rotatedAttribute.GetId())
		rotatedAttributeFQNs = append(rotatedAttributeFQNs, rotatedAttribute.GetFqn())
	}
	for _, attr := range attributeMap[rotateKey] {
		s.Contains(rotatedAttributeIDs, attr.GetId())
		s.Contains(rotatedAttributeFQNs, attr.GetFqn())
	}

	rotatedNamespaceIDs := make([]string, 0)
	rotatedNamespaceFQNs := make([]string, 0)
	for _, rotatedNamespace := range rotatedInKey.GetRotatedResources().GetNamespaceMappings() {
		rotatedNamespaceIDs = append(rotatedNamespaceIDs, rotatedNamespace.GetId())
		rotatedNamespaceFQNs = append(rotatedNamespaceFQNs, rotatedNamespace.GetFqn())
	}
	for _, ns := range namespaceMap[rotateKey] {
		s.Contains(rotatedNamespaceIDs, ns.GetId())
		s.Contains(rotatedNamespaceFQNs, ns.GetFqn())
	}

	// Verify that the old key is now inactive
	oldKey, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{
		Id: keyMap[rotateKey].GetKey().GetId(),
	})
	s.Require().NoError(err)
	s.Equal(policy.KeyStatus_KEY_STATUS_INACTIVE, oldKey.GetKey().GetKeyStatus())

	// Verify that namespace has the new key
	for _, ns := range namespaceMap[rotateKey] {
		updatedNs, err := s.db.PolicyClient.GetNamespace(s.ctx, ns.GetId())
		s.Require().NoError(err)
		s.Len(updatedNs.GetKasKeys(), 1)
		s.Equal(rotatedInKey.GetKasKey().GetKey().GetId(), updatedNs.GetKasKeys()[0].GetKey().GetId())
	}

	// Verify that namespace which was assigned a key that was not rotated is still intact
	for _, ns := range namespaceMap[nonRotateKey] {
		nonUpdatedNs, err := s.db.PolicyClient.GetNamespace(s.ctx, ns.GetId())
		s.Require().NoError(err)
		s.Len(nonUpdatedNs.GetKasKeys(), 1)
		s.Equal(keyMap[nonRotateKey].GetKey().GetId(), nonUpdatedNs.GetKasKeys()[0].GetKey().GetId())
	}

	// Verify that attribute has the new key
	for _, attr := range attributeMap[rotateKey] {
		updatedAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, &attributes.GetAttributeRequest_AttributeId{
			AttributeId: attr.GetId(),
		})
		s.Require().NoError(err)
		s.Len(updatedAttr.GetKasKeys(), 1)
		s.Equal(rotatedInKey.GetKasKey().GetKey().GetId(), updatedAttr.GetKasKeys()[0].GetKey().GetId())
	}

	// Verify that attribute definition which was assigned a key that was not rotated is still intact
	for _, attr := range attributeMap[nonRotateKey] {
		nonUpdatedAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, &attributes.GetAttributeRequest_AttributeId{
			AttributeId: attr.GetId(),
		})
		s.Require().NoError(err)
		s.Len(nonUpdatedAttr.GetKasKeys(), 1)
		s.Equal(keyMap[nonRotateKey].GetKey().GetId(), nonUpdatedAttr.GetKasKeys()[0].GetKey().GetId())
	}

	// Clean up
	namespaceIDs := make([]string, 0)
	attributeIDs := make([]string, 0)
	for _, ns := range namespaceMap[rotateKey] {
		namespaceIDs = append(namespaceIDs, ns.GetId())
	}
	for _, ns := range namespaceMap[nonRotateKey] {
		namespaceIDs = append(namespaceIDs, ns.GetId())
	}
	for _, attr := range attributeMap[rotateKey] {
		attributeIDs = append(attributeIDs, attr.GetId())
	}
	for _, attr := range attributeMap[nonRotateKey] {
		attributeIDs = append(attributeIDs, attr.GetId())
	}

	s.cleanupRotate(
		[]string{},
		namespaceIDs,
		attributeIDs,
		[]string{keyMap[rotateKey].GetKey().GetId(), keyMap[nonRotateKey].GetKey().GetId(), rotatedInKey.GetKasKey().GetKey().GetId()},
		[]string{kas.GetId()},
	)
}

func (s *KasRegistryKeySuite) Test_RotateKey_NoAttributeKeyMapping_Success() {
	kasReq := kasregistry.CreateKeyAccessServerRequest{
		Name: "test_rotate_key_kas",
		Uri:  "https://test-rotate-key.opentdf.io",
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasReq)
	s.Require().NoError(err)
	s.NotNil(kas)

	keyMap := s.setupKeysForRotate(kas.GetId())
	newKey := kasregistry.RotateKeyRequest_NewKey{
		KeyId:        "new_key_id",
		Algorithm:    policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_LOCAL,
		PublicKeyCtx: &policy.KasPublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.KasPrivateKeyCtx{
			KeyId:      validKeyID1,
			WrappedKey: keyCtx,
		},
	}
	rotatedInKey, err := s.db.PolicyClient.RotateKey(s.ctx, keyMap[rotateKey], &newKey)
	s.Require().NoError(err)
	s.NotNil(rotatedInKey)
	s.Equal(newKey.GetKeyId(), rotatedInKey.GetKasKey().GetKey().GetKeyId())
	s.Equal(newKey.GetAlgorithm(), rotatedInKey.GetKasKey().GetKey().GetKeyAlgorithm())
	s.Equal(newKey.GetKeyMode(), rotatedInKey.GetKasKey().GetKey().GetKeyMode())
	s.Equal(newKey.GetPublicKeyCtx().GetPem(), rotatedInKey.GetKasKey().GetKey().GetPublicKeyCtx().GetPem())
	s.Equal(newKey.GetPrivateKeyCtx().GetKeyId(), rotatedInKey.GetKasKey().GetKey().GetPrivateKeyCtx().GetKeyId())
	s.Equal(newKey.GetPrivateKeyCtx().GetWrappedKey(), rotatedInKey.GetKasKey().GetKey().GetPrivateKeyCtx().GetWrappedKey())
	s.Equal(policy.KeyStatus_KEY_STATUS_ACTIVE, rotatedInKey.GetKasKey().GetKey().GetKeyStatus())

	// Validate the rotated resoureces in the response.
	s.Equal(rotatedInKey.GetRotatedResources().GetRotatedOutKey().GetKey().GetId(), keyMap[rotateKey].GetKey().GetId())
	s.Empty(rotatedInKey.GetRotatedResources().GetAttributeDefinitionMappings())
	s.Empty(rotatedInKey.GetRotatedResources().GetNamespaceMappings())
	s.Empty(rotatedInKey.GetRotatedResources().GetAttributeValueMappings())

	// Verify that the old key is now inactive
	oldKey, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{
		Id: keyMap[rotateKey].GetKey().GetId(),
	})
	s.Require().NoError(err)
	s.Equal(policy.KeyStatus_KEY_STATUS_INACTIVE, oldKey.GetKey().GetKeyStatus())

	// Clean up
	s.cleanupRotate(
		[]string{},
		[]string{},
		[]string{},
		[]string{
			keyMap[rotateKey].GetKey().GetId(),
			keyMap[nonRotateKey].GetKey().GetId(),
			rotatedInKey.GetKasKey().GetKey().GetId(),
		},
		[]string{kas.GetId()},
	)
}

func (s *KasRegistryKeySuite) getKasRegistryServerKeysFixtures() []fixtures.FixtureDataKasRegistryKey {
	return []fixtures.FixtureDataKasRegistryKey{
		s.f.GetKasRegistryServerKeys("kas_key_1"),
		s.f.GetKasRegistryServerKeys("kas_key_2"),
	}
}

func (s *KasRegistryKeySuite) getKasRegistryFixtures() []fixtures.FixtureDataKasRegistry {
	return []fixtures.FixtureDataKasRegistry{
		s.f.GetKasRegistryKey("key_access_server_1"),
		s.f.GetKasRegistryKey("key_access_server_2"),
	}
}

func (s *KasRegistryKeySuite) setupNamespaceForRotate(numNSToRotate, numNSToNotRotate int, keyToRotate, secondKey *policy.AsymmetricKey) map[string][]*policy.Namespace {
	namespacesToRotate := make([]*policy.Namespace, numNSToRotate)
	namespacesToNotRotate := make([]*policy.Namespace, numNSToNotRotate)

	for i := 0; i < numNSToRotate+numNSToNotRotate; i++ {
		if i < numNSToRotate {
			// Create a namespace
			nsReq := namespaces.CreateNamespaceRequest{
				Name: rotatePrefix + uuid.New().String(),
			}
			namespaceWithKeyToRotate, err := s.db.PolicyClient.CreateNamespace(s.ctx, &nsReq)
			s.Require().NoError(err)
			s.NotNil(namespaceWithKeyToRotate)

			assignKeyReq := namespaces.NamespaceKey{
				NamespaceId: namespaceWithKeyToRotate.GetId(),
				KeyId:       keyToRotate.GetId(),
			}
			namespace, err := s.db.PolicyClient.AssignPublicKeyToNamespace(s.ctx, &assignKeyReq)
			s.Require().NoError(err)
			s.NotNil(namespace)

			namespacesToRotate[i] = namespaceWithKeyToRotate
		} else {
			nsReq2 := namespaces.CreateNamespaceRequest{
				Name: nonRotatePrefix + uuid.New().String(),
			}
			namespaceWithoutKeyToRotate, err := s.db.PolicyClient.CreateNamespace(s.ctx, &nsReq2)
			s.Require().NoError(err)
			s.NotNil(namespaceWithoutKeyToRotate)

			assignKeyReq2 := namespaces.NamespaceKey{
				NamespaceId: namespaceWithoutKeyToRotate.GetId(),
				KeyId:       secondKey.GetId(),
			}
			namespace2, err := s.db.PolicyClient.AssignPublicKeyToNamespace(s.ctx, &assignKeyReq2)
			s.Require().NoError(err)
			s.NotNil(namespace2)
			namespacesToNotRotate[i-numNSToRotate] = namespaceWithoutKeyToRotate
		}
	}
	return map[string][]*policy.Namespace{
		rotateKey:    namespacesToRotate,
		nonRotateKey: namespacesToNotRotate,
	}
}

func (s *KasRegistryKeySuite) setupKeysForRotate(kasID string) map[string]*policy.KasKey {
	// Create a key for the KAS
	keyReq := kasregistry.CreateKeyRequest{
		KasId:        kasID,
		KeyId:        "original_key_id_to_rotate",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
		PublicKeyCtx: []byte(`{"key":"original"}`),
	}
	keyToRotate, err := s.db.PolicyClient.CreateKey(s.ctx, &keyReq)
	s.Require().NoError(err)
	s.NotNil(rotateKey)

	keyReq2 := kasregistry.CreateKeyRequest{
		KasId:        kasID,
		KeyId:        "second_original_key_id",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
		PublicKeyCtx: []byte(`{"key":"original"}`),
	}
	secondKey, err := s.db.PolicyClient.CreateKey(s.ctx, &keyReq2)
	s.Require().NoError(err)
	s.NotNil(secondKey)

	return map[string]*policy.KasKey{
		rotateKey:    keyToRotate.GetKasKey(),
		nonRotateKey: secondKey.GetKasKey(),
	}
}

func (s *KasRegistryKeySuite) setupAttributesForRotate(numAttrsToRotate, numAttrsToNotRotate, numAttrValuesToRotate, numAttrsValuesToNotRotate int, namespaceMap map[string][]*policy.Namespace, keyToRotate, keyNotRotated *policy.AsymmetricKey) map[string][]*policy.Attribute {
	attributesToRotate := make([]*policy.Attribute, numAttrsToRotate)
	attributesToNotRotate := make([]*policy.Attribute, numAttrsToNotRotate)

	if (numAttrValuesToRotate > 1 && numAttrsToRotate == 0) || (numAttrsValuesToNotRotate > 1 && numAttrsToNotRotate == 0) {
		s.Fail("Invalid test setup: if there are multiple attribute values, there must be at least on attribute")
	}

	if len(namespaceMap[rotateKey]) == 0 || len(namespaceMap[nonRotateKey]) == 0 {
		s.Fail("Should at least have one namespace for rotating and non-rotating")
	}

	for i := 0; i < numAttrsToRotate+numAttrsToNotRotate; i++ {
		if i < numAttrsToRotate {
			attrValueNames := make([]string, 0)
			if i == 0 {
				// Create all the attribute values for the first attribute
				for j := 0; j < numAttrValuesToRotate; j++ {
					attrValueNames = append(attrValueNames, rotatePrefix+uuid.NewString())
				}
			}

			// Create a namespace
			attrReq := attributes.CreateAttributeRequest{
				NamespaceId: namespaceMap[rotateKey][0].GetId(),
				Name:        rotatePrefix + uuid.NewString(),
				Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
				Values:      attrValueNames,
			}
			rotateAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attrReq)
			s.Require().NoError(err)
			s.NotNil(rotateAttr)

			assignKeyToAttrReq := attributes.AttributeKey{
				AttributeId: rotateAttr.GetId(),
				KeyId:       keyToRotate.GetId(),
			}
			attribute, err := s.db.PolicyClient.AssignPublicKeyToAttribute(s.ctx, &assignKeyToAttrReq)
			s.Require().NoError(err)
			s.NotNil(attribute)

			attributesToRotate[i] = rotateAttr
		} else {
			attrValueNames := make([]string, 0)
			if i-numAttrValuesToRotate == 0 {
				// Create all the attribute values for the first attribute
				for j := 0; j < numAttrValuesToRotate; j++ {
					attrValueNames = append(attrValueNames, nonRotatePrefix+uuid.NewString())
				}
			}
			attrReq := attributes.CreateAttributeRequest{
				NamespaceId: namespaceMap[nonRotateKey][0].GetId(),
				Name:        nonRotatePrefix + uuid.NewString(),
				Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
				Values:      attrValueNames,
			}
			noRotateAttr, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attrReq)
			s.Require().NoError(err)
			s.NotNil(noRotateAttr)

			assignKeyToAttrReq := attributes.AttributeKey{
				AttributeId: noRotateAttr.GetId(),
				KeyId:       keyNotRotated.GetId(),
			}
			attribute, err := s.db.PolicyClient.AssignPublicKeyToAttribute(s.ctx, &assignKeyToAttrReq)
			s.Require().NoError(err)
			s.NotNil(attribute)
			attributesToNotRotate[i-numAttrsToNotRotate] = noRotateAttr
		}
	}
	// Go through and assing the values to public keys
	for _, value := range attributesToRotate[0].GetValues() {
		if value.GetId() == "" {
			continue
		}
		assignKeyToAttrValueReq := attributes.ValueKey{
			ValueId: value.GetId(),
			KeyId:   keyToRotate.GetId(),
		}
		_, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &assignKeyToAttrValueReq)
		s.Require().NoError(err)
	}
	for _, value := range attributesToNotRotate[0].GetValues() {
		if value.GetId() == "" {
			continue
		}
		assignKeyToAttrValueReq := attributes.ValueKey{
			ValueId: value.GetId(),
			KeyId:   keyNotRotated.GetId(),
		}
		_, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, &assignKeyToAttrValueReq)
		s.Require().NoError(err)
	}

	return map[string][]*policy.Attribute{
		rotateKey:    attributesToRotate,
		nonRotateKey: attributesToNotRotate,
	}
}

func (s *KasRegistryKeySuite) cleanupRotate(attrValueIDs []string, namespaceIDs []string, attributeIDs []string, keyIDs []string, keyAccessServerIDs []string) {
	for _, id := range attrValueIDs {
		_, err := s.db.PolicyClient.DeleteAttributeValue(s.ctx, id)
		s.Require().NoError(err)
	}
	for _, id := range namespaceIDs {
		_, err := s.db.PolicyClient.DeleteNamespace(s.ctx, id)
		s.Require().NoError(err)
	}
	for _, id := range attributeIDs {
		_, err := s.db.PolicyClient.DeleteAttribute(s.ctx, id)
		s.Require().NoError(err)
	}
	for _, id := range keyIDs {
		_, err := s.db.PolicyClient.DeleteKey(s.ctx, id)
		s.Require().NoError(err)
	}
	for _, id := range keyAccessServerIDs {
		_, err := s.db.PolicyClient.DeleteKeyAccessServer(s.ctx, id)
		s.Require().NoError(err)
	}
}

func (s *KasRegistryKeySuite) validateListKeysResponse(resp *kasregistry.ListKeysResponse, err error) {
	s.Require().NoError(err)
	s.NotNil(resp)
	s.GreaterOrEqual(len(resp.GetKasKeys()), 2)
	s.GreaterOrEqual(int32(2), resp.GetPagination().GetTotal())

	for _, key := range resp.GetKasKeys() {
		var fixtureKey *fixtures.FixtureDataKasRegistryKey

		for _, kasKey := range s.kasKeys {
			if kasKey.ID == key.GetKey().GetId() {
				fixtureKey = &kasKey
				break
			}
		}

		s.Require().NotNil(fixtureKey, "No matching KAS key found for ID: %s", key.GetKey().GetId())
		s.Equal(fixtureKey.KeyAccessServerID, key.GetKasId())
		s.Equal(fixtureKey.ID, key.GetKey().GetId())
		s.Equal(fixtureKey.ProviderConfigID, key.GetKey().GetProviderConfig().GetId())

		privateKeyCtx, err := base64.StdEncoding.DecodeString(fixtureKey.PrivateKeyCtx)
		s.Require().NoError(err)
		s.Equal(privateKeyCtx, key.GetKey().GetPrivateKeyCtx())

		pubKeyCtx, err := base64.StdEncoding.DecodeString(fixtureKey.PublicKeyCtx)
		s.Require().NoError(err)
		s.Equal(pubKeyCtx, key.GetKey().GetPublicKeyCtx())
	}
}
