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
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
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
	keyCtx                   = `YS1wZW0K`
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
	s.db = fixtures.NewDBInterface(s.ctx, c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision(s.ctx)
	s.kasFixtures = s.getKasRegistryFixtures()
	s.kasKeys = s.getKasRegistryServerKeysFixtures()
}

func (s *KasRegistryKeySuite) TearDownSuite() {
	slog.Info("tearing down db.KasKeys test suite")
	s.f.TearDown(s.ctx)
}

func TestKasRegistryKeysSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping db.KasRegistryKeys integration tests")
	}
	suite.Run(t, new(KasRegistryKeySuite))
}

func (s *KasRegistryKeySuite) Test_CreateKasKey_InvalidKasId_Fail() {
	req := kasregistry.CreateKeyRequest{
		KasId:        notFoundKasUUID,
		KeyId:        validKeyID1,
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_4096,
		KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
		PublicKeyCtx: &policy.PublicKeyCtx{
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
		PublicKeyCtx:     &policy.PublicKeyCtx{Pem: keyCtx},
		ProviderConfigId: providerConfigID,
	}
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorContains(err, db.ErrForeignKeyViolation.Error())
}

func (s *KasRegistryKeySuite) Test_CreateKasKey_NonBase64Ctx_Fail() {
	nonBase64Ctx := `{"pem: "value"}`
	req := kasregistry.CreateKeyRequest{
		KasId:        s.kasKeys[0].KeyAccessServerID,
		KeyId:        validKeyID1,
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_REMOTE,
		PublicKeyCtx: &policy.PublicKeyCtx{Pem: nonBase64Ctx},
	}
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().Error(err)
	s.Require().ErrorContains(err, db.ErrExpectedBase64EncodedValue.Error())
	s.Nil(resp)

	req = kasregistry.CreateKeyRequest{
		KasId:         s.kasKeys[0].KeyAccessServerID,
		KeyId:         validKeyID1,
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:       policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx:  &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{WrappedKey: nonBase64Ctx, KeyId: validKeyID1},
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
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
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

	_, err = s.db.PolicyClient.UnsafeDeleteKey(s.ctx, resp.GetKasKey(), &unsafe.UnsafeDeleteKasKeyRequest{
		Id:     resp.GetKasKey().GetKey().GetId(),
		KasUri: resp.GetKasKey().GetKasUri(),
		Kid:    resp.GetKasKey().GetKey().GetKeyId(),
	})
	s.Require().NoError(err)
}

func (s *KasRegistryKeySuite) Test_CreateKasKey_Legacy_Success() {
	// Create KAS server
	req := kasregistry.CreateKeyRequest{
		KasId:        s.kasKeys[0].KeyAccessServerID,
		KeyId:        "legacy_key_id",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			WrappedKey: keyCtx,
			KeyId:      validKeyID1,
		},
		Legacy: true,
	}
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.True(resp.GetKasKey().GetKey().GetLegacy())

	_, err = s.db.PolicyClient.UnsafeDeleteKey(s.ctx, resp.GetKasKey(), &unsafe.UnsafeDeleteKasKeyRequest{
		Id:     resp.GetKasKey().GetKey().GetId(),
		KasUri: resp.GetKasKey().GetKasUri(),
		Kid:    resp.GetKasKey().GetKey().GetKeyId(),
	})
	s.Require().NoError(err)
}

func (s *KasRegistryKeySuite) Test_CreateKasKey_Legacy_MultipleOnSameKas_Fail() {
	// Create KAS server
	req := kasregistry.CreateKeyRequest{
		KasId:        s.kasKeys[0].KeyAccessServerID,
		KeyId:        "legacy_key_id_1",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			WrappedKey: keyCtx,
			KeyId:      validKeyID1,
		},
		Legacy: true,
	}
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.True(resp.GetKasKey().GetKey().GetLegacy())

	defer func() {
		_, err := s.db.PolicyClient.UnsafeDeleteKey(s.ctx, resp.GetKasKey(), &unsafe.UnsafeDeleteKasKeyRequest{
			Id:     resp.GetKasKey().GetKey().GetId(),
			KasUri: resp.GetKasKey().GetKasUri(),
			Kid:    resp.GetKasKey().GetKey().GetKeyId(),
		})
		s.Require().NoError(err)
	}()

	req2 := kasregistry.CreateKeyRequest{
		KasId:        s.kasKeys[0].KeyAccessServerID,
		KeyId:        "legacy_key_id_2",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			WrappedKey: keyCtx,
			KeyId:      validKeyID1,
		},
		Legacy: true,
	}
	_, err = s.db.PolicyClient.CreateKey(s.ctx, &req2)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
}

func (s *KasRegistryKeySuite) Test_CreateKasKey_Legacy_MultipleOnDifferentKas_Success() {
	// Create KAS server
	req := kasregistry.CreateKeyRequest{
		KasId:        s.kasKeys[0].KeyAccessServerID,
		KeyId:        "legacy_key_id_1",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			WrappedKey: keyCtx,
			KeyId:      validKeyID1,
		},
		Legacy: true,
	}
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.True(resp.GetKasKey().GetKey().GetLegacy())

	defer func() {
		_, err := s.db.PolicyClient.UnsafeDeleteKey(s.ctx, resp.GetKasKey(), &unsafe.UnsafeDeleteKasKeyRequest{
			Id:     resp.GetKasKey().GetKey().GetId(),
			KasUri: resp.GetKasKey().GetKasUri(),
			Kid:    resp.GetKasKey().GetKey().GetKeyId(),
		})
		s.Require().NoError(err)
	}()

	// Create a new KAS server
	kasReq := kasregistry.CreateKeyAccessServerRequest{
		Name: "test_kas_legacy_key",
		Uri:  "https://test-kas-legacy-key.opentdf.io",
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasReq)
	s.Require().NoError(err)
	s.NotNil(kas)

	kasIDs := []string{kas.GetId()}
	keyIDs := []string{}

	defer func() {
		s.cleanupKeys(keyIDs, kasIDs)
	}()

	req2 := kasregistry.CreateKeyRequest{
		KasId:        kas.GetId(),
		KeyId:        "legacy_key_id_2",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			WrappedKey: keyCtx,
			KeyId:      validKeyID1,
		},
		Legacy: true,
	}
	resp2, err := s.db.PolicyClient.CreateKey(s.ctx, &req2)
	s.Require().NoError(err)
	s.NotNil(resp2)
	s.True(resp2.GetKasKey().GetKey().GetLegacy())
	keyIDs = append(keyIDs, resp2.GetKasKey().GetKey().GetId())
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
	if s.kasKeys[0].ProviderConfigID == nil {
		s.Nil(resp.GetKey().GetProviderConfig())
	} else {
		s.Equal(*s.kasKeys[0].ProviderConfigID, resp.GetKey().GetProviderConfig().GetId())
	}
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
	s.Equal(*s.kasKeys[0].ProviderConfigID, resp.GetKey().GetProviderConfig().GetId())
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
	if s.kasKeys[0].ProviderConfigID == nil {
		s.Nil(resp.GetKey().GetProviderConfig())
	} else {
		s.Equal(*s.kasKeys[0].ProviderConfigID, resp.GetKey().GetProviderConfig().GetId())
	}
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
	s.Equal(*s.kasKeys[0].ProviderConfigID, resp.GetKey().GetProviderConfig().GetId())
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

func (s *KasRegistryKeySuite) Test_ListKeys_NoKasFilter_Success() {
	req := kasregistry.ListKeysRequest{}
	resp, err := s.db.PolicyClient.ListKeys(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.NotEmpty(resp.GetKasKeys())
}

func (s *KasRegistryKeySuite) Test_ListKeys_KasID_Success() {
	req := kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasId{
			KasId: s.kasKeys[0].KeyAccessServerID,
		},
	}
	resp, err := s.db.PolicyClient.ListKeys(s.ctx, &req)
	s.validateListKeysResponse(resp, 2, err)
}

func (s *KasRegistryKeySuite) Test_ListKeys_KasName_Success() {
	req := kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasName{
			KasName: s.kasFixtures[0].Name,
		},
	}
	resp, err := s.db.PolicyClient.ListKeys(s.ctx, &req)
	s.validateListKeysResponse(resp, 2, err)
}

func (s *KasRegistryKeySuite) Test_ListKeys_KasURI_Success() {
	req := kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasUri{
			KasUri: s.kasFixtures[0].URI,
		},
	}
	resp, err := s.db.PolicyClient.ListKeys(s.ctx, &req)
	s.validateListKeysResponse(resp, 2, err)
}

func (s *KasRegistryKeySuite) Test_ListKeys_KasFilter_NotFound_Fails() {
	tests := []struct {
		name    string
		makeReq func() *kasregistry.ListKeysRequest
	}{
		{
			name: "by_kas_id",
			makeReq: func() *kasregistry.ListKeysRequest {
				return &kasregistry.ListKeysRequest{
					KasFilter: &kasregistry.ListKeysRequest_KasId{
						KasId: uuid.NewString(),
					},
				}
			},
		},
		{
			name: "by_kas_name",
			makeReq: func() *kasregistry.ListKeysRequest {
				return &kasregistry.ListKeysRequest{
					KasFilter: &kasregistry.ListKeysRequest_KasName{
						KasName: "kas-name-does-not-exist",
					},
				}
			},
		},
		{
			name: "by_kas_uri",
			makeReq: func() *kasregistry.ListKeysRequest {
				return &kasregistry.ListKeysRequest{
					KasFilter: &kasregistry.ListKeysRequest_KasUri{
						KasUri: "https://kas-uri-does-not-exist.opentdf.io",
					},
				}
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		s.Run(tc.name, func() {
			req := tc.makeReq()
			resp, err := s.db.PolicyClient.ListKeys(s.ctx, req)
			s.Require().Error(err)
			s.Nil(resp)
			s.Require().ErrorContains(err, db.ErrNotFound.Error())
		})
	}
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
	s.validateListKeysResponse(resp, 1, err)
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
	s.Equal(int32(0), resp.GetPagination().GetNextOffset())
	s.Equal(int32(0), resp.GetPagination().GetCurrentOffset())
}

func (s *KasRegistryKeySuite) Test_ListKeys_Legacy_Success() {
	kasIDs := make([]string, 0)
	keyIDs := make([]string, 0)

	defer func() {
		s.cleanupKeys(keyIDs, kasIDs)
	}()

	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri:  "https://legacy-kas.opentdf.io",
		Name: "Legacy KAS",
	})
	s.Require().NoError(err)
	s.Require().NotNil(kas)
	kasIDs = append(kasIDs, kas.GetId())

	legacyReq := kasregistry.CreateKeyRequest{
		KasId:        kas.GetId(),
		KeyId:        "legacy_key_id",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			WrappedKey: keyCtx,
			KeyId:      validKeyID1,
		},
		Legacy: true,
	}
	legacyResp, err := s.db.PolicyClient.CreateKey(s.ctx, &legacyReq)
	s.Require().NoError(err)
	s.NotNil(legacyResp)
	s.True(legacyResp.GetKasKey().GetKey().GetLegacy())
	keyIDs = append(keyIDs, legacyResp.GetKasKey().GetKey().GetId())

	nonLegacyReq := kasregistry.CreateKeyRequest{
		KasId:        kas.GetId(),
		KeyId:        "non_legacy_key_id",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			WrappedKey: keyCtx,
			KeyId:      validKeyID1,
		},
	}
	nonLegacyResp, err := s.db.PolicyClient.CreateKey(s.ctx, &nonLegacyReq)
	s.Require().NoError(err)
	s.Require().NotNil(nonLegacyResp)
	s.Require().False(nonLegacyResp.GetKasKey().GetKey().GetLegacy())
	keyIDs = append(keyIDs, nonLegacyResp.GetKasKey().GetKey().GetId())

	// List legacy keys
	legacyFilter := true
	listResp, err := s.db.PolicyClient.ListKeys(s.ctx, &kasregistry.ListKeysRequest{
		Legacy: &legacyFilter,
		KasFilter: &kasregistry.ListKeysRequest_KasId{
			KasId: kas.GetId(),
		},
	})
	s.Require().NoError(err)
	s.NotNil(listResp)
	s.Len(listResp.GetKasKeys(), 1)
	s.True(listResp.GetKasKeys()[0].GetKey().GetLegacy())
	s.Equal(legacyResp.GetKasKey().GetKey().GetId(), listResp.GetKasKeys()[0].GetKey().GetId())

	// Check that legacy key is included with non-legacy keys when filter is nil
	listResp, err = s.db.PolicyClient.ListKeys(s.ctx, &kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasId{
			KasId: kas.GetId(),
		},
	})
	s.Require().NoError(err)
	s.NotNil(listResp)
	s.Len(listResp.GetKasKeys(), 2)
	foundLegacy := false
	foundNonLegacy := false
	for _, key := range listResp.GetKasKeys() {
		if key.GetKey().GetLegacy() {
			s.Equal("legacy_key_id", key.GetKey().GetKeyId())
			foundLegacy = true
		} else {
			foundNonLegacy = true
		}
	}
	s.True(foundNonLegacy)
	s.True(foundLegacy)

	legacyFilter = false
	listResp, err = s.db.PolicyClient.ListKeys(s.ctx, &kasregistry.ListKeysRequest{
		Legacy: &legacyFilter,
		KasFilter: &kasregistry.ListKeysRequest_KasId{
			KasId: kas.GetId(),
		},
	})
	s.Require().NoError(err)
	s.NotNil(listResp)
	s.Len(listResp.GetKasKeys(), 1)

	foundLegacy = false
	for _, key := range listResp.GetKasKeys() {
		if key.GetKey().GetLegacy() {
			foundLegacy = true
		}
	}
	s.False(foundLegacy)
}

func (s *KasRegistryKeySuite) Test_RotateKey_Multiple_Attributes_Values_Namespaces_Success() {
	namespaceIDs := make([]string, 0)
	keyIDs := make([]string, 0)
	kasIDs := make([]string, 0)

	defer func() {
		s.cleanupNamespacesAndAttrsByIDs(namespaceIDs)
		s.cleanupKeys(keyIDs, kasIDs)
	}()

	// Create a new KAS server
	kasReq := kasregistry.CreateKeyAccessServerRequest{
		Name: "test_rotate_key_kas",
		Uri:  "https://test-rotate-key.opentdf.io",
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasReq)
	s.Require().NoError(err)
	s.NotNil(kas)
	kasIDs = append(kasIDs, kas.GetId())

	keyMap := s.setupKeysForRotate(kas.GetId())
	keyIDs = append(keyIDs, keyMap[rotateKey].GetKey().GetId(), keyMap[nonRotateKey].GetKey().GetId())
	namespaceMap := s.setupNamespaceForRotate(1, 1, keyMap[rotateKey].GetKey(), keyMap[nonRotateKey].GetKey())
	namespaceIDs = append(namespaceIDs, namespaceMap[rotateKey][0].GetId(), namespaceMap[nonRotateKey][0].GetId())
	attributeMap := s.setupAttributesForRotate(1, 1, 1, 1, namespaceMap, keyMap[rotateKey].GetKey(), keyMap[nonRotateKey].GetKey())

	newKey := kasregistry.RotateKeyRequest_NewKey{
		KeyId:        "new_key_id",
		Algorithm:    policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			KeyId:      validKeyID1,
			WrappedKey: keyCtx,
		},
	}

	rotatedInKey, err := s.db.PolicyClient.RotateKey(s.ctx, keyMap[rotateKey], &newKey)
	s.Require().NoError(err)
	s.NotNil(rotatedInKey)
	keyIDs = append(keyIDs, rotatedInKey.GetKasKey().GetKey().GetId())

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
	s.Equal(policy.KeyStatus_KEY_STATUS_ROTATED, oldKey.GetKey().GetKeyStatus())

	// Verify that namespace has the new key
	updatedNs, err := s.db.PolicyClient.GetNamespace(s.ctx, namespaceMap[rotateKey][0].GetId())
	s.Require().NoError(err)
	s.Len(updatedNs.GetKasKeys(), 1)
	s.Equal(rotatedInKey.GetKasKey().GetKey().GetKeyId(), updatedNs.GetKasKeys()[0].GetPublicKey().GetKid())
	s.Equal(rotatedInKey.GetKasKey().GetKasUri(), updatedNs.GetKasKeys()[0].GetKasUri())

	// Verify that namespace which was assigned a key that was not rotated is still intact
	nonUpdatedNs, err := s.db.PolicyClient.GetNamespace(s.ctx, namespaceMap[nonRotateKey][0].GetId())
	s.Require().NoError(err)
	s.Len(nonUpdatedNs.GetKasKeys(), 1)
	s.Equal(keyMap[nonRotateKey].GetKey().GetKeyId(), nonUpdatedNs.GetKasKeys()[0].GetPublicKey().GetKid())
	s.Equal(keyMap[nonRotateKey].GetKasUri(), nonUpdatedNs.GetKasKeys()[0].GetKasUri())

	// Verify that attribute has the new key
	updatedAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, &attributes.GetAttributeRequest_AttributeId{
		AttributeId: attributeMap[rotateKey][0].GetId(),
	})
	s.Require().NoError(err)
	s.Len(updatedAttr.GetKasKeys(), 1)
	s.Equal(rotatedInKey.GetKasKey().GetKey().GetKeyId(), updatedAttr.GetKasKeys()[0].GetPublicKey().GetKid())
	s.Equal(rotatedInKey.GetKasKey().GetKasUri(), updatedAttr.GetKasKeys()[0].GetKasUri())

	// Verify that attribute definition which was assigned a key that was not rotated is still intact
	nonUpdatedAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, &attributes.GetAttributeRequest_AttributeId{
		AttributeId: attributeMap[nonRotateKey][0].GetId(),
	})
	s.Require().NoError(err)
	s.Len(nonUpdatedAttr.GetKasKeys(), 1)
	s.Equal(keyMap[nonRotateKey].GetKey().GetKeyId(), nonUpdatedAttr.GetKasKeys()[0].GetPublicKey().GetKid())
	s.Equal(keyMap[nonRotateKey].GetKasUri(), nonUpdatedAttr.GetKasKeys()[0].GetKasUri())

	// Verify that attribute value has the new key
	attrValue, err := s.db.PolicyClient.GetAttributeValue(s.ctx, &attributes.GetAttributeValueRequest_ValueId{
		ValueId: attributeMap[rotateKey][0].GetValues()[0].GetId(),
	})
	s.Require().NoError(err)
	s.Len(attrValue.GetKasKeys(), 1)
	s.Equal(rotatedInKey.GetKasKey().GetKey().GetKeyId(), attrValue.GetKasKeys()[0].GetPublicKey().GetKid())
	s.Equal(rotatedInKey.GetKasKey().GetKasUri(), attrValue.GetKasKeys()[0].GetKasUri())

	// Verify that attribute value which was assigned a key that was not rotated is still intact
	nonUpdatedAttrValue, err := s.db.PolicyClient.GetAttributeValue(s.ctx, &attributes.GetAttributeValueRequest_ValueId{
		ValueId: attributeMap[nonRotateKey][0].GetValues()[0].GetId(),
	})
	s.Require().NoError(err)
	s.Len(nonUpdatedAttrValue.GetKasKeys(), 1)
	s.Equal(keyMap[nonRotateKey].GetKey().GetKeyId(), nonUpdatedAttrValue.GetKasKeys()[0].GetPublicKey().GetKid())
	s.Equal(keyMap[nonRotateKey].GetKasUri(), nonUpdatedAttrValue.GetKasKeys()[0].GetKasUri())
}

func (s *KasRegistryKeySuite) Test_RotateKey_Two_Attribute_Two_Namespace_0_AttributeValue_Success() {
	namespaceIDs := make([]string, 0)
	keyIDs := make([]string, 0)
	kasIDs := make([]string, 0)

	defer func() {
		s.cleanupNamespacesAndAttrsByIDs(namespaceIDs)
		s.cleanupKeys(keyIDs, kasIDs)
	}()

	// Create a new KAS server
	kasReq := kasregistry.CreateKeyAccessServerRequest{
		Name: "test_rotate_key_kas",
		Uri:  "https://test-rotate-key.opentdf.io",
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasReq)
	s.Require().NoError(err)
	s.NotNil(kas)
	kasIDs = append(kasIDs, kas.GetId())

	keyMap := s.setupKeysForRotate(kas.GetId())
	keyIDs = append(keyIDs, keyMap[rotateKey].GetKey().GetId(), keyMap[nonRotateKey].GetKey().GetId())
	namespaceMap := s.setupNamespaceForRotate(2, 2, keyMap[rotateKey].GetKey(), keyMap[nonRotateKey].GetKey())
	namespaceIDs = append(namespaceIDs, namespaceMap[rotateKey][0].GetId(), namespaceMap[rotateKey][1].GetId(), namespaceMap[nonRotateKey][0].GetId(), namespaceMap[nonRotateKey][1].GetId())
	attributeMap := s.setupAttributesForRotate(2, 2, 0, 0, namespaceMap, keyMap[rotateKey].GetKey(), keyMap[nonRotateKey].GetKey())

	newKey := kasregistry.RotateKeyRequest_NewKey{
		KeyId:        "new_key_id",
		Algorithm:    policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			KeyId:      validKeyID1,
			WrappedKey: keyCtx,
		},
	}

	rotatedInKey, err := s.db.PolicyClient.RotateKey(s.ctx, keyMap[rotateKey], &newKey)
	s.Require().NoError(err)
	s.NotNil(rotatedInKey)
	keyIDs = append(keyIDs, rotatedInKey.GetKasKey().GetKey().GetId())

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
	s.Equal(policy.KeyStatus_KEY_STATUS_ROTATED, oldKey.GetKey().GetKeyStatus())

	// Verify that namespace has the new key
	for _, ns := range namespaceMap[rotateKey] {
		updatedNs, err := s.db.PolicyClient.GetNamespace(s.ctx, ns.GetId())
		s.Require().NoError(err)
		s.Len(updatedNs.GetKasKeys(), 1)
		s.Equal(rotatedInKey.GetKasKey().GetKey().GetKeyId(), updatedNs.GetKasKeys()[0].GetPublicKey().GetKid())
		s.Equal(rotatedInKey.GetKasKey().GetKasUri(), updatedNs.GetKasKeys()[0].GetKasUri())
	}

	// Verify that namespace which was assigned a key that was not rotated is still intact
	for _, ns := range namespaceMap[nonRotateKey] {
		nonUpdatedNs, err := s.db.PolicyClient.GetNamespace(s.ctx, ns.GetId())
		s.Require().NoError(err)
		s.Len(nonUpdatedNs.GetKasKeys(), 1)
		s.Equal(keyMap[nonRotateKey].GetKey().GetKeyId(), nonUpdatedNs.GetKasKeys()[0].GetPublicKey().GetKid())
		s.Equal(keyMap[nonRotateKey].GetKasUri(), nonUpdatedNs.GetKasKeys()[0].GetKasUri())
	}

	// Verify that attribute has the new key
	for _, attr := range attributeMap[rotateKey] {
		updatedAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, &attributes.GetAttributeRequest_AttributeId{
			AttributeId: attr.GetId(),
		})
		s.Require().NoError(err)
		s.Len(updatedAttr.GetKasKeys(), 1)
		s.Equal(rotatedInKey.GetKasKey().GetKey().GetKeyId(), updatedAttr.GetKasKeys()[0].GetPublicKey().GetKid())
		s.Equal(rotatedInKey.GetKasKey().GetKasUri(), updatedAttr.GetKasKeys()[0].GetKasUri())
	}

	// Verify that attribute definition which was assigned a key that was not rotated is still intact
	for _, attr := range attributeMap[nonRotateKey] {
		nonUpdatedAttr, err := s.db.PolicyClient.GetAttribute(s.ctx, &attributes.GetAttributeRequest_AttributeId{
			AttributeId: attr.GetId(),
		})
		s.Require().NoError(err)
		s.Len(nonUpdatedAttr.GetKasKeys(), 1)
		s.Equal(keyMap[nonRotateKey].GetKey().GetKeyId(), nonUpdatedAttr.GetKasKeys()[0].GetPublicKey().GetKid())
		s.Equal(keyMap[nonRotateKey].GetKasUri(), nonUpdatedAttr.GetKasKeys()[0].GetKasUri())
	}
}

func (s *KasRegistryKeySuite) Test_RotateKey_NoAttributeKeyMapping_Success() {
	keyIDs := make([]string, 0)
	kasIDs := make([]string, 0)
	defer func() {
		s.cleanupKeys(keyIDs, kasIDs)
	}()

	kasReq := kasregistry.CreateKeyAccessServerRequest{
		Name: "test_rotate_key_kas",
		Uri:  "https://test-rotate-key.opentdf.io",
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasReq)
	s.Require().NoError(err)
	s.NotNil(kas)
	kasIDs = append(kasIDs, kas.GetId())

	keyMap := s.setupKeysForRotate(kas.GetId())
	keyIDs = append(keyIDs, keyMap[rotateKey].GetKey().GetId(), keyMap[nonRotateKey].GetKey().GetId())
	newKey := kasregistry.RotateKeyRequest_NewKey{
		KeyId:        "new_key_id",
		Algorithm:    policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			KeyId:      validKeyID1,
			WrappedKey: keyCtx,
		},
	}

	// Ensure there is no default key mapping
	baseKey, err := s.db.PolicyClient.GetBaseKey(s.ctx)
	s.Require().NoError(err)
	s.Empty(baseKey)

	rotatedInKey, err := s.db.PolicyClient.RotateKey(s.ctx, keyMap[rotateKey], &newKey)
	s.Require().NoError(err)
	s.NotNil(rotatedInKey)
	keyIDs = append(keyIDs, rotatedInKey.GetKasKey().GetKey().GetId())
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
	s.Equal(policy.KeyStatus_KEY_STATUS_ROTATED, oldKey.GetKey().GetKeyStatus())

	// Ensure there are no default kas keys after rotation
	baseKey, err = s.db.PolicyClient.GetBaseKey(s.ctx)
	s.Require().NoError(err)
	s.Empty(baseKey)
}

func (s *KasRegistryKeySuite) Test_RotateKey_NoBaseKeyRotated_Success() {
	keyIDs := make([]string, 0)
	kasIDs := make([]string, 0)
	defer func() {
		s.cleanupKeys(keyIDs, kasIDs)
	}()

	kasReq := kasregistry.CreateKeyAccessServerRequest{
		Name: "test_rotate_key_kas",
		Uri:  "https://test-rotate-key.opentdf.io",
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasReq)
	s.Require().NoError(err)
	s.NotNil(kas)
	kasIDs = append(kasIDs, kas.GetId())

	keyMap := s.setupKeysForRotate(kas.GetId())
	keyIDs = append(keyIDs, keyMap[rotateKey].GetKey().GetId(), keyMap[nonRotateKey].GetKey().GetId())
	newKey := kasregistry.RotateKeyRequest_NewKey{
		KeyId:        "new_key_id",
		Algorithm:    policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			KeyId:      validKeyID1,
			WrappedKey: keyCtx,
		},
	}
	_, err = s.db.PolicyClient.SetBaseKey(s.ctx, &kasregistry.SetBaseKeyRequest{
		ActiveKey: &kasregistry.SetBaseKeyRequest_Id{
			Id: keyMap[nonRotateKey].GetKey().GetId(),
		},
	})
	s.Require().NoError(err)

	// Ensure there is no default key mapping
	baseKey, err := s.db.PolicyClient.GetBaseKey(s.ctx)
	s.Require().NoError(err)
	s.Require().NotNil(baseKey)

	rotatedInKey, err := s.db.PolicyClient.RotateKey(s.ctx, keyMap[rotateKey], &newKey)
	s.Require().NoError(err)
	s.NotNil(rotatedInKey)
	keyIDs = append(keyIDs, rotatedInKey.GetKasKey().GetKey().GetId())

	// Check that the rotated in key is now the ZTDF default key.
	baseKey, err = s.db.PolicyClient.GetBaseKey(s.ctx)
	s.Require().NoError(err)
	s.Require().NotNil(baseKey)
	s.Equal(keyMap[nonRotateKey].GetKey().GetKeyId(), baseKey.GetPublicKey().GetKid())
}

func (s *KasRegistryKeySuite) Test_RotateKey_BaseKeyRotated_Success() {
	keyIDs := make([]string, 0)
	kasIDs := make([]string, 0)
	defer func() {
		s.cleanupKeys(keyIDs, kasIDs)
	}()

	kasReq := kasregistry.CreateKeyAccessServerRequest{
		Name: "test_rotate_key_kas",
		Uri:  "https://test-rotate-key.opentdf.io",
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasReq)
	s.Require().NoError(err)
	s.NotNil(kas)
	kasIDs = append(kasIDs, kas.GetId())

	keyMap := s.setupKeysForRotate(kas.GetId())
	keyIDs = append(keyIDs, keyMap[rotateKey].GetKey().GetId(), keyMap[nonRotateKey].GetKey().GetId())
	newKey := kasregistry.RotateKeyRequest_NewKey{
		KeyId:        "new_key_id",
		Algorithm:    policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			KeyId:      validKeyID1,
			WrappedKey: keyCtx,
		},
	}

	// Set default key mapping
	_, err = s.db.PolicyClient.SetBaseKey(s.ctx, &kasregistry.SetBaseKeyRequest{
		ActiveKey: &kasregistry.SetBaseKeyRequest_Id{
			Id: keyMap[rotateKey].GetKey().GetId(),
		},
	})
	s.Require().NoError(err)

	rotatedInKey, err := s.db.PolicyClient.RotateKey(s.ctx, keyMap[rotateKey], &newKey)
	s.Require().NoError(err)
	s.NotNil(rotatedInKey)
	keyIDs = append(keyIDs, rotatedInKey.GetKasKey().GetKey().GetId())

	baseKey, err := s.db.PolicyClient.GetBaseKey(s.ctx)
	s.Require().NoError(err)
	s.Require().NotNil(baseKey)
	s.Equal(rotatedInKey.GetKasKey().GetKey().GetKeyId(), baseKey.GetPublicKey().GetKid())
}

func (s *KasRegistryKeySuite) Test_SetBaseKey_KasKeyNotFound_Fails() {
	keyIDs := make([]string, 0)
	kasIDs := make([]string, 0)
	defer func() {
		s.cleanupKeys(keyIDs, kasIDs)
	}()

	// Create a new KAS server
	kasReq := kasregistry.CreateKeyAccessServerRequest{
		Name: "test_default_key_kas",
		Uri:  "https://test-default-key.opentdf.io",
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasReq)
	s.Require().NoError(err)
	s.NotNil(kas)
	kasIDs = append(kasIDs, kas.GetId())

	// Create a key for the KAS
	keyReq := kasregistry.CreateKeyRequest{
		KasId:        kas.GetId(),
		KeyId:        "default_key_id",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{
			Pem: keyCtx,
		},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			KeyId:      validKeyID1,
			WrappedKey: keyCtx,
		},
	}
	key, err := s.db.PolicyClient.CreateKey(s.ctx, &keyReq)
	s.Require().NoError(err)
	s.NotNil(key)
	keyIDs = append(keyIDs, key.GetKasKey().GetKey().GetId())

	// Ensure there is no default key mapping
	baseKey, err := s.db.PolicyClient.GetBaseKey(s.ctx)
	s.Require().NoError(err)
	s.Require().Nil(baseKey)

	// Set default key mapping
	_, err = s.db.PolicyClient.SetBaseKey(s.ctx, &kasregistry.SetBaseKeyRequest{
		ActiveKey: &kasregistry.SetBaseKeyRequest_Id{
			Id: uuid.NewString(),
		},
	})
	s.Require().Error(err)
	s.Require().ErrorContains(err, "not found")
}

func (s *KasRegistryKeySuite) Test_SetBaseKey_Insert_Success() {
	keyIDs := make([]string, 0)
	kasIDs := make([]string, 0)
	defer func() {
		s.cleanupKeys(keyIDs, kasIDs)
	}()

	// Create a new KAS server
	kasReq := kasregistry.CreateKeyAccessServerRequest{
		Name: "test_default_key_kas",
		Uri:  "https://test-default-key.opentdf.io",
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasReq)
	s.Require().NoError(err)
	s.NotNil(kas)
	kasIDs = append(kasIDs, kas.GetId())

	// Create a key for the KAS
	keyReq := kasregistry.CreateKeyRequest{
		KasId:        kas.GetId(),
		KeyId:        "default_key_id",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{
			Pem: keyCtx,
		},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			KeyId:      validKeyID1,
			WrappedKey: keyCtx,
		},
	}
	key, err := s.db.PolicyClient.CreateKey(s.ctx, &keyReq)
	s.Require().NoError(err)
	s.NotNil(key)
	keyIDs = append(keyIDs, key.GetKasKey().GetKey().GetId())

	// Ensure there is no default key mapping
	baseKey, err := s.db.PolicyClient.GetBaseKey(s.ctx)
	s.Require().NoError(err)
	s.Require().Nil(baseKey)

	// Set default key mapping
	newBaseKey, err := s.db.PolicyClient.SetBaseKey(s.ctx, &kasregistry.SetBaseKeyRequest{
		ActiveKey: &kasregistry.SetBaseKeyRequest_Id{
			Id: key.GetKasKey().GetKey().GetId(),
		},
	})
	s.Require().NoError(err)
	s.NotNil(newBaseKey)
	s.Nil(newBaseKey.GetPreviousBaseKey())
	s.Equal(key.GetKasKey().GetKey().GetKeyId(), newBaseKey.GetNewBaseKey().GetPublicKey().GetKid())
	s.Equal(key.GetKasKey().GetKey().GetKeyAlgorithm(), newBaseKey.GetNewBaseKey().GetPublicKey().GetAlgorithm())
	decodedKeyCtx, err := base64.StdEncoding.DecodeString(keyCtx)
	s.Require().NoError(err)
	s.Equal(string(decodedKeyCtx), newBaseKey.GetNewBaseKey().GetPublicKey().GetPem())
}

func (s *KasRegistryKeySuite) Test_SetBaseKey_CannotSetPublicKeyOnlyKey_Fails() {
	keyIDs := make([]string, 0)
	kasIDs := make([]string, 0)
	defer func() {
		s.cleanupKeys(keyIDs, kasIDs)
	}()

	// Create a new KAS server
	kasReq := kasregistry.CreateKeyAccessServerRequest{
		Name: "test_default_key_kas",
		Uri:  "https://test-default-key.opentdf.io",
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasReq)
	s.Require().NoError(err)
	s.NotNil(kas)
	kasIDs = append(kasIDs, kas.GetId())

	// Create a key for the KAS
	keyReq := kasregistry.CreateKeyRequest{
		KasId:        kas.GetId(),
		KeyId:        "default_key_id",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_PUBLIC_KEY_ONLY,
		PublicKeyCtx: &policy.PublicKeyCtx{
			Pem: keyCtx,
		},
	}
	key, err := s.db.PolicyClient.CreateKey(s.ctx, &keyReq)
	s.Require().NoError(err)
	s.NotNil(key)
	keyIDs = append(keyIDs, key.GetKasKey().GetKey().GetId())

	// Ensure there is no default key mapping
	baseKey, err := s.db.PolicyClient.GetBaseKey(s.ctx)
	s.Require().NoError(err)
	s.Require().Nil(baseKey)

	// Set default key mapping
	_, err = s.db.PolicyClient.SetBaseKey(s.ctx, &kasregistry.SetBaseKeyRequest{
		ActiveKey: &kasregistry.SetBaseKeyRequest_Id{
			Id: key.GetKasKey().GetKey().GetId(),
		},
	})
	s.Require().Error(err)
	s.Require().ErrorContains(err, "KEY_MODE_PUBLIC_KEY_ONLY as default key")
}

func (s *KasRegistryKeySuite) Test_SetBaseKey_CannotSetNonActiveKey_Fails() {
	keyIDs := make([]string, 0)
	kasIDs := make([]string, 0)
	defer func() {
		s.cleanupKeys(keyIDs, kasIDs)
	}()

	// Create a new KAS server
	kasReq := kasregistry.CreateKeyAccessServerRequest{
		Name: "test_default_key_kas",
		Uri:  "https://test-default-key.opentdf.io",
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasReq)
	s.Require().NoError(err)
	s.NotNil(kas)
	kasIDs = append(kasIDs, kas.GetId())

	// Create a key for the KAS
	keyReq := kasregistry.CreateKeyRequest{
		KasId:        kas.GetId(),
		KeyId:        "default_key_id",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{
			Pem: keyCtx,
		},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			KeyId:      validKeyID1,
			WrappedKey: keyCtx,
		},
	}
	key, err := s.db.PolicyClient.CreateKey(s.ctx, &keyReq)
	s.Require().NoError(err)
	s.NotNil(key)
	keyIDs = append(keyIDs, key.GetKasKey().GetKey().GetId())

	// Ensure there is no default key mapping
	baseKey, err := s.db.PolicyClient.GetBaseKey(s.ctx)
	s.Require().NoError(err)
	s.Require().Nil(baseKey)

	// Update the key status to rotated
	rotatedKeysResp, err := s.db.PolicyClient.RotateKey(s.ctx,
		key.GetKasKey(),
		&kasregistry.RotateKeyRequest_NewKey{
			KeyId:     "rotated_key_id",
			Algorithm: policy.Algorithm_ALGORITHM_RSA_2048,
			KeyMode:   policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
			PublicKeyCtx: &policy.PublicKeyCtx{
				Pem: keyCtx,
			},
			PrivateKeyCtx: &policy.PrivateKeyCtx{
				KeyId:      validKeyID1,
				WrappedKey: keyCtx,
			},
		},
	)
	s.Require().NoError(err)
	s.NotNil(rotatedKeysResp)
	keyIDs = append(keyIDs, rotatedKeysResp.GetKasKey().GetKey().GetId())

	// Set default key mapping
	_, err = s.db.PolicyClient.SetBaseKey(s.ctx, &kasregistry.SetBaseKeyRequest{
		ActiveKey: &kasregistry.SetBaseKeyRequest_Id{
			Id: key.GetKasKey().GetKey().GetId(),
		},
	})
	s.Require().Error(err)
	s.Require().ErrorContains(err, "cannot set key of status")
}

func (s *KasRegistryKeySuite) Test_RotateKey_MetadataUnchanged_Success() {
	keyIDs := make([]string, 0)
	kasIDs := make([]string, 0)
	defer func() {
		s.cleanupKeys(keyIDs, kasIDs)
	}()

	kasReq := kasregistry.CreateKeyAccessServerRequest{
		Name: "test_rotate_key_kas",
		Uri:  "https://test-rotate-key.opentdf.io",
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasReq)
	s.Require().NoError(err)
	s.NotNil(kas)
	kasIDs = append(kasIDs, kas.GetId())

	labels := map[string]string{"key1": "value1", "key2": "value2"}
	keyReq := kasregistry.CreateKeyRequest{
		KasId:        kas.GetId(),
		KeyId:        "original_key_id_to_rotate",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P384,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{
			Pem: keyCtx,
		},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			KeyId:      validKeyID1,
			WrappedKey: keyCtx,
		},
		Metadata: &common.MetadataMutable{
			Labels: labels,
		},
	}
	keyToRotateResp, err := s.db.PolicyClient.CreateKey(s.ctx, &keyReq)
	s.Require().NoError(err)
	s.NotNil(keyToRotateResp)
	keyIDs = append(keyIDs, keyToRotateResp.GetKasKey().GetKey().GetId())
	s.Require().Equal(labels, keyToRotateResp.GetKasKey().GetKey().GetMetadata().GetLabels())

	newKey := kasregistry.RotateKeyRequest_NewKey{
		KeyId:        "new_key_id",
		Algorithm:    policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			KeyId:      validKeyID1,
			WrappedKey: keyCtx,
		},
	}
	rotatedInKey, err := s.db.PolicyClient.RotateKey(s.ctx, keyToRotateResp.GetKasKey(), &newKey)
	s.Require().NoError(err)
	s.NotNil(rotatedInKey)
	keyIDs = append(keyIDs, rotatedInKey.GetKasKey().GetKey().GetId())

	// Verify that the old key is now rotated
	oldKey, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{
		Id: keyToRotateResp.GetKasKey().GetKey().GetId(),
	})
	s.Require().NoError(err)
	s.Equal(policy.KeyStatus_KEY_STATUS_ROTATED, oldKey.GetKey().GetKeyStatus())
	s.Require().Equal(labels, oldKey.GetKey().GetMetadata().GetLabels())
}

func (s *KasRegistryKeySuite) Test_ListKeyMappings_InvalidLimit_Fail() {
	req := kasregistry.ListKeyMappingsRequest{
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax + 1,
		},
	}
	resp, err := s.db.PolicyClient.ListKeyMappings(s.ctx, &req)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrListLimitTooLarge)
	s.Nil(resp)
}

func (s *KasRegistryKeySuite) Test_ListKeyMappings_ByID_Invalid_UUID_Fail() {
	req := kasregistry.ListKeyMappingsRequest{
		Identifier: &kasregistry.ListKeyMappingsRequest_Id{
			Id: "non_existent_key_id",
		},
	}
	mappingsResp, err := s.db.PolicyClient.ListKeyMappings(s.ctx, &req)
	s.Require().Nil(mappingsResp)
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
}

func (s *KasRegistryKeySuite) Test_ListKeyMappings_ByID_OneAttrValue_Success() {
	kasKeys := make([]*policy.KasKey, 0)
	kasIDs := make([]string, 0)
	namespaces := make([]*policy.Namespace, 0)
	attributeDefs := make([]*policy.Attribute, 0)
	attrValues := make([]*policy.Value, 0)
	defer func() {
		keyIDs := make([]string, 0)
		for _, key := range kasKeys {
			keyIDs = append(keyIDs, key.GetKey().GetId())
		}
		s.cleanupKeys(keyIDs, kasIDs)
		s.cleanupNamespacesAndAttrs(namespaces)
	}()
	kasKey := s.createKeyAndKas()
	kasKeys = append(kasKeys, kasKey)
	kasIDs = append(kasIDs, kasKey.GetKasId())
	namespaces = append(namespaces, s.createNamespace())
	attributeDefs = append(attributeDefs, s.createAttrDef(namespaces[0].GetId()))
	attrValues = append(attrValues, s.createValue(attributeDefs[0].GetId()))
	s.createValueMapping(kasKey.GetKey().GetId(), attrValues[0].GetId())

	req := kasregistry.ListKeyMappingsRequest{
		Identifier: &kasregistry.ListKeyMappingsRequest_Id{
			Id: kasKey.GetKey().GetId(),
		},
	}
	mappingsResp, err := s.db.PolicyClient.ListKeyMappings(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(mappingsResp)
	s.Len(mappingsResp.GetKeyMappings(), 1)
	s.validateKeyMapping(mappingsResp.GetKeyMappings()[0], kasKey, []*policy.Namespace{}, []*policy.Attribute{}, attrValues)
	s.NotNil(mappingsResp.GetPagination())
	s.Equal(int32(1), mappingsResp.GetPagination().GetTotal())
	s.Equal(int32(0), mappingsResp.GetPagination().GetCurrentOffset())
	s.Equal(int32(0), mappingsResp.GetPagination().GetNextOffset())
}

func (s *KasRegistryKeySuite) Test_ListKeyMappings_By_Key_No_Kas_Identifier_Fail() {
	req := kasregistry.ListKeyMappingsRequest{
		Identifier: &kasregistry.ListKeyMappingsRequest_Key{
			Key: &kasregistry.KasKeyIdentifier{
				Kid: "non_existent_key_id",
			},
		},
	}
	mappingsResp, err := s.db.PolicyClient.ListKeyMappings(s.ctx, &req)
	s.Require().Nil(mappingsResp)
	s.Require().ErrorIs(err, db.ErrUnknownSelectIdentifier)
}

func (s *KasRegistryKeySuite) Test_ListKeyMappings_By_Key_No_Key_Id_With_Kas_Identifier_Fail() {
	req := kasregistry.ListKeyMappingsRequest{
		Identifier: &kasregistry.ListKeyMappingsRequest_Key{
			Key: &kasregistry.KasKeyIdentifier{
				Identifier: &kasregistry.KasKeyIdentifier_Uri{
					Uri: "non_existent_key_uri",
				},
			},
		},
	}
	mappingsResp, err := s.db.PolicyClient.ListKeyMappings(s.ctx, &req)
	s.Require().Nil(mappingsResp)
	s.Require().ErrorIs(err, db.ErrSelectIdentifierInvalid)
}

func (s *KasRegistryKeySuite) Test_ListKeyMappings_By_Key_Success() {
	kasKeys := make([]*policy.KasKey, 0)
	kasIDs := make([]string, 0)
	namespaces := make([]*policy.Namespace, 0)
	attributeDefs := make([]*policy.Attribute, 0)
	attrValues := make([]*policy.Value, 0)
	defer func() {
		keyIDs := make([]string, 0)
		for _, key := range kasKeys {
			keyIDs = append(keyIDs, key.GetKey().GetId())
		}
		s.cleanupKeys(keyIDs, kasIDs)
		s.cleanupNamespacesAndAttrs(namespaces)
	}()
	kasKey := s.createKeyAndKas()
	kasKeys = append(kasKeys, kasKey)
	kasIDs = append(kasIDs, kasKey.GetKasId())
	namespaces = append(namespaces, s.createNamespace())
	attributeDefs = append(attributeDefs, s.createAttrDef(namespaces[0].GetId()))
	attrValues = append(attrValues, s.createValue(attributeDefs[0].GetId()))
	s.createValueMapping(kasKey.GetKey().GetId(), attrValues[0].GetId())

	// Create a second key on the same KAS
	keyReqTwo := kasregistry.CreateKeyRequest{
		KasId:        kasKey.GetKasId(),
		KeyId:        "second-kas-key",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{
			Pem: keyCtx,
		},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			KeyId:      validKeyID1,
			WrappedKey: keyCtx,
		},
	}
	nonSearchedKey, err := s.db.PolicyClient.CreateKey(s.ctx, &keyReqTwo)
	s.Require().NoError(err)
	s.NotNil(nonSearchedKey)
	kasKeys = append(kasKeys, nonSearchedKey.GetKasKey())
	s.createValueMapping(nonSearchedKey.GetKasKey().GetKey().GetId(), attrValues[0].GetId())

	validateResp := func(resp *kasregistry.ListKeyMappingsResponse) {
		s.Require().NoError(err)
		s.NotNil(resp)
		s.Len(resp.GetKeyMappings(), 1)
		s.validateKeyMapping(resp.GetKeyMappings()[0], kasKey, []*policy.Namespace{}, []*policy.Attribute{}, attrValues)
		s.NotNil(resp.GetPagination())
		s.Equal(int32(1), resp.GetPagination().GetTotal())
		s.Equal(int32(0), resp.GetPagination().GetCurrentOffset())
		s.Equal(int32(0), resp.GetPagination().GetNextOffset())
	}

	req := kasregistry.ListKeyMappingsRequest{
		Identifier: &kasregistry.ListKeyMappingsRequest_Key{
			Key: &kasregistry.KasKeyIdentifier{
				Identifier: &kasregistry.KasKeyIdentifier_Uri{
					Uri: kasKey.GetKasUri(),
				},
				Kid: kasKey.GetKey().GetKeyId(),
			},
		},
	}
	mappingsResp, err := s.db.PolicyClient.ListKeyMappings(s.ctx, &req)
	validateResp(mappingsResp)

	req = kasregistry.ListKeyMappingsRequest{
		Identifier: &kasregistry.ListKeyMappingsRequest_Key{
			Key: &kasregistry.KasKeyIdentifier{
				Identifier: &kasregistry.KasKeyIdentifier_KasId{
					KasId: kasKey.GetKasId(),
				},
				Kid: kasKey.GetKey().GetKeyId(),
			},
		},
	}
	mappingsResp, err = s.db.PolicyClient.ListKeyMappings(s.ctx, &req)
	validateResp(mappingsResp)

	// Get the kas name
	kas, err := s.db.PolicyClient.GetKeyAccessServer(s.ctx, &kasregistry.GetKeyAccessServerRequest_KasId{
		KasId: kasKey.GetKasId(),
	})
	s.Require().NoError(err)
	s.NotNil(kas)
	req = kasregistry.ListKeyMappingsRequest{
		Identifier: &kasregistry.ListKeyMappingsRequest_Key{
			Key: &kasregistry.KasKeyIdentifier{
				Identifier: &kasregistry.KasKeyIdentifier_Name{
					Name: kas.GetName(),
				},
				Kid: kasKey.GetKey().GetKeyId(),
			},
		},
	}
	mappingsResp, err = s.db.PolicyClient.ListKeyMappings(s.ctx, &req)
	validateResp(mappingsResp)
}

func (s *KasRegistryKeySuite) Test_ListKeyMappings_SameKeyId_DifferentKas_Success() {
	kasKeys := make([]*policy.KasKey, 0)
	kasIDs := make([]string, 0)
	namespaces := make([]*policy.Namespace, 0)
	attributeDefs := make([]*policy.Attribute, 0)
	attrValues := make([]*policy.Value, 0)
	defer func() {
		keyIDs := make([]string, 0)
		for _, key := range kasKeys {
			keyIDs = append(keyIDs, key.GetKey().GetId())
		}
		s.cleanupKeys(keyIDs, kasIDs)
		s.cleanupNamespacesAndAttrs(namespaces)
	}()

	kasKey := s.createKeyAndKas()
	s.NotNil(kasKey)
	kasKeys = append(kasKeys, kasKey)
	kasIDs = append(kasIDs, kasKey.GetKasId())
	namespaces = append(namespaces, s.createNamespace())
	attributeDefs = append(attributeDefs, s.createAttrDef(namespaces[0].GetId()))
	attrValues = append(attrValues, s.createValue(attributeDefs[0].GetId()))
	s.createValueMapping(kasKey.GetKey().GetId(), attrValues[0].GetId())

	// Create another KAS
	kasReq := kasregistry.CreateKeyAccessServerRequest{
		Name: "test_list_mapping_kas_2_" + uuid.NewString(),
		Uri:  "https://test-list-mappings-2-" + uuid.NewString() + ".opentdf.io",
	}
	kasTwo, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasReq)
	s.Require().NoError(err)
	s.NotNil(kasTwo)
	kasIDs = append(kasIDs, kasTwo.GetId())

	keyReqTwo := kasregistry.CreateKeyRequest{
		KasId:        kasTwo.GetId(),
		KeyId:        kasKey.GetKey().GetKeyId(),
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{
			Pem: keyCtx,
		},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			KeyId:      validKeyID1,
			WrappedKey: keyCtx,
		},
	}
	nonSearchedKey, err := s.db.PolicyClient.CreateKey(s.ctx, &keyReqTwo)
	s.Require().NoError(err)
	s.NotNil(nonSearchedKey)
	kasKeys = append(kasKeys, nonSearchedKey.GetKasKey())
	s.createValueMapping(nonSearchedKey.GetKasKey().GetKey().GetId(), attrValues[0].GetId())

	listReq := kasregistry.ListKeyMappingsRequest{
		Identifier: &kasregistry.ListKeyMappingsRequest_Key{
			Key: &kasregistry.KasKeyIdentifier{
				Identifier: &kasregistry.KasKeyIdentifier_KasId{
					KasId: kasKey.GetKasId(),
				},
				Kid: kasKey.GetKey().GetKeyId(),
			},
		},
	}
	mappingsResp, err := s.db.PolicyClient.ListKeyMappings(s.ctx, &listReq)
	s.Require().NoError(err)
	s.NotNil(mappingsResp)
	s.Len(mappingsResp.GetKeyMappings(), 1)
	s.validateKeyMapping(mappingsResp.GetKeyMappings()[0], kasKey, []*policy.Namespace{}, []*policy.Attribute{}, attrValues)
	s.NotNil(mappingsResp.GetPagination())
	s.Equal(int32(1), mappingsResp.GetPagination().GetTotal())
	s.Equal(int32(0), mappingsResp.GetPagination().GetCurrentOffset())
	s.Equal(int32(0), mappingsResp.GetPagination().GetNextOffset())
}

func (s *KasRegistryKeySuite) Test_ListKeyMappings_By_Key_Success_EmptyMappings() {
	kasKeys := make([]*policy.KasKey, 0)
	kasIDs := make([]string, 0)
	defer func() {
		keyIDs := make([]string, 0)
		for _, key := range kasKeys {
			keyIDs = append(keyIDs, key.GetKey().GetId())
		}
		s.cleanupKeys(keyIDs, kasIDs)
	}()
	kasKey := s.createKeyAndKas()
	kasKeys = append(kasKeys, kasKey)
	kasIDs = append(kasIDs, kasKey.GetKasId())

	req := kasregistry.ListKeyMappingsRequest{
		Identifier: &kasregistry.ListKeyMappingsRequest_Id{
			Id: kasKey.GetKey().GetId(),
		},
	}
	mappingsResp, err := s.db.PolicyClient.ListKeyMappings(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(mappingsResp)
	s.Empty(mappingsResp.GetKeyMappings())
	s.NotNil(mappingsResp.GetPagination())
	s.Equal(int32(0), mappingsResp.GetPagination().GetTotal())
	s.Equal(int32(0), mappingsResp.GetPagination().GetCurrentOffset())
	s.Equal(int32(0), mappingsResp.GetPagination().GetNextOffset())
}

func (s *KasRegistryKeySuite) Test_ListKeyMappings_Multiple_Keys_Pagination_Success() {
	kasKeys := make([]*policy.KasKey, 0)
	kasIDs := make([]string, 0)
	namespaces := make([]*policy.Namespace, 0)
	attributeDefs := make([]*policy.Attribute, 0)
	attrValues := make([]*policy.Value, 0)
	defer func() {
		keyIDs := make([]string, 0)
		for _, key := range kasKeys {
			keyIDs = append(keyIDs, key.GetKey().GetId())
		}
		s.cleanupKeys(keyIDs, kasIDs)
		s.cleanupNamespacesAndAttrs(namespaces)
	}()
	for i := range 2 {
		kasKey := s.createKeyAndKas()
		kasKeys = append(kasKeys, kasKey)
		kasIDs = append(kasIDs, kasKey.GetKasId())
		namespaces = append(namespaces, s.createNamespace())
		attributeDefs = append(attributeDefs, s.createAttrDef(namespaces[i].GetId()))
		attrValues = append(attrValues, s.createValue(attributeDefs[i].GetId()))
		s.createNamespaceMapping(kasKey.GetKey().GetId(), namespaces[i].GetId())
		s.createAttrDefMapping(kasKey.GetKey().GetId(), attributeDefs[i].GetId())
		s.createValueMapping(kasKey.GetKey().GetId(), attrValues[i].GetId())
	}

	// List all key mappings without any identifier
	req := kasregistry.ListKeyMappingsRequest{}
	mappingsResp, err := s.db.PolicyClient.ListKeyMappings(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(mappingsResp)
	s.Len(mappingsResp.GetKeyMappings(), 2)
	s.validateKeyMapping(mappingsResp.GetKeyMappings()[0], kasKeys[0], []*policy.Namespace{namespaces[0]}, []*policy.Attribute{attributeDefs[0]}, []*policy.Value{attrValues[0]})
	s.validateKeyMapping(mappingsResp.GetKeyMappings()[1], kasKeys[1], []*policy.Namespace{namespaces[1]}, []*policy.Attribute{attributeDefs[1]}, []*policy.Value{attrValues[1]})
	s.NotNil(mappingsResp.GetPagination())
	s.Equal(int32(2), mappingsResp.GetPagination().GetTotal())
	s.Equal(int32(0), mappingsResp.GetPagination().GetCurrentOffset())
	s.Equal(int32(0), mappingsResp.GetPagination().GetNextOffset())

	req = kasregistry.ListKeyMappingsRequest{
		Pagination: &policy.PageRequest{
			Limit: 1,
		},
	}
	mappingsResp, err = s.db.PolicyClient.ListKeyMappings(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(mappingsResp)
	s.Len(mappingsResp.GetKeyMappings(), 1)
	s.validateKeyMapping(mappingsResp.GetKeyMappings()[0], kasKeys[0], []*policy.Namespace{namespaces[0]}, []*policy.Attribute{attributeDefs[0]}, []*policy.Value{attrValues[0]})
	s.NotNil(mappingsResp.GetPagination())
	s.Equal(int32(2), mappingsResp.GetPagination().GetTotal())
	s.Equal(int32(0), mappingsResp.GetPagination().GetCurrentOffset())
	s.Equal(int32(1), mappingsResp.GetPagination().GetNextOffset())

	req = kasregistry.ListKeyMappingsRequest{
		Pagination: &policy.PageRequest{
			Limit:  1,
			Offset: mappingsResp.GetPagination().GetNextOffset(),
		},
	}
	mappingsResp, err = s.db.PolicyClient.ListKeyMappings(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(mappingsResp)
	s.Len(mappingsResp.GetKeyMappings(), 1)
	s.validateKeyMapping(mappingsResp.GetKeyMappings()[0], kasKeys[1], []*policy.Namespace{namespaces[1]}, []*policy.Attribute{attributeDefs[1]}, []*policy.Value{attrValues[1]})
	s.NotNil(mappingsResp.GetPagination())
	s.Equal(int32(2), mappingsResp.GetPagination().GetTotal())
	s.Equal(int32(1), mappingsResp.GetPagination().GetCurrentOffset())
	s.Equal(int32(0), mappingsResp.GetPagination().GetNextOffset())
}

func (s *KasRegistryKeySuite) Test_ListKeyMappings_Multiple_Mixed_Mappings() {
	kasKeys := make([]*policy.KasKey, 0)
	kasIDs := make([]string, 0)
	namespaces := make([]*policy.Namespace, 0)
	attributeDefs := make([]*policy.Attribute, 0)
	attrValues := make([]*policy.Value, 0)
	defer func() {
		keyIDs := make([]string, 0)
		for _, key := range kasKeys {
			keyIDs = append(keyIDs, key.GetKey().GetId())
		}
		s.cleanupKeys(keyIDs, kasIDs)
		s.cleanupNamespacesAndAttrs(namespaces)
	}()

	for range 3 {
		kasKey := s.createKeyAndKas()
		s.NotNil(kasKey)
		kasKeys = append(kasKeys, kasKey)
		kasIDs = append(kasIDs, kasKey.GetKasId())
	}
	for i := range 2 {
		namespaces = append(namespaces, s.createNamespace())
		attributeDefs = append(attributeDefs, s.createAttrDef(namespaces[i].GetId()))
		attrValues = append(attrValues, s.createValue(attributeDefs[i].GetId()))
		s.createNamespaceMapping(kasKeys[0].GetKey().GetId(), namespaces[i].GetId())
		s.createAttrDefMapping(kasKeys[1].GetKey().GetId(), attributeDefs[i].GetId())
		s.createValueMapping(kasKeys[0].GetKey().GetId(), attrValues[i].GetId())
	}
	req := kasregistry.ListKeyMappingsRequest{}
	mappedResponse, err := s.db.PolicyClient.ListKeyMappings(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(mappedResponse)
	s.Len(mappedResponse.GetKeyMappings(), 2)
	s.validateKeyMapping(mappedResponse.GetKeyMappings()[0], kasKeys[0], namespaces, []*policy.Attribute{}, attrValues)
	s.validateKeyMapping(mappedResponse.GetKeyMappings()[1], kasKeys[1], []*policy.Namespace{}, attributeDefs, []*policy.Value{})
	s.NotNil(mappedResponse.GetPagination())
	s.Equal(int32(2), mappedResponse.GetPagination().GetTotal())
	s.Equal(int32(0), mappedResponse.GetPagination().GetCurrentOffset())
	s.Equal(int32(0), mappedResponse.GetPagination().GetNextOffset())
}

func (s *KasRegistryKeySuite) Test_UnsafeDeleteKey_InvalidId_Fail() {
	resp, err := s.db.PolicyClient.UnsafeDeleteKey(s.ctx, &policy.KasKey{}, &unsafe.UnsafeDeleteKasKeyRequest{
		Id: "invalid-uuid",
	})
	s.Require().Error(err)
	s.Nil(resp)
	s.Require().ErrorContains(err, db.ErrUUIDInvalid.Error())
}

func (s *KasRegistryKeySuite) Test_DeleteKey_WrongKasUriOrKid_Fail() {
	// Create a key
	req := kasregistry.CreateKeyRequest{
		KasId:        s.kasKeys[0].KeyAccessServerID,
		KeyId:        uuid.NewString(),
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			WrappedKey: keyCtx,
			KeyId:      validKeyID1,
		},
	}
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)

	defer func() {
		r := unsafe.UnsafeDeleteKasKeyRequest{
			Id:     resp.GetKasKey().GetKey().GetId(),
			KasUri: resp.GetKasKey().GetKasUri(),
			Kid:    resp.GetKasKey().GetKey().GetKeyId(),
		}
		_, err := s.db.PolicyClient.UnsafeDeleteKey(s.ctx, resp.GetKasKey(), &r)
		s.Require().NoError(err)
	}()

	// Attempt to delete with incorrect Kid
	deleteResp, err := s.db.PolicyClient.UnsafeDeleteKey(s.ctx, resp.GetKasKey(), &unsafe.UnsafeDeleteKasKeyRequest{Id: resp.GetKasKey().GetKey().GetId(), KasUri: resp.GetKasKey().GetKasUri(), Kid: "wrong-KID"})
	s.Require().Error(err)
	s.Nil(deleteResp)
	s.Require().ErrorIs(err, db.ErrKIDMismatch)

	deleteResp, err = s.db.PolicyClient.UnsafeDeleteKey(s.ctx, resp.GetKasKey(), &unsafe.UnsafeDeleteKasKeyRequest{Id: resp.GetKasKey().GetKey().GetId(), KasUri: "wrong-kas-uri", Kid: resp.GetKasKey().GetKey().GetKeyId()})
	s.Require().Error(err)
	s.Nil(deleteResp)
	s.Require().ErrorIs(err, db.ErrKasURIMismatch)
}

func (s *KasRegistryKeySuite) Test_DeleteKey_Success() {
	// Create KAS server
	req := kasregistry.CreateKeyRequest{
		KasId:        s.kasKeys[0].KeyAccessServerID,
		KeyId:        uuid.NewString(),
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{Pem: keyCtx},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			WrappedKey: keyCtx,
			KeyId:      validKeyID1,
		},
	}
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)

	deleteResp, err := s.db.PolicyClient.UnsafeDeleteKey(s.ctx, resp.GetKasKey(), &unsafe.UnsafeDeleteKasKeyRequest{
		Id:     resp.GetKasKey().GetKey().GetId(),
		Kid:    resp.GetKasKey().GetKey().GetKeyId(),
		KasUri: resp.GetKasKey().GetKasUri(),
	})
	s.Require().NoError(err)
	s.NotNil(deleteResp)
	s.Equal(resp.GetKasKey().GetKey().GetId(), deleteResp.GetId())

	// Verify it's deleted
	getResp, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{
		Id: resp.GetKasKey().GetKey().GetId(),
	})
	s.Require().Error(err)
	s.Nil(getResp)
	s.Require().ErrorContains(err, db.ErrNotFound.Error())
}

func (s *KasRegistryKeySuite) validateKeyMapping(mapping *kasregistry.KeyMapping, expectedKey *policy.KasKey, expectedNamespace []*policy.Namespace, expectedAttrDef []*policy.Attribute, expectedValue []*policy.Value) {
	s.Equal(expectedKey.GetKey().GetKeyId(), mapping.GetKid())
	s.Equal(expectedKey.GetKasUri(), mapping.GetKasUri())
	s.Len(mapping.GetNamespaceMappings(), len(expectedNamespace))
	s.Len(mapping.GetAttributeMappings(), len(expectedAttrDef))
	s.Len(mapping.GetValueMappings(), len(expectedValue))

	if len(expectedNamespace) > 0 {
		for _, ns := range expectedNamespace {
			found := false
			for _, nsMapping := range mapping.GetNamespaceMappings() {
				if nsMapping.GetId() == ns.GetId() && nsMapping.GetFqn() == ns.GetFqn() {
					found = true
					break
				}
			}
			s.True(found, "Namespace mapping not found: %s", ns.GetFqn())
		}
	}
	if len(expectedAttrDef) > 0 {
		for _, attr := range expectedAttrDef {
			found := false
			for _, attrMapping := range mapping.GetAttributeMappings() {
				if attrMapping.GetId() == attr.GetId() && attrMapping.GetFqn() == attr.GetFqn() {
					found = true
					break
				}
			}
			s.True(found, "Attribute mapping not found: %s", attr.GetFqn())
		}
	}
	if len(expectedValue) > 0 {
		for _, val := range expectedValue {
			found := false
			for _, valMapping := range mapping.GetValueMappings() {
				if valMapping.GetId() == val.GetId() && valMapping.GetFqn() == val.GetFqn() {
					found = true
					break
				}
			}
			s.True(found, "Value mapping not found: %s", val.GetFqn())
		}
	}
}

func (s *KasRegistryKeySuite) setupKeysForRotate(kasID string) map[string]*policy.KasKey {
	// Create a key for the KAS
	keyReq := kasregistry.CreateKeyRequest{
		KasId:        kasID,
		KeyId:        "original_key_id_to_rotate",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P384,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{
			Pem: keyCtx,
		},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
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
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{
			Pem: keyCtx,
		},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
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
				for j := 0; j < numAttrsToNotRotate; j++ {
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

func (s *KasRegistryKeySuite) cleanupKeys(keyIDs []string, keyAccessServerIDs []string) {
	// use Pgx.Exec because DELETE is only for testing and should not be part of PolicyDBClient
	_, err := s.db.PolicyClient.Pgx.Exec(s.ctx, "DELETE FROM base_keys")
	s.Require().NoError(err)

	for _, id := range keyIDs {
		key, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{
			Id: id,
		})
		s.Require().NoError(err)
		s.NotNil(key)
		r := unsafe.UnsafeDeleteKasKeyRequest{
			Id:     key.GetKey().GetId(),
			KasUri: key.GetKasUri(),
			Kid:    key.GetKey().GetKeyId(),
		}
		_, err = s.db.PolicyClient.UnsafeDeleteKey(s.ctx, key, &r)
		s.Require().NoError(err)
	}
	for _, id := range keyAccessServerIDs {
		_, err := s.db.PolicyClient.DeleteKeyAccessServer(s.ctx, id)
		s.Require().NoError(err)
	}
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

func (s *KasRegistryKeySuite) validateListKeysResponse(resp *kasregistry.ListKeysResponse, numKeys int, err error) {
	s.Require().NoError(err)
	s.NotNil(resp)
	s.GreaterOrEqual(len(resp.GetKasKeys()), numKeys)
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
		if fixtureKey.ProviderConfigID == nil {
			s.Nil(key.GetKey().GetProviderConfig())
		} else {
			s.Equal(*fixtureKey.ProviderConfigID, key.GetKey().GetProviderConfig().GetId())
		}
		validatePrivatePublicCtx(&s.Suite, []byte(fixtureKey.PrivateKeyCtx), []byte(fixtureKey.PublicKeyCtx), key)
		s.Require().NoError(err)
	}
}

func validatePublicKeyCtx(s *suite.Suite, expectedPubCtx []byte, actual *policy.SimpleKasKey) {
	decodedExpectedPubCtx, err := base64.StdEncoding.DecodeString(string(expectedPubCtx))
	s.Require().NoError(err)

	var expectedPub policy.PublicKeyCtx
	err = protojson.Unmarshal(decodedExpectedPubCtx, &expectedPub)
	s.Require().NoError(err)
	s.Equal(expectedPub.GetPem(), actual.GetPublicKey().GetPem())
}

func validatePrivatePublicCtx(s *suite.Suite, expectedPrivCtx, expectedPubCtx []byte, actual *policy.KasKey) {
	decodedExpectedPrivCtx, err := base64.StdEncoding.DecodeString(string(expectedPrivCtx))
	s.Require().NoError(err)

	var expectedPriv policy.PrivateKeyCtx
	err = protojson.Unmarshal(decodedExpectedPrivCtx, &expectedPriv)
	s.Require().NoError(err)

	s.Equal(expectedPriv.GetKeyId(), actual.GetKey().GetPrivateKeyCtx().GetKeyId())
	s.Equal(expectedPriv.GetWrappedKey(), actual.GetKey().GetPrivateKeyCtx().GetWrappedKey())
	validatePublicKeyCtx(s, expectedPubCtx, &policy.SimpleKasKey{
		KasUri: actual.GetKasUri(),
		PublicKey: &policy.SimpleKasPublicKey{
			Pem: actual.GetKey().GetPublicKeyCtx().GetPem(),
		},
	})
}

// cascade delete will remove namespaces and all associated attributes and values
func (s *KasRegistryKeySuite) cleanupNamespacesAndAttrsByIDs(namespaceIDs []string) {
	namespaces := make([]*policy.Namespace, len(namespaceIDs))
	for i, id := range namespaceIDs {
		ns, err := s.db.PolicyClient.GetNamespace(s.ctx, id)
		s.Require().NoError(err)
		s.NotNil(ns)
		namespaces[i] = ns
	}
	s.cleanupNamespacesAndAttrs(namespaces)
}

// cascade delete will remove namespaces and all associated attributes and values
func (s *KasRegistryKeySuite) cleanupNamespacesAndAttrs(namespaces []*policy.Namespace) {
	for _, ns := range namespaces {
		_, err := s.db.PolicyClient.UnsafeDeleteNamespace(s.ctx, ns, ns.GetFqn())
		s.Require().NoError(err)
	}
}

func (s *KasRegistryKeySuite) createNamespace() *policy.Namespace {
	nsReq := namespaces.CreateNamespaceRequest{
		Name: "test_namespace_" + uuid.NewString(),
	}
	namespace, err := s.db.PolicyClient.CreateNamespace(s.ctx, &nsReq)
	s.Require().NoError(err)
	s.NotNil(namespace)
	return namespace
}

func (s *KasRegistryKeySuite) createAttrDef(namespaceID string) *policy.Attribute {
	attrDefReq := attributes.CreateAttributeRequest{
		Name:        "test_attr_def_" + uuid.NewString(),
		NamespaceId: namespaceID,
		Rule:        policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF,
	}
	attrDef, err := s.db.PolicyClient.CreateAttribute(s.ctx, &attrDefReq)
	s.Require().NoError(err)
	s.NotNil(attrDef)
	return attrDef
}

func (s *KasRegistryKeySuite) createValue(definitionID string) *policy.Value {
	valueReq := attributes.CreateAttributeValueRequest{
		AttributeId: definitionID,
		Value:       "test_value_" + uuid.NewString(),
	}
	value, err := s.db.PolicyClient.CreateAttributeValue(s.ctx, definitionID, &valueReq)
	s.Require().NoError(err)
	s.NotNil(value)
	return value
}

func (s *KasRegistryKeySuite) createAttrDefMapping(keyID, attrID string) {
	attrDefMapping := &attributes.AttributeKey{
		KeyId:       keyID,
		AttributeId: attrID,
	}
	mapping, err := s.db.PolicyClient.AssignPublicKeyToAttribute(s.ctx, attrDefMapping)
	s.Require().NoError(err)
	s.NotNil(mapping)
}

func (s *KasRegistryKeySuite) createValueMapping(keyID, valueID string) {
	valueMapping := &attributes.ValueKey{
		KeyId:   keyID,
		ValueId: valueID,
	}
	mapping, err := s.db.PolicyClient.AssignPublicKeyToValue(s.ctx, valueMapping)
	s.Require().NoError(err)
	s.NotNil(mapping)
}

func (s *KasRegistryKeySuite) createNamespaceMapping(keyID, namespaceID string) {
	namespaceMapping := &namespaces.NamespaceKey{
		KeyId:       keyID,
		NamespaceId: namespaceID,
	}
	mapping, err := s.db.PolicyClient.AssignPublicKeyToNamespace(s.ctx, namespaceMapping)
	s.Require().NoError(err)
	s.NotNil(mapping)
}

func (s *KasRegistryKeySuite) createKeyAndKas() *policy.KasKey {
	kasReq := kasregistry.CreateKeyAccessServerRequest{
		Name: "test_list_mapping_kas_" + uuid.NewString(),
		Uri:  "https://test-list-mappings-" + uuid.NewString() + ".opentdf.io",
	}
	kas, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, &kasReq)
	s.Require().NoError(err)
	s.NotNil(kas)

	// Create key
	keyReq := kasregistry.CreateKeyRequest{
		KasId:        kas.GetId(),
		KeyId:        uuid.NewString(),
		KeyAlgorithm: policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:      policy.KeyMode_KEY_MODE_CONFIG_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{
			Pem: keyCtx,
		},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			KeyId:      validKeyID1,
			WrappedKey: keyCtx,
		},
	}
	keyResp, err := s.db.PolicyClient.CreateKey(s.ctx, &keyReq)
	s.Require().NoError(err)
	s.NotNil(keyResp)

	return keyResp.GetKasKey()
}

// Test_ListKeyMappings_AllParameterCombinations validates that listKeyMappings works correctly
// with various combinations of optional parameters
func (s *KasRegistryKeySuite) Test_ListKeyMappings_AllParameterCombinations() {
	kas1 := s.kasFixtures[0]
	key1 := s.kasKeys[0]

	// Test 1: No parameters - should return all mappings (may be 0)
	allMappings, err := s.db.PolicyClient.ListKeyMappings(s.ctx, &kasregistry.ListKeyMappingsRequest{})
	s.Require().NoError(err)
	s.NotNil(allMappings)
	// No assertion on count - fixtures may not have any mappings

	// Test 2: Filter by key with KAS URI
	mappingsByKey, err := s.db.PolicyClient.ListKeyMappings(s.ctx, &kasregistry.ListKeyMappingsRequest{
		Identifier: &kasregistry.ListKeyMappingsRequest_Key{
			Key: &kasregistry.KasKeyIdentifier{
				Identifier: &kasregistry.KasKeyIdentifier_Uri{
					Uri: kas1.URI,
				},
				Kid: key1.KeyID,
			},
		},
	})
	s.Require().NoError(err, "Should successfully query with KAS URI and key ID")
	s.NotNil(mappingsByKey)

	// Test 3: Filter by key with KAS ID (validates alternative params path)
	mappingsByKeyID, err := s.db.PolicyClient.ListKeyMappings(s.ctx, &kasregistry.ListKeyMappingsRequest{
		Identifier: &kasregistry.ListKeyMappingsRequest_Key{
			Key: &kasregistry.KasKeyIdentifier{
				Identifier: &kasregistry.KasKeyIdentifier_KasId{
					KasId: key1.KeyAccessServerID,
				},
				Kid: key1.KeyID,
			},
		},
	})
	s.Require().NoError(err, "Should successfully query with KAS ID and key ID")
	s.NotNil(mappingsByKeyID)
}
