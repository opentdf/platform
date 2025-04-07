package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/keymanagement"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/suite"
)

const (
	validProviderConfigName  = "provider_config_name"
	validProviderConfigName2 = "provider_config_name_2"
	validProviderConfigName3 = "provider_config_name_3"
	validKeyId1              = "key_id_1"
	validKeyId2              = "key_id_2"
	validKeyId3              = "key_id_3"
	keyId4                   = "key_id_4"
	notFoundKasUUID          = "123e4567-e89b-12d3-a456-426614174000"
	privateKeyCtx            = `{"key":"value"}`
	providerConfigId         = "123e4567-e89b-12d3-a456-426614174000"
)

type kasRegistryKey struct {
	asymKey *policy.AsymmetricKey
	kasId   string
}

type KasRegistryKeySuite struct {
	suite.Suite
	f           fixtures.Fixtures
	db          fixtures.DBInterface
	kasFixtures []fixtures.FixtureDataKasRegistry
	kasKeys     []kasRegistryKey // Note: I use the first Key for Create Tests and the Second/Third key for Update/List Tests
	ctx         context.Context  //nolint:containedctx // context is used in the test suite
}

func (s *KasRegistryKeySuite) SetupSuite() {
	slog.Info("setting up db.KasKeys test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_kas_keys"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
	s.createFixtures()
	s.kasFixtures = s.getKasRegistryFixtures()
}

func (s *KasRegistryKeySuite) createFixtures() {
	s.kasKeys = make([]kasRegistryKey, 3)
	fixtureKeys := s.getKasRegistryFixtures()
	resp := s.addKeyAndProviderConfig(validProviderConfigName, &kasregistry.CreateKeyRequest{
		KasId:         fixtureKeys[0].ID,
		KeyId:         validKeyId1,
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
		PrivateKeyCtx: []byte(privateKeyCtx),
		PublicKeyCtx:  []byte(privateKeyCtx),
	})
	s.kasKeys[0] = kasRegistryKey{
		asymKey: resp.Key,
		kasId:   fixtureKeys[0].ID,
	}

	resp = s.addKeyAndProviderConfig(validProviderConfigName, &kasregistry.CreateKeyRequest{
		KasId:         fixtureKeys[1].ID,
		KeyId:         validKeyId2,
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
		PrivateKeyCtx: []byte(privateKeyCtx),
		PublicKeyCtx:  []byte(privateKeyCtx),
	})
	s.kasKeys[1] = kasRegistryKey{
		asymKey: resp.Key,
		kasId:   fixtureKeys[1].ID,
	}

	// Update the second key to be inactive
	_, err := s.db.PolicyClient.UpdateKey(s.ctx, &kasregistry.UpdateKeyRequest{
		Id:        s.kasKeys[1].asymKey.Id,
		KeyStatus: policy.KeyStatus_KEY_STATUS_INACTIVE,
	})
	s.Require().NoError(err)

	resp = s.addKeyAndProviderConfig(validProviderConfigName3, &kasregistry.CreateKeyRequest{
		KasId:         fixtureKeys[1].ID,
		KeyId:         validKeyId3,
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
		PrivateKeyCtx: []byte(privateKeyCtx),
		PublicKeyCtx:  []byte(privateKeyCtx),
	})
	s.kasKeys[2] = kasRegistryKey{
		asymKey: resp.Key,
		kasId:   fixtureKeys[1].ID,
	}
}

func (s *KasRegistryKeySuite) addKeyAndProviderConfig(providerName string, r *kasregistry.CreateKeyRequest) *kasregistry.CreateKeyResponse {
	kpc, err := s.addProviderConfig(providerName)
	s.Require().NoError(err)
	s.Require().NotNil(kpc)

	r.ProviderConfigId = kpc.Id
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, r)
	s.Require().NoError(err)
	s.Require().NotNil(resp)
	s.Require().NotNil(resp.Key)

	return resp
}

func (s *KasRegistryKeySuite) addProviderConfig(providerName string) (*policy.KeyProviderConfig, error) {
	return s.db.PolicyClient.CreateProviderConfig(s.ctx, &keymanagement.CreateProviderConfigRequest{
		Name:       providerName,
		ConfigJson: []byte(privateKeyCtx),
	})
}

func (s *KasRegistryKeySuite) getKasRegistryFixtures() []fixtures.FixtureDataKasRegistry {
	return []fixtures.FixtureDataKasRegistry{
		s.f.GetKasRegistryKey("key_access_server_1"),
		s.f.GetKasRegistryKey("key_access_server_2"),
	}
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

func (s *KasRegistryKeySuite) Test_CreateKasKey_InvalidKasId_Fail() {
	req := kasregistry.CreateKeyRequest{
		KasId:         notFoundKasUUID,
		KeyId:         validKeyId1,
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_4096,
		KeyMode:       policy.KeyMode_KEY_MODE_REMOTE,
		PrivateKeyCtx: []byte(privateKeyCtx),
	}
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().Error(err)
	s.ErrorContains(err, db.ErrTextNotFound)
	s.Nil(resp)
}

func (s *KasRegistryKeySuite) Test_CreateKasKey_PrivateCtxEmpty_Fail() {
	req := kasregistry.CreateKeyRequest{
		KasId:         s.kasKeys[0].kasId,
		KeyId:         validKeyId1,
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_4096,
		KeyMode:       policy.KeyMode_KEY_MODE_REMOTE,
		PrivateKeyCtx: make([]byte, 0),
	}
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().Error(err)
	s.Nil(resp)
	s.ErrorContains(err, "private key context")
}

func (s *KasRegistryKeySuite) Test_CreateKasKey_LocalKeyMode_NoPublicCtx_Fail() {
	req := kasregistry.CreateKeyRequest{
		KasId:         s.kasKeys[0].kasId,
		KeyId:         validKeyId1,
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_4096,
		KeyMode:       policy.KeyMode_KEY_MODE_LOCAL,
		PrivateKeyCtx: []byte(privateKeyCtx),
	}
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().Error(err)
	s.Nil(resp)
	s.ErrorContains(err, "public key context")
}

func (s *KasRegistryKeySuite) Test_CreateKasKey_ProviderConfigInvalid_Fail() {
	req := kasregistry.CreateKeyRequest{
		KasId:            s.kasKeys[0].kasId,
		KeyId:            validKeyId1,
		KeyAlgorithm:     policy.Algorithm_ALGORITHM_RSA_4096,
		KeyMode:          policy.KeyMode_KEY_MODE_REMOTE,
		PrivateKeyCtx:    []byte(privateKeyCtx),
		ProviderConfigId: providerConfigId,
	}
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().Error(err)
	s.Nil(resp)
	s.ErrorContains(err, db.ErrTextNotFound)
}

func (s *KasRegistryKeySuite) Test_CreateKasKey_ActiveKeyForAlgoExists_Fail() {
	req := kasregistry.CreateKeyRequest{
		KasId:         s.kasKeys[0].kasId,
		KeyId:         "",
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:       policy.KeyMode_KEY_MODE_REMOTE,
		PrivateKeyCtx: []byte(privateKeyCtx),
	}
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().Error(err)
	s.ErrorContains(err, "cannot create a new key")
	s.Nil(resp)
}

func (s *KasRegistryKeySuite) Test_CreateKasKey_Success() {
	req := kasregistry.CreateKeyRequest{
		KasId:         s.kasKeys[0].kasId,
		KeyId:         keyId4,
		KeyAlgorithm:  policy.Algorithm_ALGORITHM_RSA_2048,
		KeyMode:       policy.KeyMode_KEY_MODE_REMOTE,
		PrivateKeyCtx: []byte(privateKeyCtx),
	}
	resp, err := s.db.PolicyClient.CreateKey(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Nil(resp.GetKey().GetProviderConfig())
}

func (s *KasRegistryKeySuite) Test_GetKasKey_InvalidId_Fail() {
	resp, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{
		Id: "invalid-uuid",
	})
	s.Require().Error(err)
	s.Nil(resp)
	s.ErrorContains(err, db.ErrUUIDInvalid.Error())
}

func (s *KasRegistryKeySuite) Test_GetKasKey_InvalidKeyId_Fail() {
	resp, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_KeyId{
		KeyId: "",
	})
	s.Require().Error(err)
	s.Nil(resp)
	s.ErrorContains(err, db.ErrSelectIdentifierInvalid.Error())
}

func (s *KasRegistryKeySuite) Test_GetKasKey_InvalidIdentifier_Fail() {
	resp, err := s.db.PolicyClient.GetKey(s.ctx, &keymanagement.GetProviderConfigRequest_Id{
		Id: "",
	})
	s.Require().Error(err)
	s.Nil(resp)
	s.ErrorContains(err, db.ErrUnknownSelectIdentifier.Error())
}

func (s *KasRegistryKeySuite) Test_GetKasKeyById_Success() {
	resp, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_Id{
		Id: s.kasKeys[0].asymKey.Id,
	})
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(s.kasKeys[0].asymKey.GetId(), resp.GetId())
}

func (s *KasRegistryKeySuite) Test_GetKasKeyByKeyId_Success() {
	resp, err := s.db.PolicyClient.GetKey(s.ctx, &kasregistry.GetKeyRequest_KeyId{
		KeyId: s.kasKeys[0].asymKey.KeyId,
	})
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(s.kasKeys[0].asymKey.GetId(), resp.GetId())
}

func (s *KasRegistryKeySuite) Test_UpdateKey_InvalidKeyId_Fails() {
	req := kasregistry.UpdateKeyRequest{
		Id: "",
	}
	resp, err := s.db.PolicyClient.UpdateKey(s.ctx, &req)
	s.Require().Error(err)
	s.Nil(resp)
	s.ErrorContains(err, db.ErrUUIDInvalid.Error())
}

func (s *KasRegistryKeySuite) Test_UpdateKey_AlreadyActiveKeyWithSameAlgo_Fails() {
	req := kasregistry.UpdateKeyRequest{
		Id:        s.kasKeys[1].asymKey.Id,
		KeyStatus: policy.KeyStatus_KEY_STATUS_ACTIVE,
	}
	resp, err := s.db.PolicyClient.UpdateKey(s.ctx, &req)
	s.Require().Error(err)
	s.Nil(resp)
	s.ErrorContains(err, "key cannot be updated")
}

func (s *KasRegistryKeySuite) Test_UpdateKey_EmptyOptions_Fails() {
	req := kasregistry.UpdateKeyRequest{
		Id: s.kasKeys[1].asymKey.Id,
	}
	resp, err := s.db.PolicyClient.UpdateKey(s.ctx, &req)
	s.Require().Error(err)
	s.Nil(resp)
	s.ErrorContains(err, "cannot update key")
}

func (s *KasRegistryKeySuite) Test_UpdateKeyStatus_Success() {
	req := kasregistry.UpdateKeyRequest{
		Id:        s.kasKeys[1].asymKey.Id,
		KeyStatus: policy.KeyStatus_KEY_STATUS_COMPROMISED,
	}
	resp, err := s.db.PolicyClient.UpdateKey(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(s.kasKeys[1].asymKey.GetId(), resp.GetId())
}

func (s *KasRegistryKeySuite) Test_UpdateKeyMetadata_Success() {
	req := kasregistry.UpdateKeyRequest{
		Id: s.kasKeys[1].asymKey.Id,
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{"key": "value"},
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	}
	resp, err := s.db.PolicyClient.UpdateKey(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(s.kasKeys[1].asymKey.GetId(), resp.GetId())
}

func (s *KasRegistryKeySuite) Test_ListKeys_InvalidLimit_Fail() {
	req := kasregistry.ListKeysRequest{
		Pagination: &policy.PageRequest{
			Limit: 5001,
		},
	}
	resp, err := s.db.PolicyClient.ListKeys(s.ctx, &req)
	s.Require().Error(err)
	s.Nil(resp)
	s.ErrorContains(err, db.ErrListLimitTooLarge.Error())
}

func (s *KasRegistryKeySuite) Test_ListKeys_KasID_Success() {
	req := kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasId{
			KasId: s.kasKeys[1].kasId,
		},
	}
	resp, err := s.db.PolicyClient.ListKeys(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(2, len(resp.Keys))
	s.Equal(int32(2), resp.Pagination.Total)
	fixtureKeyIds := []string{s.kasKeys[1].asymKey.GetId(), s.kasKeys[2].asymKey.GetId()}
	fixtureProviderConfigIds := []string{s.kasKeys[1].asymKey.GetProviderConfig().GetId(), s.kasKeys[2].asymKey.GetProviderConfig().GetId()}
	s.Contains(fixtureKeyIds, resp.Keys[0].GetId())
	s.Contains(fixtureKeyIds, resp.Keys[1].GetId())
	s.Contains(fixtureProviderConfigIds, resp.Keys[0].GetProviderConfig().GetId())
	s.Contains(fixtureProviderConfigIds, resp.Keys[1].GetProviderConfig().GetId())
}
func (s *KasRegistryKeySuite) Test_ListKeys_KasName_Success() {
	req := kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasName{
			KasName: s.kasFixtures[1].Name,
		},
	}
	resp, err := s.db.PolicyClient.ListKeys(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(2, len(resp.Keys))
	s.Equal(int32(2), resp.Pagination.Total)
	fixtureKeyIds := []string{s.kasKeys[1].asymKey.GetId(), s.kasKeys[2].asymKey.GetId()}
	fixtureProviderConfigIds := []string{s.kasKeys[1].asymKey.GetProviderConfig().GetId(), s.kasKeys[2].asymKey.GetProviderConfig().GetId()}
	s.Contains(fixtureKeyIds, resp.Keys[0].GetId())
	s.Contains(fixtureKeyIds, resp.Keys[1].GetId())
	s.Contains(fixtureProviderConfigIds, resp.Keys[0].GetProviderConfig().GetId())
	s.Contains(fixtureProviderConfigIds, resp.Keys[1].GetProviderConfig().GetId())
}
func (s *KasRegistryKeySuite) Test_ListKeys_KasURI_Success() {
	req := kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasUri{
			KasUri: s.kasFixtures[1].URI,
		},
	}
	resp, err := s.db.PolicyClient.ListKeys(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(2, len(resp.Keys))
	s.Equal(int32(2), resp.Pagination.Total)
	fixtureKeyIds := []string{s.kasKeys[1].asymKey.GetId(), s.kasKeys[2].asymKey.GetId()}
	fixtureProviderConfigIds := []string{s.kasKeys[1].asymKey.GetProviderConfig().GetId(), s.kasKeys[2].asymKey.GetProviderConfig().GetId()}
	s.Contains(fixtureKeyIds, resp.Keys[0].GetId())
	s.Contains(fixtureKeyIds, resp.Keys[1].GetId())
	s.Contains(fixtureProviderConfigIds, resp.Keys[0].GetProviderConfig().GetId())
	s.Contains(fixtureProviderConfigIds, resp.Keys[1].GetProviderConfig().GetId())
}

func (s *KasRegistryKeySuite) Test_ListKeys_FilterAlgo_NoKeysWithAlgo_Success() {
	req := kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasId{
			KasId: s.kasFixtures[1].ID,
		},
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P521,
	}
	resp, err := s.db.PolicyClient.ListKeys(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(0, len(resp.Keys))
}

func (s *KasRegistryKeySuite) Test_ListKeys_FilterAlgo_TwoKeys_Success() {
	req := kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasUri{
			KasUri: s.kasFixtures[1].URI,
		},
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
	}
	resp, err := s.db.PolicyClient.ListKeys(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(2, len(resp.Keys))
	s.Equal(int32(2), resp.Pagination.Total)
	fixtureKeyIds := []string{s.kasKeys[1].asymKey.GetId(), s.kasKeys[2].asymKey.GetId()}
	fixtureProviderConfigIds := []string{s.kasKeys[1].asymKey.GetProviderConfig().GetId(), s.kasKeys[2].asymKey.GetProviderConfig().GetId()}
	s.Contains(fixtureKeyIds, resp.Keys[0].GetId())
	s.Contains(fixtureKeyIds, resp.Keys[1].GetId())
	s.Contains(fixtureProviderConfigIds, resp.Keys[0].GetProviderConfig().GetId())
	s.Contains(fixtureProviderConfigIds, resp.Keys[1].GetProviderConfig().GetId())
}

func (s *KasRegistryKeySuite) Test_ListKeys_KasID_Limit_Success() {
	req := kasregistry.ListKeysRequest{
		KasFilter: &kasregistry.ListKeysRequest_KasUri{
			KasUri: s.kasFixtures[1].URI,
		},
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
		Pagination: &policy.PageRequest{
			Limit: 1,
		},
	}
	resp, err := s.db.PolicyClient.ListKeys(s.ctx, &req)
	s.Require().NoError(err)
	s.NotNil(resp)
	s.Equal(1, len(resp.Keys))
	s.Equal(int32(2), resp.Pagination.Total)
	s.Equal(int32(1), resp.Pagination.NextOffset)
	s.Equal(int32(0), resp.Pagination.CurrentOffset)
	fixtureKeyIds := []string{s.kasKeys[1].asymKey.GetId(), s.kasKeys[2].asymKey.GetId()}
	fixtureProviderConfigIds := []string{s.kasKeys[1].asymKey.GetProviderConfig().GetId(), s.kasKeys[2].asymKey.GetProviderConfig().GetId()}
	s.Contains(fixtureKeyIds, resp.Keys[0].GetId())
	s.Contains(fixtureProviderConfigIds, resp.Keys[0].GetProviderConfig().GetId())
}
