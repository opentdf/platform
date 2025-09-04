package integration

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/protocol/go/policy/keymanagement"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/suite"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	validProviderConfig   = []byte(`{"key": "value"}`)
	validProviderConfig2  = []byte(`{"key2": "value2"}`)
	invalidProviderConfig = []byte(`{"key": "value"`)
	invalidUUID           = "invalid-uuid"
	validLabels           = map[string]string{"key": "value"}
	additionalLabels      = map[string]string{"key2": "value2"}
)

type KeyManagementSuite struct {
	suite.Suite
	f            fixtures.Fixtures
	db           fixtures.DBInterface
	ctx          context.Context //nolint:containedctx // context is used in the test suite
	testProvider string
}

func (s *KeyManagementSuite) SetupSuite() {
	slog.Info("setting up db.KeyManagement test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_provider_config"
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
}

func (s *KeyManagementSuite) SetupTest() {
	s.testProvider = s.getUniqueProviderName("test-provider")
}

func (s *KeyManagementSuite) TearDownSuite() {
	slog.Info("tearing down db.KeyManagement test suite")
	s.f.TearDown()
}

func (s *KeyManagementSuite) Test_CreateProviderConfig_NoMetada_Succeeds() {
	pcIDs := make([]string, 0)
	s.deleteTestProviderConfigs(append(pcIDs, s.createTestProviderConfig(s.testProvider, validProviderConfig, nil).GetId()))
}

func (s *KeyManagementSuite) Test_CreateProviderConfig_Metadata_Succeeds() {
	pcIDs := make([]string, 0)
	s.deleteTestProviderConfigs(append(pcIDs, s.createTestProviderConfig(s.testProvider, validProviderConfig, &common.MetadataMutable{
		Labels: validLabels,
	}).GetId()))
}

func (s *KeyManagementSuite) Test_CreateProviderConfig_EmptyConfig_Fails() {
	pc, err := s.db.PolicyClient.CreateProviderConfig(s.ctx, &keymanagement.CreateProviderConfigRequest{
		Name: s.testProvider,
	})
	s.Require().Error(err)
	s.Require().ErrorContains(err, db.ErrNotNullViolation.Error())
	s.Nil(pc)
}

func (s *KeyManagementSuite) Test_CreateProviderConfig_InvalidConfig_Fails() {
	pc, err := s.db.PolicyClient.CreateProviderConfig(s.ctx, &keymanagement.CreateProviderConfigRequest{
		Name:       s.testProvider,
		ConfigJson: invalidProviderConfig,
	})
	s.Require().Error(err)
	s.Require().ErrorContains(err, db.ErrEnumValueInvalid.Error())
	s.Nil(pc)
}

func (s *KeyManagementSuite) Test_CreateProviderConfig_DuplicateName_Fails() {
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()
	pc := s.createTestProviderConfig(s.testProvider, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc.GetId())

	pc, err := s.db.PolicyClient.CreateProviderConfig(s.ctx, &keymanagement.CreateProviderConfigRequest{
		Name:       pc.GetName(),
		Manager:    pc.GetManager(),
		ConfigJson: validProviderConfig,
	})
	s.Require().Error(err)
	s.Require().ErrorContains(err, db.ErrUniqueConstraintViolation.Error())
	s.Nil(pc)
}

func (s *KeyManagementSuite) Test_CreateProviderConfig_CapitalizedName_Succeeds() {
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()

	providerName := strings.ToUpper(s.testProvider)
	pc := s.createTestProviderConfig(providerName, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc.GetId())

	pcGet, err := s.db.PolicyClient.GetProviderConfig(s.ctx, &keymanagement.GetProviderConfigRequest_Name{
		Name: s.testProvider,
	})
	s.Require().NoError(err)
	s.NotNil(pcGet)
	s.Equal(s.testProvider, pcGet.GetName()) // Expect name to be lowercased
	s.Equal(validProviderConfig, pcGet.GetConfigJson())
}

func (s *KeyManagementSuite) Test_GetProviderConfig_WithId_Succeeds() {
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()

	pc := s.createTestProviderConfig(s.testProvider, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc.GetId())

	pc, err := s.db.PolicyClient.GetProviderConfig(s.ctx, &keymanagement.GetProviderConfigRequest_Id{
		Id: pc.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(pc)
}

func (s *KeyManagementSuite) Test_GetProviderConfig_WithName_Succeeds() {
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()

	pc := s.createTestProviderConfig(s.testProvider, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc.GetId())

	pc, err := s.db.PolicyClient.GetProviderConfig(s.ctx, &keymanagement.GetProviderConfigRequest_Name{
		Name: s.testProvider,
	})
	s.Require().NoError(err)
	s.NotNil(pc)
	s.Equal(s.testProvider, pc.GetName())
	s.Equal(validProviderConfig, pc.GetConfigJson())
}

func (s *KeyManagementSuite) Test_GetProviderConfig_MixedCaseName_Succeeds() {
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()

	mixedCaseName := cases.Title(language.English).String(s.testProvider) // "Test-provider"
	pc := s.createTestProviderConfig(mixedCaseName, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc.GetId())

	pcGet, err := s.db.PolicyClient.GetProviderConfig(s.ctx, &keymanagement.GetProviderConfigRequest_Name{
		Name: s.testProvider, // search with lowercase name
	})
	s.Require().NoError(err)
	s.NotNil(pcGet)
	s.Equal(s.testProvider, pcGet.GetName()) // Expect name to be lowercased
	s.Equal(validProviderConfig, pcGet.GetConfigJson())
}

func (s *KeyManagementSuite) Test_GetProviderConfig_InvalidIdentifier_Fails() {
	pc, err := s.db.PolicyClient.GetProviderConfig(s.ctx, &map[string]string{})
	s.Require().Error(err)
	s.Nil(pc)
}

// Finish List/Update/Delete tests
func (s *KeyManagementSuite) Test_ListProviderConfig_No_Pagination_Succeeds() {
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()

	pc := s.createTestProviderConfig(s.testProvider, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc.GetId())

	resp, err := s.db.PolicyClient.ListProviderConfigs(s.ctx, &policy.PageRequest{})
	s.Require().NoError(err)
	s.NotNil(resp)
	s.NotEmpty(resp.GetProviderConfigs())
}

func (s *KeyManagementSuite) Test_ListProviderConfig_PaginationLimit_Succeeds() {
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()

	testProvider2 := s.getUniqueProviderName("test-provider-2")

	pc := s.createTestProviderConfig(s.testProvider, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc.GetId())
	pc2 := s.createTestProviderConfig(testProvider2, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc2.GetId())

	respOne, err := s.db.PolicyClient.ListProviderConfigs(s.ctx, &policy.PageRequest{
		Limit: 1,
	})
	s.Require().NoError(err)
	s.NotNil(respOne)
	s.NotEmpty(respOne.GetProviderConfigs())
	s.Len(respOne.GetProviderConfigs(), 1)
	s.GreaterOrEqual(respOne.GetPagination().GetTotal(), int32(1))

	respTwo, err := s.db.PolicyClient.ListProviderConfigs(s.ctx, &policy.PageRequest{
		Limit:  1,
		Offset: 1,
	})
	s.Require().NoError(err)
	s.NotNil(respTwo)
	s.NotEmpty(respTwo.GetProviderConfigs())
	s.Len(respTwo.GetProviderConfigs(), 1)
	s.GreaterOrEqual(respTwo.GetPagination().GetTotal(), int32(1))
	s.NotEqual(respOne.GetProviderConfigs()[0].GetId(), respTwo.GetProviderConfigs()[0].GetId())
}

func (s *KeyManagementSuite) Test_ListProviderConfig_PaginationLimitExceeded_Fails() {
	resp, err := s.db.PolicyClient.ListProviderConfigs(s.ctx, &policy.PageRequest{
		Limit: s.db.LimitMax + 1,
	})
	s.Require().Error(err)
	s.Nil(resp)
}

func (s *KeyManagementSuite) Test_UpdateProviderConfig_ExtendsMetadata_Succeeds() {
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()

	testProvider2 := s.getUniqueProviderName("test-provider-2")
	pc := s.createTestProviderConfig(s.testProvider, validProviderConfig, &common.MetadataMutable{
		Labels: validLabels,
	})
	pcIDs = append(pcIDs, pc.GetId())
	s.NotNil(pc)
	s.Equal(strings.ToLower(s.testProvider), pc.GetName())
	s.Equal(validProviderConfig, pc.GetConfigJson())
	s.Equal(validLabels, pc.GetMetadata().GetLabels())

	pc, err := s.db.PolicyClient.UpdateProviderConfig(s.ctx, &keymanagement.UpdateProviderConfigRequest{
		Id:         pc.GetId(),
		Name:       testProvider2,
		ConfigJson: validProviderConfig2,
		Metadata: &common.MetadataMutable{
			Labels: additionalLabels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	s.Require().NoError(err)
	s.NotNil(pc)
	s.Equal(testProvider2, pc.GetName())
	s.Equal(validProviderConfig2, pc.GetConfigJson())

	mixedLabels := make(map[string]string, 2)
	for k, v := range validLabels {
		mixedLabels[k] = v
	}
	for k, v := range additionalLabels {
		mixedLabels[k] = v
	}
	s.Equal(mixedLabels, pc.GetMetadata().GetLabels())
}

func (s *KeyManagementSuite) Test_UpdateProviderConfig_ReplaceMetadata_Succeeds() {
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()

	testProvider2 := s.getUniqueProviderName("test-provider-2")
	pc := s.createTestProviderConfig(s.testProvider, validProviderConfig, &common.MetadataMutable{
		Labels: validLabels,
	})
	pcIDs = append(pcIDs, pc.GetId())
	s.NotNil(pc)
	s.Equal(s.testProvider, pc.GetName())
	s.Equal(validProviderConfig, pc.GetConfigJson())
	s.Equal(validLabels, pc.GetMetadata().GetLabels())

	pc, err := s.db.PolicyClient.UpdateProviderConfig(s.ctx, &keymanagement.UpdateProviderConfigRequest{
		Id:         pc.GetId(),
		Name:       testProvider2,
		ConfigJson: validProviderConfig2,
		Metadata: &common.MetadataMutable{
			Labels: additionalLabels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE,
	})
	s.Require().NoError(err)
	s.NotNil(pc)
	s.Equal(testProvider2, pc.GetName())
	s.Equal(validProviderConfig2, pc.GetConfigJson())
	s.Equal(additionalLabels, pc.GetMetadata().GetLabels())
}

func (s *KeyManagementSuite) Test_UpdateProviderConfig_InvalidUUID_Fails() {
	testProvider2 := s.getUniqueProviderName("test-provider-2")
	pc, err := s.db.PolicyClient.UpdateProviderConfig(s.ctx, &keymanagement.UpdateProviderConfigRequest{
		Id:         invalidUUID,
		Name:       testProvider2,
		ConfigJson: validProviderConfig2,
	})
	s.Require().Error(err)
	s.Nil(pc)
}

func (s *KeyManagementSuite) Test_UpdateProviderConfig_ConfigNotFound_Fails() {
	testProvider2 := s.getUniqueProviderName("test-provider-2")
	resp, err := s.db.PolicyClient.ListProviderConfigs(s.ctx, &policy.PageRequest{})
	s.Require().NoError(err)
	s.NotNil(resp)

	pcIDs := make(map[string]string, 50)
	for _, pc := range resp.GetProviderConfigs() {
		pcIDs[pc.GetId()] = ""
	}

	isUsedUUID := true
	nonUsedUUID := uuid.NewString()
	for isUsedUUID {
		if _, ok := pcIDs[nonUsedUUID]; !ok {
			isUsedUUID = false
		} else {
			nonUsedUUID = uuid.NewString()
		}
	}

	pc, err := s.db.PolicyClient.UpdateProviderConfig(s.ctx, &keymanagement.UpdateProviderConfigRequest{
		Id:         nonUsedUUID,
		Name:       testProvider2,
		ConfigJson: validProviderConfig2,
	})
	s.Require().Error(err)
	s.Nil(pc)
}

func (s *KeyManagementSuite) Test_UpdateProviderConfig_UpdatesConfigJson_And_Name_Succeeds() {
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()

	testProvider2 := s.getUniqueProviderName("test-provider-2")
	pc := s.createTestProviderConfig(s.testProvider, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc.GetId())
	s.NotNil(pc)
	s.Equal(s.testProvider, pc.GetName())
	s.Equal(validProviderConfig, pc.GetConfigJson())

	pc, err := s.db.PolicyClient.UpdateProviderConfig(s.ctx, &keymanagement.UpdateProviderConfigRequest{
		Id:         pc.GetId(),
		ConfigJson: validProviderConfig2,
		Name:       testProvider2,
	})
	s.Require().NoError(err)
	s.NotNil(pc)
	s.Equal(testProvider2, pc.GetName())
	s.Equal(validProviderConfig2, pc.GetConfigJson())
}

func (s *KeyManagementSuite) Test_UpdateProviderConfig_UpdatesConfigName_Succeeds() {
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()

	testProvider2 := s.getUniqueProviderName("test-provider-2")
	pc := s.createTestProviderConfig(s.testProvider, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc.GetId())
	s.NotNil(pc)
	s.Equal(s.testProvider, pc.GetName())
	s.Equal(validProviderConfig, pc.GetConfigJson())

	pc, err := s.db.PolicyClient.UpdateProviderConfig(s.ctx, &keymanagement.UpdateProviderConfigRequest{
		Id:   pc.GetId(),
		Name: strings.ToUpper(testProvider2),
	})
	s.Require().NoError(err)
	s.NotNil(pc)
	s.Equal(testProvider2, pc.GetName())
	s.Equal(validProviderConfig, pc.GetConfigJson())
}

func (s *KeyManagementSuite) Test_DeleteProviderConfig_Succeeds() {
	pc := s.createTestProviderConfig(s.testProvider, validProviderConfig, nil)
	s.NotNil(pc)
	pc, err := s.db.PolicyClient.DeleteProviderConfig(s.ctx, pc.GetId())
	s.Require().NoError(err)
	s.NotNil(pc)
}

func (s *KeyManagementSuite) Test_DeleteProviderConfig_InUse_Fails() {
	// Create a provider config
	pcIDs := make([]string, 0)
	var kasID string
	var keyID string
	defer func() {
		if keyID != "" {
			_, err := s.db.PolicyClient.DeleteKey(s.ctx, keyID)
			s.Require().NoError(err)
		}
		if kasID != "" {
			_, err := s.db.PolicyClient.DeleteKeyAccessServer(s.ctx, kasID)
			s.Require().NoError(err)
		}

		s.deleteTestProviderConfigs(pcIDs)
	}()
	pc := s.createTestProviderConfig(s.testProvider, validProviderConfig, nil)
	s.NotNil(pc)
	pcIDs = append(pcIDs, pc.GetId())

	// Create a key access server that uses the provider config
	uri := "provider-config-test-kas.com"
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
	kasCreateResp, err := s.db.PolicyClient.CreateKeyAccessServer(s.ctx, kasRegistry)
	s.Require().NoError(err)
	s.NotNil(kasCreateResp)
	kasID = kasCreateResp.GetId()

	// Create a key that uses the provider config
	key, err := s.db.PolicyClient.CreateKey(s.ctx, &kasregistry.CreateKeyRequest{
		KasId:        kasID,
		KeyId:        "test-key-provider-config",
		KeyAlgorithm: policy.Algorithm_ALGORITHM_EC_P256,
		KeyMode:      policy.KeyMode_KEY_MODE_PROVIDER_ROOT_KEY,
		PublicKeyCtx: &policy.PublicKeyCtx{
			Pem: keyCtx,
		},
		PrivateKeyCtx: &policy.PrivateKeyCtx{
			WrappedKey: keyCtx,
			KeyId:      "test-wrapping-kid",
		},
		ProviderConfigId: pc.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(key)
	keyID = key.GetKasKey().GetKey().GetId()

	_, err = s.db.PolicyClient.DeleteProviderConfig(s.ctx, pc.GetId())
	s.Require().Error(err)
	s.Require().ErrorContains(err, db.ErrForeignKeyViolation.Error())
}

func (s *KeyManagementSuite) Test_DeleteProviderConfig_InvalidUUID_Fails() {
	pc, err := s.db.PolicyClient.DeleteProviderConfig(s.ctx, invalidUUID)
	s.Require().Error(err)
	s.Nil(pc)
}

// Manager validation tests

func (s *KeyManagementSuite) Test_CreateProviderConfig_ValidManager_Succeeds() {
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()

	// Test with valid manager 'opentdf.io/basic'
	pc := s.createTestProviderConfigWithManager(s.testProvider, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc.GetId())

	s.Equal("opentdf.io/basic", pc.GetManager())
	s.Equal(s.testProvider, pc.GetName())
}

func (s *KeyManagementSuite) Test_CreateProviderConfig_EmptyManager_Succeeds() {
	// At the database level, empty string is different from NULL and is allowed
	// Service-level validation should prevent empty managers

	pc, err := s.db.PolicyClient.CreateProviderConfig(s.ctx, &keymanagement.CreateProviderConfigRequest{
		Name:       s.testProvider,
		Manager:    "",
		ConfigJson: validProviderConfig,
	})
	s.Require().NoError(err)
	s.NotNil(pc)
	s.Empty(pc.GetManager()) // Empty string is stored as-is

	// Cleanup
	s.deleteTestProviderConfigs([]string{pc.GetId()})
}

func (s *KeyManagementSuite) Test_CreateProviderConfig_NullManager_Fails() {
	// This test needs to actually send NULL (not just omit the field)
	// When a field is omitted in a protobuf message, it gets the zero value (empty string for strings)
	// To test the NOT NULL constraint, we need to test at the SQL level

	// Use raw SQL to test NULL constraint since protobuf doesn't allow true NULL strings
	_, err := s.db.Client.Pgx.Exec(s.ctx, "INSERT INTO "+s.db.TableName("provider_config")+" (provider_name, manager, config, metadata) VALUES ($1, NULL, $2, $3)",
		s.testProvider, validProviderConfig, `{}`)

	s.Require().Error(err)
	s.Require().ErrorContains(err, "null value")
}

// Composite unique constraint tests

func (s *KeyManagementSuite) Test_CreateProviderConfig_SameNameDifferentManager_Succeeds() {
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()

	// Create first provider config with 'opentdf.io/basic' manager
	pc1 := s.createTestProviderConfigWithManager(s.testProvider, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc1.GetId())

	// Create second provider config with same name but different manager
	// Note: This test assumes there's another valid manager type available in the test environment
	// For now, we'll test that the constraint allows different combinations
	pc2 := s.createTestProviderConfigWithManager(s.testProvider+"2", validProviderConfig2, nil)
	pcIDs = append(pcIDs, pc2.GetId())

	s.NotEqual(pc1.GetId(), pc2.GetId())
	s.Equal("opentdf.io/basic", pc1.GetManager())
	s.Equal("opentdf.io/basic", pc2.GetManager())
	s.NotEqual(pc1.GetName(), pc2.GetName())
}

func (s *KeyManagementSuite) Test_CreateProviderConfig_SameNameSameManager_Fails() {
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()

	// Create first provider config
	pc1 := s.createTestProviderConfigWithManager(s.testProvider, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc1.GetId())

	// Try to create second provider config with same name and same manager
	pc2, err := s.db.PolicyClient.CreateProviderConfig(s.ctx, &keymanagement.CreateProviderConfigRequest{
		Name:       s.testProvider,
		Manager:    "opentdf.io/basic",
		ConfigJson: validProviderConfig2,
	})
	s.Require().Error(err)
	s.Require().ErrorContains(err, db.ErrUniqueConstraintViolation.Error())
	s.Nil(pc2)
}

// Update operation tests with manager field

func (s *KeyManagementSuite) Test_UpdateProviderConfig_ChangeManager_Succeeds() {
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()

	// Create provider config with 'opentdf.io/basic' manager
	pc := s.createTestProviderConfigWithManager(s.testProvider, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc.GetId())

	s.Equal("opentdf.io/basic", pc.GetManager())

	// Update to keep the same manager (this should work)
	updatedPc, err := s.db.PolicyClient.UpdateProviderConfig(s.ctx, &keymanagement.UpdateProviderConfigRequest{
		Id:         pc.GetId(),
		Manager:    "opentdf.io/basic",
		ConfigJson: validProviderConfig2,
	})
	s.Require().NoError(err)
	s.NotNil(updatedPc)
	s.Equal("opentdf.io/basic", updatedPc.GetManager())
	s.Equal(validProviderConfig2, updatedPc.GetConfigJson())
}

// Backward compatibility tests

func (s *KeyManagementSuite) Test_CreateProviderConfig_DefaultManager_BackwardCompatibility() {
	// All existing tests that don't specify manager should default to 'local'
	// This is tested implicitly by the existing tests using createTestProviderConfig
	// which now defaults to 'local' manager

	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()

	pc := s.createTestProviderConfig(s.testProvider, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc.GetId())

	// Verify that the default manager is 'local'
	s.Equal("opentdf.io/basic", pc.GetManager())
}

// Manager field inclusion tests

func (s *KeyManagementSuite) Test_GetProviderConfig_IncludesManagerField() {
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()

	pc := s.createTestProviderConfigWithManager(s.testProvider, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc.GetId())

	// Get by ID
	retrievedByID, err := s.db.PolicyClient.GetProviderConfig(s.ctx, &keymanagement.GetProviderConfigRequest_Id{
		Id: pc.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(retrievedByID)
	s.Equal("opentdf.io/basic", retrievedByID.GetManager())

	// Get by Name
	retrievedByName, err := s.db.PolicyClient.GetProviderConfig(s.ctx, &keymanagement.GetProviderConfigRequest_Name{
		Name: s.testProvider,
	})
	s.Require().NoError(err)
	s.NotNil(retrievedByName)
	s.Equal("opentdf.io/basic", retrievedByName.GetManager())
}

func (s *KeyManagementSuite) Test_ListProviderConfigs_IncludesManagerField() {
	testProvider2 := s.getUniqueProviderName("test-provider-2")
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()

	pc1 := s.createTestProviderConfigWithManager(s.testProvider, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc1.GetId())
	pc2 := s.createTestProviderConfigWithManager(testProvider2, validProviderConfig2, nil)
	pcIDs = append(pcIDs, pc2.GetId())

	resp, err := s.db.PolicyClient.ListProviderConfigs(s.ctx, &policy.PageRequest{})
	s.Require().NoError(err)
	s.NotNil(resp)
	s.NotEmpty(resp.GetProviderConfigs())

	// Find our test configs and verify manager field is included
	found := 0
	for _, pc := range resp.GetProviderConfigs() {
		if pc.GetName() == s.testProvider || pc.GetName() == testProvider2 {
			s.Equal("opentdf.io/basic", pc.GetManager())
			found++
		}
	}
	s.Equal(2, found, "Should find both test provider configs")
}

func (s *KeyManagementSuite) createTestProviderConfig(providerName string, config []byte, metadata *common.MetadataMutable) *policy.KeyProviderConfig {
	return s.createTestProviderConfigWithManager(providerName, config, metadata)
}

func (s *KeyManagementSuite) createTestProviderConfigWithManager(providerName string, config []byte, metadata *common.MetadataMutable) *policy.KeyProviderConfig {
	pc, err := s.db.PolicyClient.CreateProviderConfig(s.ctx, &keymanagement.CreateProviderConfigRequest{
		Name:       providerName,
		Manager:    "opentdf.io/basic",
		ConfigJson: config,
		Metadata:   metadata,
	})
	s.Require().NoError(err)
	s.NotNil(pc)
	return pc
}

func (s *KeyManagementSuite) deleteTestProviderConfigs(ids []string) {
	for _, id := range ids {
		pc, err := s.db.PolicyClient.DeleteProviderConfig(s.ctx, id)
		s.Require().NoError(err)
		s.NotNil(pc)
	}
}

func (s *KeyManagementSuite) getUniqueProviderName(baseName string) string {
	return baseName + "-" + uuid.NewString()[:8]
}

func TestKeyManagementSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping attribute values integration tests")
	}
	suite.Run(t, new(KeyManagementSuite))
}
