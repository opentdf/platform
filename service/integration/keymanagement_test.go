package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/keymanagement"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/stretchr/testify/suite"
)

var (
	testProvider          = "test-provider"
	testProvider2         = "test-provider-2"
	validProviderConfig   = []byte(`{"key": "value"}`)
	validProviderConfig2  = []byte(`{"key2": "value2"}`)
	invalidProviderConfig = []byte(`{"key": "value"`)
	invalidUUID           = "invalid-uuid"
	validLabels           = map[string]string{"key": "value"}
	additionalLabels      = map[string]string{"key2": "value2"}
)

type KeyManagementSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context //nolint:containedctx // context is used in the test suite
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

func (s *KeyManagementSuite) TearDownSuite() {
	slog.Info("tearing down db.KeyManagement test suite")
	s.f.TearDown()
}

func (s *KeyManagementSuite) createTestProviderConfig() *policy.KeyProviderConfig {
	pc, err := s.db.PolicyClient.CreateProviderConfig(s.ctx, &keymanagement.CreateProviderConfigRequest{
		Name:       testProvider,
		ConfigJson: validProviderConfig,
	})
	s.Require().NoError(err)
	s.NotNil(pc)
	return pc
}

func (s *KeyManagementSuite) Test_CreateProviderConfig_NoMetada_Succeeds() {
	s.createTestProviderConfig()
}

func (s *KeyManagementSuite) Test_CreateProviderConfig_Metadata_Succeeds() {
	pc, err := s.db.PolicyClient.CreateProviderConfig(s.ctx, &keymanagement.CreateProviderConfigRequest{
		Name:       testProvider,
		ConfigJson: validProviderConfig,
		Metadata: &common.MetadataMutable{
			Labels: validLabels,
		},
	})
	s.Require().NoError(err)
	s.NotNil(pc)
}

func (s *KeyManagementSuite) Test_CreateProviderConfig_EmptyConfig_Fails() {
	pc, err := s.db.PolicyClient.CreateProviderConfig(s.ctx, &keymanagement.CreateProviderConfigRequest{
		Name: testProvider,
	})
	s.Require().Error(err)
	s.Nil(pc)
}

func (s *KeyManagementSuite) Test_CreateProviderConfig_InvalidConfig_Fails() {
	pc, err := s.db.PolicyClient.CreateProviderConfig(s.ctx, &keymanagement.CreateProviderConfigRequest{
		Name:       testProvider,
		ConfigJson: invalidProviderConfig,
	})
	s.Require().Error(err)
	s.Nil(pc)
}

func (s *KeyManagementSuite) Test_GetProviderConfig_WithId_Succeeds() {
	pc, err := s.db.PolicyClient.CreateProviderConfig(s.ctx, &keymanagement.CreateProviderConfigRequest{
		Name:       testProvider,
		ConfigJson: validProviderConfig,
	})
	s.Require().NoError(err)
	s.NotNil(pc)

	pc, err = s.db.PolicyClient.GetProviderConfig(s.ctx, &keymanagement.GetProviderConfigRequest_Id{
		Id: pc.Id,
	})
	s.Require().NoError(err)
	s.NotNil(pc)
}

func (s *KeyManagementSuite) Test_GetProviderConfig_WithName_Succeeds() {
	pc, err := s.db.PolicyClient.CreateProviderConfig(s.ctx, &keymanagement.CreateProviderConfigRequest{
		Name:       testProvider2,
		ConfigJson: validProviderConfig,
	})
	s.Require().NoError(err)
	s.NotNil(pc)

	pc, err = s.db.PolicyClient.GetProviderConfig(s.ctx, &keymanagement.GetProviderConfigRequest_Name{
		Name: testProvider2,
	})
	s.Require().NoError(err)
	s.NotNil(pc)
}

func (s *KeyManagementSuite) Test_GetProviderConfig_InvalidUUID_Fails() {
	pc, err := s.db.PolicyClient.GetProviderConfig(s.ctx, &keymanagement.GetProviderConfigRequest_Id{
		Id: invalidUUID,
	})
	s.Require().Error(err)
	s.Nil(pc)
}

func (s *KeyManagementSuite) Test_GetProviderConfig_InvalidName_Fails() {
	pc, err := s.db.PolicyClient.GetProviderConfig(s.ctx, &keymanagement.GetProviderConfigRequest_Name{
		Name: "",
	})
	s.Require().Error(err)
	s.Nil(pc)
}

func (s *KeyManagementSuite) Test_GetProviderConfig_InvalidIdentifier_Fails() {
	pc, err := s.db.PolicyClient.GetProviderConfig(s.ctx, &map[string]string{})
	s.Require().Error(err)
	s.Nil(pc)
}

// Finish List/Update/Delete tests
func (s *KeyManagementSuite) Test_ListProviderConfig_No_Pagination_Succeeds() {
	s.createTestProviderConfig()

	resp, err := s.db.PolicyClient.ListProviderConfigs(s.ctx, &policy.PageRequest{})
	s.Require().NoError(err)
	s.NotNil(resp)
	s.NotEmpty(resp.ProviderConfigs)
}

func (s *KeyManagementSuite) Test_ListProviderConfig_PaginationLimit_Succeeds() {
	s.createTestProviderConfig()
	s.createTestProviderConfig()

	resp, err := s.db.PolicyClient.ListProviderConfigs(s.ctx, &policy.PageRequest{
		Limit: 1,
	})
	s.Require().NoError(err)
	s.NotNil(resp)
	s.NotEmpty(resp.ProviderConfigs)
	s.Equal(1, len(resp.ProviderConfigs))
	s.GreaterOrEqual(resp.Pagination.Total, int32(1))
}

func (s *KeyManagementSuite) Test_ListProviderConfig_PaginationLimitExceeded_Fails() {
	s.createTestProviderConfig()

	resp, err := s.db.PolicyClient.ListProviderConfigs(s.ctx, &policy.PageRequest{
		Limit: 5001,
	})
	s.Require().Error(err)
	s.Nil(resp)
}

func (s *KeyManagementSuite) Test_UpdateProviderConfig_ExtendsMetadata_Succeeds() {
	pc, err := s.db.PolicyClient.CreateProviderConfig(s.ctx, &keymanagement.CreateProviderConfigRequest{
		Name:       testProvider,
		ConfigJson: validProviderConfig,
		Metadata: &common.MetadataMutable{
			Labels: validLabels,
		},
	})
	s.Require().NoError(err)
	s.NotNil(pc)
	s.Equal(testProvider, pc.Name)
	s.Equal(validProviderConfig, pc.ConfigJson)
	s.Equal(validLabels, pc.Metadata.Labels)

	pc, err = s.db.PolicyClient.UpdateProviderConfig(s.ctx, &keymanagement.UpdateProviderConfigRequest{
		Id:         pc.Id,
		Name:       testProvider2,
		ConfigJson: validProviderConfig2,
		Metadata: &common.MetadataMutable{
			Labels: additionalLabels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	s.Require().NoError(err)
	s.NotNil(pc)
	s.Equal(testProvider2, pc.Name)
	s.Equal(validProviderConfig2, pc.ConfigJson)

	mixedLabels := make(map[string]string, 2)
	for k, v := range validLabels {
		mixedLabels[k] = v
	}
	for k, v := range additionalLabels {
		mixedLabels[k] = v
	}
	s.Equal(mixedLabels, pc.Metadata.Labels)
}

func (s *KeyManagementSuite) Test_UpdateProviderConfig_ReplaceMetadata_Succeeds() {
	pc, err := s.db.PolicyClient.CreateProviderConfig(s.ctx, &keymanagement.CreateProviderConfigRequest{
		Name:       testProvider,
		ConfigJson: validProviderConfig,
		Metadata: &common.MetadataMutable{
			Labels: validLabels,
		},
	})
	s.Require().NoError(err)
	s.NotNil(pc)
	s.Equal(testProvider, pc.Name)
	s.Equal(validProviderConfig, pc.ConfigJson)
	s.Equal(validLabels, pc.Metadata.Labels)

	pc, err = s.db.PolicyClient.UpdateProviderConfig(s.ctx, &keymanagement.UpdateProviderConfigRequest{
		Id:         pc.Id,
		Name:       testProvider2,
		ConfigJson: validProviderConfig2,
		Metadata: &common.MetadataMutable{
			Labels: additionalLabels,
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE,
	})
	s.Require().NoError(err)
	s.NotNil(pc)
	s.Equal(testProvider2, pc.Name)
	s.Equal(validProviderConfig2, pc.ConfigJson)
	s.Equal(additionalLabels, pc.Metadata.Labels)
}

func (s *KeyManagementSuite) Test_UpdateProviderConfig_InvalidUUID_Fails() {
	pc, err := s.db.PolicyClient.UpdateProviderConfig(s.ctx, &keymanagement.UpdateProviderConfigRequest{
		Id:         invalidUUID,
		Name:       testProvider2,
		ConfigJson: validProviderConfig2,
	})
	s.Require().Error(err)
	s.Nil(pc)
}

func (s *KeyManagementSuite) Test_UpdateProviderConfig_ConfigNotFound_Fails() {
	resp, err := s.db.PolicyClient.ListProviderConfigs(s.ctx, &policy.PageRequest{})
	s.Require().NoError(err)
	s.NotNil(resp)

	pcIds := make(map[string]string, 50)
	for _, pc := range resp.ProviderConfigs {
		pcIds[pc.Id] = ""
	}

	isUsedUUID := true
	nonUsedUUID := uuid.NewString()
	for isUsedUUID {
		if _, ok := pcIds[nonUsedUUID]; !ok {
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

func (s *KeyManagementSuite) Test_DeleteProviderConfig_Succeeds() {
	pc := s.createTestProviderConfig()
	s.NotNil(pc)
	pc, err := s.db.PolicyClient.DeleteProviderConfig(s.ctx, pc.Id)
	s.Require().NoError(err)
	s.NotNil(pc)
}

func (s *KeyManagementSuite) Test_DeleteProviderConfig_InvalidUUID_Fails() {
	pc, err := s.db.PolicyClient.DeleteProviderConfig(s.ctx, invalidUUID)
	s.Require().Error(err)
	s.Nil(pc)
}

func TestKeyManagementSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping attribute values integration tests")
	}
	suite.Run(t, new(KeyManagementSuite))
}
