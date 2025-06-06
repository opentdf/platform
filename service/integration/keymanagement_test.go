package integration

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/keymanagement"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/suite"
)

var (
	testProvider          = "test-PROVIDER"
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

func (s *KeyManagementSuite) Test_CreateProviderConfig_NoMetada_Succeeds() {
	pcIDs := make([]string, 0)
	s.deleteTestProviderConfigs(append(pcIDs, s.createTestProviderConfig(testProvider, validProviderConfig, nil).GetId()))
}

func (s *KeyManagementSuite) Test_CreateProviderConfig_Metadata_Succeeds() {
	pcIDs := make([]string, 0)
	s.deleteTestProviderConfigs(append(pcIDs, s.createTestProviderConfig(testProvider, validProviderConfig, &common.MetadataMutable{
		Labels: validLabels,
	}).GetId()))
}

func (s *KeyManagementSuite) Test_CreateProviderConfig_EmptyConfig_Fails() {
	pc, err := s.db.PolicyClient.CreateProviderConfig(s.ctx, &keymanagement.CreateProviderConfigRequest{
		Name: testProvider,
	})
	s.Require().Error(err)
	s.Require().ErrorContains(err, db.ErrNotNullViolation.Error())
	s.Nil(pc)
}

func (s *KeyManagementSuite) Test_CreateProviderConfig_InvalidConfig_Fails() {
	pc, err := s.db.PolicyClient.CreateProviderConfig(s.ctx, &keymanagement.CreateProviderConfigRequest{
		Name:       testProvider,
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
	pc := s.createTestProviderConfig(testProvider, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc.GetId())

	pc, err := s.db.PolicyClient.CreateProviderConfig(s.ctx, &keymanagement.CreateProviderConfigRequest{
		Name:       pc.GetName(),
		ConfigJson: validProviderConfig,
	})
	s.Require().Error(err)
	s.Require().ErrorContains(err, db.ErrUniqueConstraintViolation.Error())
	s.Nil(pc)
}

func (s *KeyManagementSuite) Test_GetProviderConfig_WithId_Succeeds() {
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()
	pc := s.createTestProviderConfig(testProvider, validProviderConfig, nil)
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
	pc := s.createTestProviderConfig(testProvider, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc.GetId())

	pc, err := s.db.PolicyClient.GetProviderConfig(s.ctx, &keymanagement.GetProviderConfigRequest_Name{
		Name: pc.GetName(),
	})
	s.Require().NoError(err)
	s.NotNil(pc)
	s.Equal(strings.ToLower(testProvider), pc.GetName())
	s.Equal(validProviderConfig, pc.GetConfigJson())
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
	pc := s.createTestProviderConfig(testProvider, validProviderConfig, nil)
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
	pc := s.createTestProviderConfig(testProvider, validProviderConfig, nil)
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
	pc := s.createTestProviderConfig(testProvider, validProviderConfig, &common.MetadataMutable{
		Labels: validLabels,
	})
	pcIDs = append(pcIDs, pc.GetId())
	s.NotNil(pc)
	s.Equal(strings.ToLower(testProvider), pc.GetName())
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
	s.Equal(strings.ToLower(testProvider2), pc.GetName())
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
	pc := s.createTestProviderConfig(testProvider, validProviderConfig, &common.MetadataMutable{
		Labels: validLabels,
	})
	pcIDs = append(pcIDs, pc.GetId())
	s.NotNil(pc)
	s.Equal(strings.ToLower(testProvider), pc.GetName())
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

func (s *KeyManagementSuite) Test_UpdateProviderConfig_UpdatesConfigJson_Succeeds() {
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()
	pc := s.createTestProviderConfig(testProvider, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc.GetId())
	s.NotNil(pc)
	s.Equal(strings.ToLower(testProvider), pc.GetName())
	s.Equal(validProviderConfig, pc.GetConfigJson())

	pc, err := s.db.PolicyClient.UpdateProviderConfig(s.ctx, &keymanagement.UpdateProviderConfigRequest{
		Id:         pc.GetId(),
		ConfigJson: validProviderConfig2,
	})
	s.Require().NoError(err)
	s.NotNil(pc)
	s.Equal(strings.ToLower(testProvider), pc.GetName())
	s.Equal(validProviderConfig2, pc.GetConfigJson())
}

func (s *KeyManagementSuite) Test_UpdateProviderConfig_UpdatesConfigName_Succeeds() {
	pcIDs := make([]string, 0)
	defer func() {
		s.deleteTestProviderConfigs(pcIDs)
	}()
	pc := s.createTestProviderConfig(testProvider, validProviderConfig, nil)
	pcIDs = append(pcIDs, pc.GetId())
	s.NotNil(pc)
	s.Equal(strings.ToLower(testProvider), pc.GetName())
	s.Equal(validProviderConfig, pc.GetConfigJson())

	pc, err := s.db.PolicyClient.UpdateProviderConfig(s.ctx, &keymanagement.UpdateProviderConfigRequest{
		Id:   pc.GetId(),
		Name: testProvider2,
	})
	s.Require().NoError(err)
	s.NotNil(pc)
	s.Equal(strings.ToLower(testProvider2), pc.GetName())
	s.Equal(validProviderConfig, pc.GetConfigJson())
}

func (s *KeyManagementSuite) Test_DeleteProviderConfig_Succeeds() {
	pc := s.createTestProviderConfig(testProvider, validProviderConfig, nil)
	s.NotNil(pc)
	pc, err := s.db.PolicyClient.DeleteProviderConfig(s.ctx, pc.GetId())
	s.Require().NoError(err)
	s.NotNil(pc)
}

func (s *KeyManagementSuite) Test_DeleteProviderConfig_InvalidUUID_Fails() {
	pc, err := s.db.PolicyClient.DeleteProviderConfig(s.ctx, invalidUUID)
	s.Require().Error(err)
	s.Nil(pc)
}

func (s *KeyManagementSuite) createTestProviderConfig(providerName string, config []byte, metadata *common.MetadataMutable) *policy.KeyProviderConfig {
	pc, err := s.db.PolicyClient.CreateProviderConfig(s.ctx, &keymanagement.CreateProviderConfigRequest{
		Name:       providerName,
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

func TestKeyManagementSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping attribute values integration tests")
	}
	suite.Run(t, new(KeyManagementSuite))
}
