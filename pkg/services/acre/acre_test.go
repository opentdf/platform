package acre

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/opentdf/opentdf-v2-poc/gen/acre"
	"github.com/opentdf/opentdf-v2-poc/gen/attributes"
	"github.com/opentdf/opentdf-v2-poc/gen/common"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/pkg/services"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

type AcreSuite struct {
	suite.Suite
	mock       pgxmock.PgxPoolIface
	acreServer *ResourceEncoding
}

func (suite *AcreSuite) SetupSuite() {
	mock, err := pgxmock.NewPool()
	if err != nil {
		slog.Error("could not create pgxpool mock", slog.String("error", err.Error()))
	}
	suite.mock = mock

	suite.acreServer = &ResourceEncoding{
		dbClient: &db.Client{
			PgxIface: mock,
		},
	}
}

func TestAcreSuite(t *testing.T) {
	suite.Run(t, new(AcreSuite))
}

var (
	//nolint:gochecknoglobals // Test data and should be reintialized for each test
	resourceMapping = &acre.CreateResourceMappingRequest{
		Mapping: &acre.ResourceMapping{
			Descriptor_: &common.ResourceDescriptor{
				Name:      "test",
				Namespace: "opentdf",
				Version:   1,
				Fqn:       "http://opentdf.com/attr/test",
				Labels:    map[string]string{"test": "test"},
				Type:      common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING,
				Id:        1,
			},
			AttributeValueRef: &attributes.AttributeValueReference{},
			SynonymRef:        &acre.SynonymRef{},
		},
	}

	//nolint:gochecknoglobals // Test data and should be reintialized for each test
	resourceSynonym = &acre.CreateResourceSynonymRequest{
		Synonym: &acre.Synonyms{
			Descriptor_: &common.ResourceDescriptor{
				Name:      "test",
				Namespace: "opentdf",
				Version:   1,
				Fqn:       "http://opentdf.com/attr/test",
				Labels:    map[string]string{"test": "test"},
				Type:      common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM,
				Id:        1,
			},
			Terms: []string{"test"},
		},
	}

	//nolint:gochecknoglobals // Test data and should be reintialized for each test
	resourceGroup = &acre.CreateResourceGroupRequest{
		Group: &acre.ResourceGroup{
			Descriptor_: &common.ResourceDescriptor{
				Name:      "test",
				Namespace: "opentdf",
				Version:   1,
				Fqn:       "http://opentdf.com/attr/test",
				Labels:    map[string]string{"test": "test"},
				Type:      common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP,
				Id:        1,
			},
		},
	}
)

func (suite *AcreSuite) Test_CreateResourceMapping_Returns_InternalError_When_Database_Error() {
	// Copy global
	lResourceMapping := resourceMapping

	bMapping, err := protojson.Marshal(lResourceMapping.Mapping)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(lResourceMapping.Mapping.Descriptor_.Name,
			lResourceMapping.Mapping.Descriptor_.Namespace,
			lResourceMapping.Mapping.Descriptor_.Version,
			lResourceMapping.Mapping.Descriptor_.Fqn,
			lResourceMapping.Mapping.Descriptor_.Labels,
			lResourceMapping.Mapping.Descriptor_.Description,
			common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
			bMapping,
		).
		WillReturnError(errors.New("error inserting resource mapping"))

	_, err = suite.acreServer.CreateResourceMapping(context.Background(), lResourceMapping)
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrCreatingResource)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_CreateResourceMapping_Returns_OK_When_Successful() {
	// Copy global
	lResourceMapping := resourceMapping

	bMapping, err := protojson.Marshal(lResourceMapping.Mapping)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(lResourceMapping.Mapping.Descriptor_.Name,
			lResourceMapping.Mapping.Descriptor_.Namespace,
			lResourceMapping.Mapping.Descriptor_.Version,
			lResourceMapping.Mapping.Descriptor_.Fqn,
			lResourceMapping.Mapping.Descriptor_.Labels,
			lResourceMapping.Mapping.Descriptor_.Description,
			common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
			bMapping,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	_, err = suite.acreServer.CreateResourceMapping(context.Background(), lResourceMapping)

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_ListResourceMappings_Returns_InternalError_When_Database_Error() {
	selector := &common.ResourceSelector{
		Namespace: "opentdf",
		Version:   1,
	}

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
			selector.Namespace, int32(1)).
		WillReturnError(errors.New("error listing resource mappings"))

	_, err := suite.acreServer.ListResourceMappings(context.Background(), &acre.ListResourceMappingsRequest{
		Selector: selector,
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrListingResource)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_ListResourceMappings_Returns_OK_When_Successful() {
	// Copy Global
	lResourceMapping := resourceMapping

	bMapping, err := protojson.Marshal(lResourceMapping.Mapping)

	assert.NoError(suite.T(), err)

	selector := &common.ResourceSelector{
		Namespace: "opentdf",
		Version:   1,
	}

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
			selector.Namespace, int32(1)).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).
			AddRow(int32(1), bMapping))

	mappings, err := suite.acreServer.ListResourceMappings(context.Background(), &acre.ListResourceMappingsRequest{
		Selector: selector,
	})

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), []*acre.ResourceMapping{lResourceMapping.Mapping}, mappings.Mappings)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_GetResourceMapping_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String()).
		WillReturnError(errors.New("error getting resource mapping"))

	_, err := suite.acreServer.GetResourceMapping(context.Background(), &acre.GetResourceMappingRequest{
		Id: int32(1),
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrGettingResource)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_GetResourceMapping_Returns_NotFound_When_Resource_Not_Found() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String()).
		WillReturnError(pgx.ErrNoRows)

	_, err := suite.acreServer.GetResourceMapping(context.Background(), &acre.GetResourceMappingRequest{
		Id: int32(1),
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.NotFound, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrNotFound)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_GetResourceMapping_Returns_OK_When_Successful() {
	// Copy Global
	lResourceMapping := resourceMapping

	bMapping, err := protojson.Marshal(lResourceMapping.Mapping)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).
			AddRow(int32(1), bMapping))

	_, err = suite.acreServer.GetResourceMapping(context.Background(), &acre.GetResourceMappingRequest{
		Id: int32(1),
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_UpdateResourceMapping_Returns_InternalError_When_Database_Error() {
	// Copy Global
	lResourceMapping := resourceMapping

	bMapping, err := protojson.Marshal(lResourceMapping.Mapping)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(lResourceMapping.Mapping.Descriptor_.Name,
			lResourceMapping.Mapping.Descriptor_.Namespace,
			lResourceMapping.Mapping.Descriptor_.Version,
			lResourceMapping.Mapping.Descriptor_.Description,
			lResourceMapping.Mapping.Descriptor_.Fqn,
			lResourceMapping.Mapping.Descriptor_.Labels,
			common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
			bMapping,
			int32(1),
		).
		WillReturnError(errors.New("error updating resource mapping"))

	_, err = suite.acreServer.UpdateResourceMapping(context.Background(), &acre.UpdateResourceMappingRequest{
		Id:      int32(1),
		Mapping: lResourceMapping.Mapping,
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrUpdatingResource)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_UpdateResourceMapping_Returns_OK_When_Successful() {
	// Copy Global
	lResourceMapping := resourceMapping

	bMapping, err := protojson.Marshal(lResourceMapping.Mapping)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(lResourceMapping.Mapping.Descriptor_.Name,
			lResourceMapping.Mapping.Descriptor_.Namespace,
			lResourceMapping.Mapping.Descriptor_.Version,
			lResourceMapping.Mapping.Descriptor_.Description,
			lResourceMapping.Mapping.Descriptor_.Fqn,
			lResourceMapping.Mapping.Descriptor_.Labels,
			common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
			bMapping,
			int32(1),
		).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	_, err = suite.acreServer.UpdateResourceMapping(context.Background(), &acre.UpdateResourceMappingRequest{
		Id:      int32(1),
		Mapping: lResourceMapping.Mapping,
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_DeleteResourceMapping_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String()).
		WillReturnError(errors.New("error deleting resource mapping"))

	_, err := suite.acreServer.DeleteResourceMapping(context.Background(), &acre.DeleteResourceMappingRequest{
		Id: int32(1),
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrDeletingResource)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_DeleteResourceMapping_Returns_OK_When_Successful() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String()).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	_, err := suite.acreServer.DeleteResourceMapping(context.Background(), &acre.DeleteResourceMappingRequest{
		Id: int32(1),
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_CreateResourceSynonym_Returns_InternalError_When_Database_Error() {
	// Copy global
	lResourceSynonym := resourceSynonym

	bSynonym, err := protojson.Marshal(lResourceSynonym.Synonym)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(lResourceSynonym.Synonym.Descriptor_.Name,
			lResourceSynonym.Synonym.Descriptor_.Namespace,
			lResourceSynonym.Synonym.Descriptor_.Version,
			lResourceSynonym.Synonym.Descriptor_.Fqn,
			lResourceSynonym.Synonym.Descriptor_.Labels,
			lResourceSynonym.Synonym.Descriptor_.Description,
			common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
			bSynonym,
		).
		WillReturnError(errors.New("error inserting resource synonym"))

	_, err = suite.acreServer.CreateResourceSynonym(context.Background(), lResourceSynonym)
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrCreatingResource)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_CreateResourceSynonym_Returns_OK_When_Successful() {
	// Copy global
	lResourceSynonym := resourceSynonym

	bSynonym, err := protojson.Marshal(lResourceSynonym.Synonym)

	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(lResourceSynonym.Synonym.Descriptor_.Name,
			lResourceSynonym.Synonym.Descriptor_.Namespace,
			lResourceSynonym.Synonym.Descriptor_.Version,
			lResourceSynonym.Synonym.Descriptor_.Fqn,
			lResourceSynonym.Synonym.Descriptor_.Labels,
			lResourceSynonym.Synonym.Descriptor_.Description,
			common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
			bSynonym,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	_, err = suite.acreServer.CreateResourceSynonym(context.Background(), lResourceSynonym)

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_ListResourceSynonyms_Returns_InternalError_When_Database_Error() {
	selector := &common.ResourceSelector{
		Namespace: "opentdf",
		Version:   1,
	}

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
			selector.Namespace, int32(1)).
		WillReturnError(errors.New("error listing resource synonyms"))

	_, err := suite.acreServer.ListResourceSynonyms(context.Background(), &acre.ListResourceSynonymsRequest{
		Selector: selector,
	})

	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrListingResource)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_ListResourceSynonyms_Returns_OK_When_Successful() {
	// Copy Global
	lResourceSynonym := resourceSynonym

	bSynonym, err := protojson.Marshal(lResourceSynonym.Synonym)

	assert.NoError(suite.T(), err)

	selector := &common.ResourceSelector{
		Namespace: "opentdf",
		Version:   1,
	}

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
			selector.Namespace, int32(1)).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).
			AddRow(int32(1), bSynonym))

	synonyms, err := suite.acreServer.ListResourceSynonyms(context.Background(), &acre.ListResourceSynonymsRequest{
		Selector: selector,
	})

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), []*acre.Synonyms{lResourceSynonym.Synonym}, synonyms.Synonyms)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_GetResourceSynonym_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String()).
		WillReturnError(errors.New("error getting resource synonym"))

	_, err := suite.acreServer.GetResourceSynonym(context.Background(), &acre.GetResourceSynonymRequest{
		Id: int32(1),
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())
		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrGettingResource)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_GetResourceSynonym_Returns_NotFound_When_Resource_Not_Found() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String()).
		WillReturnError(pgx.ErrNoRows)

	_, err := suite.acreServer.GetResourceSynonym(context.Background(), &acre.GetResourceSynonymRequest{
		Id: int32(1),
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.NotFound, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrNotFound)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_GetResourceSynonym_Returns_OK_When_Successful() {
	// Copy global
	lResourceSynonym := resourceSynonym

	bSynonym, err := protojson.Marshal(lResourceSynonym.Synonym)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).
			AddRow(int32(1), bSynonym))

	_, err = suite.acreServer.GetResourceSynonym(context.Background(), &acre.GetResourceSynonymRequest{
		Id: int32(1),
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_UpdateResourceSynonym_Returns_InternalError_When_Database_Error() {
	// Copy Global
	lResourceSynonym := resourceSynonym

	bSynonym, err := protojson.Marshal(lResourceSynonym.Synonym)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(lResourceSynonym.Synonym.Descriptor_.Name,
			lResourceSynonym.Synonym.Descriptor_.Namespace,
			lResourceSynonym.Synonym.Descriptor_.Version,
			lResourceSynonym.Synonym.Descriptor_.Description,
			lResourceSynonym.Synonym.Descriptor_.Fqn,
			lResourceSynonym.Synonym.Descriptor_.Labels,
			common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
			bSynonym,
			int32(1),
		).
		WillReturnError(errors.New("error updating resource synonym"))

	_, err = suite.acreServer.UpdateResourceSynonym(context.Background(), &acre.UpdateResourceSynonymRequest{
		Id:      int32(1),
		Synonym: lResourceSynonym.Synonym,
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())
		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrUpdatingResource)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_UpdateResourceSynonym_Returns_OK_When_Successful() {
	// Copy Global
	lResourceSynonym := resourceSynonym

	bSynonym, err := protojson.Marshal(lResourceSynonym.Synonym)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(lResourceSynonym.Synonym.Descriptor_.Name,
			lResourceSynonym.Synonym.Descriptor_.Namespace,
			lResourceSynonym.Synonym.Descriptor_.Version,
			lResourceSynonym.Synonym.Descriptor_.Description,
			lResourceSynonym.Synonym.Descriptor_.Fqn,
			lResourceSynonym.Synonym.Descriptor_.Labels,
			common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
			bSynonym,
			int32(1),
		).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	_, err = suite.acreServer.UpdateResourceSynonym(context.Background(), &acre.UpdateResourceSynonymRequest{
		Id:      int32(1),
		Synonym: lResourceSynonym.Synonym,
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_DeleteResourceSynonym_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String()).
		WillReturnError(errors.New("error deleting resource synonym"))

	_, err := suite.acreServer.DeleteResourceSynonym(context.Background(), &acre.DeleteResourceSynonymRequest{
		Id: int32(1),
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())
		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrDeletingResource)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_DeleteResourceSynonym_Returns_OK_When_Successful() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String()).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	_, err := suite.acreServer.DeleteResourceSynonym(context.Background(), &acre.DeleteResourceSynonymRequest{
		Id: int32(1),
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_CreateResourceGroup_Returns_InternalError_When_Database_Error() {
	// Copy Global
	lResourceGroup := resourceGroup

	bGroup, err := protojson.Marshal(lResourceGroup.Group)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(lResourceGroup.Group.Descriptor_.Name,
			lResourceGroup.Group.Descriptor_.Namespace,
			lResourceGroup.Group.Descriptor_.Version,
			lResourceGroup.Group.Descriptor_.Fqn,
			lResourceGroup.Group.Descriptor_.Labels,
			lResourceGroup.Group.Descriptor_.Description,
			common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
			bGroup,
		).
		WillReturnError(errors.New("error inserting resource group"))

	_, err = suite.acreServer.CreateResourceGroup(context.Background(), lResourceGroup)
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())
		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrCreatingResource)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_CreateResourceGroup_Returns_OK_When_Successful() {
	// Copy Global
	lResourceGroup := resourceGroup

	bGroup, err := protojson.Marshal(lResourceGroup.Group)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(lResourceGroup.Group.Descriptor_.Name,
			lResourceGroup.Group.Descriptor_.Namespace,
			lResourceGroup.Group.Descriptor_.Version,
			lResourceGroup.Group.Descriptor_.Fqn,
			lResourceGroup.Group.Descriptor_.Labels,
			lResourceGroup.Group.Descriptor_.Description,
			common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
			bGroup,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	_, err = suite.acreServer.CreateResourceGroup(context.Background(), lResourceGroup)

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_ListResourceGroups_Returns_InternalError_When_Database_Error() {
	selector := &common.ResourceSelector{
		Namespace: "opentdf",
		Version:   1,
	}

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
			selector.Namespace, int32(1)).
		WillReturnError(errors.New("error listing resource groups"))

	_, err := suite.acreServer.ListResourceGroups(context.Background(), &acre.ListResourceGroupsRequest{
		Selector: selector,
	})

	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrListingResource)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_ListResourceGroups_Returns_OK_When_Successful() {
	// Copy Global
	lResourceGroup := resourceGroup

	bResourceGroup, err := protojson.Marshal(lResourceGroup.Group)

	assert.NoError(suite.T(), err)

	selector := &common.ResourceSelector{
		Namespace: "opentdf",
		Version:   1,
	}

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
			selector.Namespace, int32(1)).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).
			AddRow(int32(1), bResourceGroup))

	groups, err := suite.acreServer.ListResourceGroups(context.Background(), &acre.ListResourceGroupsRequest{
		Selector: selector,
	})

	assert.NoError(suite.T(), err)

	assert.Equal(suite.T(), []*acre.ResourceGroup{lResourceGroup.Group}, groups.Groups)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_GetResourceGroup_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String()).
		WillReturnError(errors.New("error getting resource group"))

	_, err := suite.acreServer.GetResourceGroup(context.Background(), &acre.GetResourceGroupRequest{
		Id: int32(1),
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrGettingResource)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_GetResourceGroup_Returns_NotFound_When_Resource_Not_Found() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String()).
		WillReturnError(pgx.ErrNoRows)

	_, err := suite.acreServer.GetResourceGroup(context.Background(), &acre.GetResourceGroupRequest{
		Id: int32(1),
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.NotFound, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrNotFound)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_GetResourceGroup_Returns_OK_When_Successful() {
	// Copy Global
	lResourceGroup := resourceGroup

	bGroup, err := protojson.Marshal(lResourceGroup.Group)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).
			AddRow(int32(1), bGroup))

	_, err = suite.acreServer.GetResourceGroup(context.Background(), &acre.GetResourceGroupRequest{
		Id: int32(1),
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_UpdateResourceGroup_Returns_InternalError_When_Database_Error() {
	// Copy Global
	lResourceGroup := resourceGroup

	bGroup, err := protojson.Marshal(lResourceGroup.Group)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(lResourceGroup.Group.Descriptor_.Name,
			lResourceGroup.Group.Descriptor_.Namespace,
			lResourceGroup.Group.Descriptor_.Version,
			lResourceGroup.Group.Descriptor_.Description,
			lResourceGroup.Group.Descriptor_.Fqn,
			lResourceGroup.Group.Descriptor_.Labels,
			common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
			bGroup,
			int32(1),
		).
		WillReturnError(errors.New("error updating resource group"))

	_, err = suite.acreServer.UpdateResourceGroup(context.Background(), &acre.UpdateResourceGroupRequest{
		Id:    int32(1),
		Group: lResourceGroup.Group,
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrUpdatingResource)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_UpdateResourceGroup_Returns_OK_When_Successful() {
	// Copy Global
	lResourceGroup := resourceGroup

	bGroup, err := protojson.Marshal(lResourceGroup.Group)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(lResourceGroup.Group.Descriptor_.Name,
			lResourceGroup.Group.Descriptor_.Namespace,
			lResourceGroup.Group.Descriptor_.Version,
			lResourceGroup.Group.Descriptor_.Description,
			lResourceGroup.Group.Descriptor_.Fqn,
			lResourceGroup.Group.Descriptor_.Labels,
			common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
			bGroup,
			int32(1),
		).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	_, err = suite.acreServer.UpdateResourceGroup(context.Background(), &acre.UpdateResourceGroupRequest{
		Id:    int32(1),
		Group: lResourceGroup.Group,
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_DeleteResourceGroup_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String()).
		WillReturnError(errors.New("error deleting resource group"))

	_, err := suite.acreServer.DeleteResourceGroup(context.Background(), &acre.DeleteResourceGroupRequest{
		Id: int32(1),
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)
		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())
		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrDeletingResource)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_DeleteResourceGroup_Returns_OK_When_Successful() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), common.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String()).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	_, err := suite.acreServer.DeleteResourceGroup(context.Background(), &acre.DeleteResourceGroupRequest{
		Id: int32(1),
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}
