package acre

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5"
	acrev1 "github.com/opentdf/opentdf-v2-poc/gen/acre/v1"
	attributesv1 "github.com/opentdf/opentdf-v2-poc/gen/attributes/v1"
	commonv1 "github.com/opentdf/opentdf-v2-poc/gen/common/v1"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	mapping = &acrev1.CreateResourceMappingRequest{
		Mapping: &acrev1.ResourceMapping{
			Descriptor_: &commonv1.ResourceDescriptor{
				Name:      "test",
				Namespace: "opentdf",
				Version:   1,
				Fqn:       "http://opentdf.com/attr/test",
				Labels:    map[string]string{"test": "test"},
				Type:      commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING,
			},
			AttributeValueRef: &attributesv1.AttributeValueReference{},
			SynonymRef:        &acrev1.SynonymRef{},
		},
	}

	synonym = &acrev1.CreateResourceSynonymRequest{
		Synonym: &acrev1.Synonyms{
			Descriptor_: &commonv1.ResourceDescriptor{
				Name:      "test",
				Namespace: "opentdf",
				Version:   1,
				Fqn:       "http://opentdf.com/attr/test",
				Labels:    map[string]string{"test": "test"},
				Type:      commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM,
			},
			Terms: []string{"test"},
		},
	}

	group = &acrev1.CreateResourceGroupRequest{
		Group: &acrev1.ResourceGroup{
			Descriptor_: &commonv1.ResourceDescriptor{
				Name:      "test",
				Namespace: "opentdf",
				Version:   1,
				Fqn:       "http://opentdf.com/attr/test",
				Labels:    map[string]string{"test": "test"},
				Type:      commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP,
			},
		},
	}
)

func (suite *AcreSuite) Test_CreateResourceMapping_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(mapping.Mapping.Descriptor_.Name,
			mapping.Mapping.Descriptor_.Namespace,
			mapping.Mapping.Descriptor_.Version,
			mapping.Mapping.Descriptor_.Fqn,
			mapping.Mapping.Descriptor_.Labels,
			mapping.Mapping.Descriptor_.Description,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
			mapping.Mapping,
		).
		WillReturnError(errors.New("error inserting resource mapping"))

	_, err := suite.acreServer.CreateResourceMapping(context.Background(), mapping)
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), "error inserting resource mapping")
	}
}

func (suite *AcreSuite) Test_CreateResourceMapping_Returns_OK_When_Successful() {
	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(mapping.Mapping.Descriptor_.Name,
			mapping.Mapping.Descriptor_.Namespace,
			mapping.Mapping.Descriptor_.Version,
			mapping.Mapping.Descriptor_.Fqn,
			mapping.Mapping.Descriptor_.Labels,
			mapping.Mapping.Descriptor_.Description,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
			mapping.Mapping,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	_, err := suite.acreServer.CreateResourceMapping(context.Background(), mapping)

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_ListResourceMappings_Returns_InternalError_When_Database_Error() {
	selector := &commonv1.ResourceSelector{
		Namespace: "opentdf",
		Version:   1,
	}

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
			selector.Namespace, int32(1)).
		WillReturnError(errors.New("error listing resource mappings"))

	_, err := suite.acreServer.ListResourceMappings(context.Background(), &acrev1.ListResourceMappingsRequest{
		Selector: selector,
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), "error listing resource mappings")
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_ListResourceMappings_Returns_OK_When_Successful() {
	selector := &commonv1.ResourceSelector{
		Namespace: "opentdf",
		Version:   1,
	}

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
			selector.Namespace, int32(1)).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).
			AddRow(int32(1), mapping.Mapping))

	mappings, err := suite.acreServer.ListResourceMappings(context.Background(), &acrev1.ListResourceMappingsRequest{
		Selector: selector,
	})

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), []*acrev1.ResourceMapping{mapping.Mapping}, mappings.Mappings)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_GetResourceMapping_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String()).
		WillReturnError(errors.New("error getting resource mapping"))

	_, err := suite.acreServer.GetResourceMapping(context.Background(), &acrev1.GetResourceMappingRequest{
		Id: int32(1),
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), "error getting resource mapping")
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_GetResourceMapping_Returns_NotFound_When_Resource_Not_Found() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String()).
		WillReturnError(pgx.ErrNoRows)

	_, err := suite.acreServer.GetResourceMapping(context.Background(), &acrev1.GetResourceMappingRequest{
		Id: int32(1),
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.NotFound, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), "resource mapping not found")
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_GetResourceMapping_Returns_OK_When_Successful() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).
			AddRow(int32(1), mapping.Mapping))

	_, err := suite.acreServer.GetResourceMapping(context.Background(), &acrev1.GetResourceMappingRequest{
		Id: int32(1),
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_UpdateResourceMapping_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(mapping.Mapping.Descriptor_.Name,
			mapping.Mapping.Descriptor_.Namespace,
			mapping.Mapping.Descriptor_.Version,
			mapping.Mapping.Descriptor_.Description,
			mapping.Mapping.Descriptor_.Fqn,
			mapping.Mapping.Descriptor_.Labels,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
			mapping.Mapping,
			int32(1),
		).
		WillReturnError(errors.New("error updating resource mapping"))

	_, err := suite.acreServer.UpdateResourceMapping(context.Background(), &acrev1.UpdateResourceMappingRequest{
		Id:      int32(1),
		Mapping: mapping.Mapping,
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), "error updating resource mapping")
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_UpdateResourceMapping_Returns_OK_When_Successful() {
	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(mapping.Mapping.Descriptor_.Name,
			mapping.Mapping.Descriptor_.Namespace,
			mapping.Mapping.Descriptor_.Version,
			mapping.Mapping.Descriptor_.Description,
			mapping.Mapping.Descriptor_.Fqn,
			mapping.Mapping.Descriptor_.Labels,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String(),
			mapping.Mapping,
			int32(1),
		).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	_, err := suite.acreServer.UpdateResourceMapping(context.Background(), &acrev1.UpdateResourceMappingRequest{
		Id:      int32(1),
		Mapping: mapping.Mapping,
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_DeleteResourceMapping_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String()).
		WillReturnError(errors.New("error deleting resource mapping"))

	_, err := suite.acreServer.DeleteResourceMapping(context.Background(), &acrev1.DeleteResourceMappingRequest{
		Id: int32(1),
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), "error deleting resource mapping")
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_DeleteResourceMapping_Returns_OK_When_Successful() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_MAPPING.String()).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	_, err := suite.acreServer.DeleteResourceMapping(context.Background(), &acrev1.DeleteResourceMappingRequest{
		Id: int32(1),
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_CreateResourceSynonym_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(synonym.Synonym.Descriptor_.Name,
			synonym.Synonym.Descriptor_.Namespace,
			synonym.Synonym.Descriptor_.Version,
			synonym.Synonym.Descriptor_.Fqn,
			synonym.Synonym.Descriptor_.Labels,
			synonym.Synonym.Descriptor_.Description,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
			synonym.Synonym,
		).
		WillReturnError(errors.New("error inserting resource synonym"))

	_, err := suite.acreServer.CreateResourceSynonym(context.Background(), synonym)
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), "error inserting resource synonym")
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_CreateResourceSynonym_Returns_OK_When_Successful() {
	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(synonym.Synonym.Descriptor_.Name,
			synonym.Synonym.Descriptor_.Namespace,
			synonym.Synonym.Descriptor_.Version,
			synonym.Synonym.Descriptor_.Fqn,
			synonym.Synonym.Descriptor_.Labels,
			synonym.Synonym.Descriptor_.Description,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
			synonym.Synonym,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	_, err := suite.acreServer.CreateResourceSynonym(context.Background(), synonym)

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_ListResourceSynonyms_Returns_InternalError_When_Database_Error() {
	selector := &commonv1.ResourceSelector{
		Namespace: "opentdf",
		Version:   1,
	}

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
			selector.Namespace, int32(1)).
		WillReturnError(errors.New("error listing resource synonyms"))

	_, err := suite.acreServer.ListResourceSynonyms(context.Background(), &acrev1.ListResourceSynonymsRequest{
		Selector: selector,
	})

	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), "error listing resource synonyms")
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_ListResourceSynonyms_Returns_OK_When_Successful() {
	selector := &commonv1.ResourceSelector{
		Namespace: "opentdf",
		Version:   1,
	}

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
			selector.Namespace, int32(1)).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).
			AddRow(int32(1), synonym.Synonym))

	synonyms, err := suite.acreServer.ListResourceSynonyms(context.Background(), &acrev1.ListResourceSynonymsRequest{
		Selector: selector,
	})

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), []*acrev1.Synonyms{synonym.Synonym}, synonyms.Synonyms)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_GetResourceSynonym_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String()).
		WillReturnError(errors.New("error getting resource synonym"))

	_, err := suite.acreServer.GetResourceSynonym(context.Background(), &acrev1.GetResourceSynonymRequest{
		Id: int32(1),
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())
		assert.Contains(suite.T(), grpcStatus.Message(), "error getting resource synonym")
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_GetResourceSynonym_Returns_NotFound_When_Resource_Not_Found() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String()).
		WillReturnError(pgx.ErrNoRows)

	_, err := suite.acreServer.GetResourceSynonym(context.Background(), &acrev1.GetResourceSynonymRequest{
		Id: int32(1),
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.NotFound, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), "resource synonym not found")
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_GetResourceSynonym_Returns_OK_When_Successful() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).
			AddRow(int32(1), synonym.Synonym))

	_, err := suite.acreServer.GetResourceSynonym(context.Background(), &acrev1.GetResourceSynonymRequest{
		Id: int32(1),
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_UpdateResourceSynonym_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(synonym.Synonym.Descriptor_.Name,
			synonym.Synonym.Descriptor_.Namespace,
			synonym.Synonym.Descriptor_.Version,
			synonym.Synonym.Descriptor_.Description,
			synonym.Synonym.Descriptor_.Fqn,
			synonym.Synonym.Descriptor_.Labels,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
			synonym.Synonym,
			int32(1),
		).
		WillReturnError(errors.New("error updating resource synonym"))

	_, err := suite.acreServer.UpdateResourceSynonym(context.Background(), &acrev1.UpdateResourceSynonymRequest{
		Id:      int32(1),
		Synonym: synonym.Synonym,
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())
		assert.Contains(suite.T(), grpcStatus.Message(), "error updating resource synonym")
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_UpdateResourceSynonym_Returns_OK_When_Successful() {
	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(synonym.Synonym.Descriptor_.Name,
			synonym.Synonym.Descriptor_.Namespace,
			synonym.Synonym.Descriptor_.Version,
			synonym.Synonym.Descriptor_.Description,
			synonym.Synonym.Descriptor_.Fqn,
			synonym.Synonym.Descriptor_.Labels,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String(),
			synonym.Synonym,
			int32(1),
		).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	_, err := suite.acreServer.UpdateResourceSynonym(context.Background(), &acrev1.UpdateResourceSynonymRequest{
		Id:      int32(1),
		Synonym: synonym.Synonym,
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_DeleteResourceSynonym_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String()).
		WillReturnError(errors.New("error deleting resource synonym"))

	_, err := suite.acreServer.DeleteResourceSynonym(context.Background(), &acrev1.DeleteResourceSynonymRequest{
		Id: int32(1),
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())
		assert.Contains(suite.T(), grpcStatus.Message(), "error deleting resource synonym")
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_DeleteResourceSynonym_Returns_OK_When_Successful() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_SYNONYM.String()).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	_, err := suite.acreServer.DeleteResourceSynonym(context.Background(), &acrev1.DeleteResourceSynonymRequest{
		Id: int32(1),
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_CreateResourceGroup_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(group.Group.Descriptor_.Name,
			group.Group.Descriptor_.Namespace,
			group.Group.Descriptor_.Version,
			group.Group.Descriptor_.Fqn,
			group.Group.Descriptor_.Labels,
			group.Group.Descriptor_.Description,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
			group.Group,
		).
		WillReturnError(errors.New("error inserting resource group"))

	_, err := suite.acreServer.CreateResourceGroup(context.Background(), group)
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())
		assert.Contains(suite.T(), grpcStatus.Message(), "error inserting resource group")
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_CreateResourceGroup_Returns_OK_When_Successful() {
	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(group.Group.Descriptor_.Name,
			group.Group.Descriptor_.Namespace,
			group.Group.Descriptor_.Version,
			group.Group.Descriptor_.Fqn,
			group.Group.Descriptor_.Labels,
			group.Group.Descriptor_.Description,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
			group.Group,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	_, err := suite.acreServer.CreateResourceGroup(context.Background(), group)

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_ListResourceGroups_Returns_InternalError_When_Database_Error() {
	selector := &commonv1.ResourceSelector{
		Namespace: "opentdf",
		Version:   1,
	}

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
			selector.Namespace, int32(1)).
		WillReturnError(errors.New("error listing resource groups"))

	_, err := suite.acreServer.ListResourceGroups(context.Background(), &acrev1.ListResourceGroupsRequest{
		Selector: selector,
	})

	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), "error listing resource groups")
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_ListResourceGroups_Returns_OK_When_Successful() {
	selector := &commonv1.ResourceSelector{
		Namespace: "opentdf",
		Version:   1,
	}

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
			selector.Namespace, int32(1)).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).
			AddRow(int32(1), group.Group))

	groups, err := suite.acreServer.ListResourceGroups(context.Background(), &acrev1.ListResourceGroupsRequest{
		Selector: selector,
	})

	assert.NoError(suite.T(), err)

	assert.Equal(suite.T(), []*acrev1.ResourceGroup{group.Group}, groups.Groups)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_GetResourceGroup_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String()).
		WillReturnError(errors.New("error getting resource group"))

	_, err := suite.acreServer.GetResourceGroup(context.Background(), &acrev1.GetResourceGroupRequest{
		Id: int32(1),
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), "error getting resource group")
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_GetResourceGroup_Returns_NotFound_When_Resource_Not_Found() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String()).
		WillReturnError(pgx.ErrNoRows)

	_, err := suite.acreServer.GetResourceGroup(context.Background(), &acrev1.GetResourceGroupRequest{
		Id: int32(1),
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.NotFound, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), "resource group not found")
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_GetResourceGroup_Returns_OK_When_Successful() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).
			AddRow(int32(1), group.Group))

	_, err := suite.acreServer.GetResourceGroup(context.Background(), &acrev1.GetResourceGroupRequest{
		Id: int32(1),
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_UpdateResourceGroup_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(group.Group.Descriptor_.Name,
			group.Group.Descriptor_.Namespace,
			group.Group.Descriptor_.Version,
			group.Group.Descriptor_.Description,
			group.Group.Descriptor_.Fqn,
			group.Group.Descriptor_.Labels,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
			group.Group,
			int32(1),
		).
		WillReturnError(errors.New("error updating resource group"))

	_, err := suite.acreServer.UpdateResourceGroup(context.Background(), &acrev1.UpdateResourceGroupRequest{
		Id:    int32(1),
		Group: group.Group,
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), "error updating resource group")
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_UpdateResourceGroup_Returns_OK_When_Successful() {
	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(group.Group.Descriptor_.Name,
			group.Group.Descriptor_.Namespace,
			group.Group.Descriptor_.Version,
			group.Group.Descriptor_.Description,
			group.Group.Descriptor_.Fqn,
			group.Group.Descriptor_.Labels,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String(),
			group.Group,
			int32(1),
		).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	_, err := suite.acreServer.UpdateResourceGroup(context.Background(), &acrev1.UpdateResourceGroupRequest{
		Id:    int32(1),
		Group: group.Group,
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_DeleteResourceGroup_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String()).
		WillReturnError(errors.New("error deleting resource group"))

	_, err := suite.acreServer.DeleteResourceGroup(context.Background(), &acrev1.DeleteResourceGroupRequest{
		Id: int32(1),
	})
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)
		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())
		assert.Contains(suite.T(), grpcStatus.Message(), "error deleting resource group")
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcreSuite) Test_DeleteResourceGroup_Returns_OK_When_Successful() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_RESOURCE_ENCODING_GROUP.String()).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	_, err := suite.acreServer.DeleteResourceGroup(context.Background(), &acrev1.DeleteResourceGroupRequest{
		Id: int32(1),
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}
