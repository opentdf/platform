package acse

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	acsev1 "github.com/opentdf/opentdf-v2-poc/gen/acse/v1"
	attributesv1 "github.com/opentdf/opentdf-v2-poc/gen/attributes/v1"
	commonv1 "github.com/opentdf/opentdf-v2-poc/gen/common/v1"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/pkg/services"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

type AcseSuite struct {
	suite.Suite
	mock      pgxmock.PgxPoolIface
	acseSerer *SubjectEncoding
}

func (suite *AcseSuite) SetupSuite() {
	mock, err := pgxmock.NewPool()
	if err != nil {
		slog.Error("could not create pgxpool mock", slog.String("error", err.Error()))
	}
	suite.mock = mock

	suite.acseSerer = &SubjectEncoding{
		dbClient: &db.Client{
			PgxIface: mock,
		},
	}
}

func TestAcseSuite(t *testing.T) {
	suite.Run(t, new(AcseSuite))
}

//nolint:gochecknoglobals // This is test data and should be reinitialized for each test
var subjectMapping = &acsev1.CreateSubjectMappingRequest{
	SubjectMapping: &acsev1.SubjectMapping{
		Descriptor_: &commonv1.ResourceDescriptor{
			Type:      commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING,
			Version:   1,
			Name:      "architecture-mapping",
			Namespace: "opentdf",
			// Still need to understand purpose of FQN
			Fqn:    "http://opentdf.com/attr/relto",
			Labels: map[string]string{"origin": "Country of Origin"},
			Id:     1,
		},
		SubjectAttribute:  "architect",
		SubjectValues:     []string{"owner", "collaborator", "contributor"},
		Operator:          acsev1.SubjectMapping_OPERATOR_IN,
		AttributeValueRef: &attributesv1.AttributeValueReference{},
	},
}

func (suite *AcseSuite) Test_CreateSubjectMapping_Returns_Internal_Error_When_Database_Error() {
	// Copy Global Test Data to Local
	mapping := subjectMapping

	bMapping, err := protojson.Marshal(mapping.SubjectMapping)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(mapping.SubjectMapping.Descriptor_.Name,
			mapping.SubjectMapping.Descriptor_.Namespace,
			mapping.SubjectMapping.Descriptor_.Version,
			mapping.SubjectMapping.Descriptor_.Fqn,
			mapping.SubjectMapping.Descriptor_.Labels,
			mapping.SubjectMapping.Descriptor_.Description,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String(),
			bMapping,
		).
		WillReturnError(errors.New("error inserting resource"))

	_, err = suite.acseSerer.CreateSubjectMapping(context.Background(), mapping)
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), "error inserting resource")
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcseSuite) Test_CreateSubjectMapping_Returns_OK_When_Successful() {
	// Copy Global Test Data to Local
	mapping := subjectMapping

	bMapping, err := protojson.Marshal(mapping.SubjectMapping)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(mapping.SubjectMapping.Descriptor_.Name,
			mapping.SubjectMapping.Descriptor_.Namespace,
			mapping.SubjectMapping.Descriptor_.Version,
			mapping.SubjectMapping.Descriptor_.Fqn,
			mapping.SubjectMapping.Descriptor_.Labels,
			mapping.SubjectMapping.Descriptor_.Description,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String(),
			bMapping,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	_, err = suite.acseSerer.CreateSubjectMapping(context.Background(), mapping)

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcseSuite) Test_ListSubjectMappings_Returns_Internal_Error_When_Database_Error() {
	selector := &commonv1.ResourceSelector{
		Namespace: "opentdf",
		Version:   1,
	}

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String(), selector.Namespace, int32(1)).
		WillReturnError(errors.New("error listing subject mappings"))

	_, err := suite.acseSerer.ListSubjectMappings(context.Background(), &acsev1.ListSubjectMappingsRequest{
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

func (suite *AcseSuite) Test_ListSubjectMappings_Returns_OK_When_Successful() {
	// Copy Global Test Data to Local
	mapping := subjectMapping

	bMapping, err := protojson.Marshal(mapping.SubjectMapping)

	assert.NoError(suite.T(), err)

	selector := &commonv1.ResourceSelector{
		Namespace: "opentdf",
		Version:   1,
	}

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String(), selector.Namespace, int32(1)).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).AddRow(int32(1), bMapping))

	_, err = suite.acseSerer.ListSubjectMappings(context.Background(), &acsev1.ListSubjectMappingsRequest{
		Selector: selector,
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcseSuite) Test_GetSubjectMapping_Returns_Internal_Error_When_Database_Error() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String()).
		WillReturnError(errors.New("error getting subject mapping"))

	_, err := suite.acseSerer.GetSubjectMapping(context.Background(), &acsev1.GetSubjectMappingRequest{
		Id: 1,
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

func (suite *AcseSuite) Test_GetSubjectMapping_Returns_NotFound_Error_When_No_Mapping_Found() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}))

	_, err := suite.acseSerer.GetSubjectMapping(context.Background(), &acsev1.GetSubjectMappingRequest{
		Id: 1,
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

func (suite *AcseSuite) Test_GetSubjectMapping_Returns_OK_When_Successful() {
	// Copy Global Test Data to Local
	mapping := subjectMapping

	bMapping, err := protojson.Marshal(mapping.SubjectMapping)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).AddRow(int32(1), bMapping))

	_, err = suite.acseSerer.GetSubjectMapping(context.Background(), &acsev1.GetSubjectMappingRequest{
		Id: 1,
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcseSuite) Test_UpdateSubjectMapping_Returns_Internal_Error_When_Database_Error() {
	// Copy Global Test Data to Local
	mapping := subjectMapping

	bMapping, err := protojson.Marshal(mapping.SubjectMapping)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(mapping.SubjectMapping.Descriptor_.Name,
			mapping.SubjectMapping.Descriptor_.Namespace,
			mapping.SubjectMapping.Descriptor_.Version,
			mapping.SubjectMapping.Descriptor_.Description,
			mapping.SubjectMapping.Descriptor_.Fqn,
			mapping.SubjectMapping.Descriptor_.Labels,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String(),
			bMapping,
			int32(1),
		).
		WillReturnError(errors.New("error updating subject mapping"))

	_, err = suite.acseSerer.UpdateSubjectMapping(context.Background(), &acsev1.UpdateSubjectMappingRequest{
		Id:             1,
		SubjectMapping: mapping.SubjectMapping,
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

func (suite *AcseSuite) Test_UpdateSubjectMapping_Returns_OK_When_Successful() {
	// Copy Global Test Data to Local
	mapping := subjectMapping

	bMapping, err := protojson.Marshal(mapping.SubjectMapping)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(mapping.SubjectMapping.Descriptor_.Name,
			mapping.SubjectMapping.Descriptor_.Namespace,
			mapping.SubjectMapping.Descriptor_.Version,
			mapping.SubjectMapping.Descriptor_.Description,
			mapping.SubjectMapping.Descriptor_.Fqn,
			mapping.SubjectMapping.Descriptor_.Labels,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String(),
			bMapping,
			int32(1),
		).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	_, err = suite.acseSerer.UpdateSubjectMapping(context.Background(), &acsev1.UpdateSubjectMappingRequest{
		Id:             1,
		SubjectMapping: mapping.SubjectMapping,
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AcseSuite) Test_DeleteSubjectMapping_Returns_Internal_Error_When_Database_Error() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String()).
		WillReturnError(errors.New("error deleting subject mapping"))

	_, err := suite.acseSerer.DeleteSubjectMapping(context.Background(), &acsev1.DeleteSubjectMappingRequest{
		Id: 1,
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

func (suite *AcseSuite) Test_DeleteSubjectMapping_Returns_OK_When_Successful() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_SUBJECT_ENCODING_MAPPING.String()).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	_, err := suite.acseSerer.DeleteSubjectMapping(context.Background(), &acsev1.DeleteSubjectMappingRequest{
		Id: 1,
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}
