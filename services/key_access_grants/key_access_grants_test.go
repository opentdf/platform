package keyaccessgrants

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	attributesv1 "github.com/opentdf/opentdf-v2-poc/gen/attributes/v1"
	commonv1 "github.com/opentdf/opentdf-v2-poc/gen/common/v1"
	kagv1 "github.com/opentdf/opentdf-v2-poc/gen/key_access_grants/v1"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/pkg/services"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

type KeyAccessGrantSuite struct {
	suite.Suite
	mock      pgxmock.PgxPoolIface
	kagServer *KeyAccessGrants
}

func (suite *KeyAccessGrantSuite) SetupSuite() {
	mock, err := pgxmock.NewPool()
	if err != nil {
		slog.Error("could not create pgxpool mock", slog.String("error", err.Error()))
	}
	suite.mock = mock

	suite.kagServer = &KeyAccessGrants{
		dbClient: &db.Client{
			PgxIface: mock,
		},
	}
}

func TestAcseSuite(t *testing.T) {
	suite.Run(t, new(KeyAccessGrantSuite))
}

//nolint:gochecknoglobals // This is test data and should be reinitialized for each test
var keyAccessGrants = &kagv1.CreateKeyAccessGrantsRequest{
	Grants: &kagv1.KeyAccessGrants{
		Descriptor_: &commonv1.ResourceDescriptor{
			Name:      "test",
			Namespace: "opentdf.com",
			Version:   1,
			Fqn:       "http://opentdf.com/v1/grants/tests",
			Id:        1,
			Type:      commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_KEY_ACCESS_GRANTS,
		},
		KeyAccessServers: []*kagv1.KeyAccessServer{
			{
				Url: "http://localhost:9000",
			},
		},
		KeyAccessGrants: []*kagv1.KeyAccessGrant{
			{
				AttributeDefinition: &attributesv1.AttributeDefinition{
					Name: "test",
				},
				AttributeValueGrants: []*kagv1.KeyAccessGrantAttributeValue{
					{
						Value:  &attributesv1.AttributeValueReference{},
						KasIds: []string{"kas1", "kas2"},
					},
				},
			},
		},
	},
}

func (suite *KeyAccessGrantSuite) Test_CreateKeyAccessGrants_Returns_Internal_Error_When_Database_Error() {
	// Copy Global Test Data to Local
	grant := keyAccessGrants

	bGrants, err := protojson.Marshal(grant.Grants)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(grant.Grants.Descriptor_.Name,
			grant.Grants.Descriptor_.Namespace,
			grant.Grants.Descriptor_.Version,
			grant.Grants.Descriptor_.Fqn,
			grant.Grants.Descriptor_.Labels,
			grant.Grants.Descriptor_.Description,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_KEY_ACCESS_GRANTS.String(),
			bGrants,
		).
		WillReturnError(errors.New("error inserting resource"))

	_, err = suite.kagServer.CreateKeyAccessGrants(context.Background(), grant)
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), "error inserting resource")
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *KeyAccessGrantSuite) Test_CreateKeyAccessGrants_Returns_OK_When_Successful() {
	// Copy Global Test Data to Local
	grant := keyAccessGrants

	bGrant, err := protojson.Marshal(grant.Grants)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(grant.Grants.Descriptor_.Name,
			grant.Grants.Descriptor_.Namespace,
			grant.Grants.Descriptor_.Version,
			grant.Grants.Descriptor_.Fqn,
			grant.Grants.Descriptor_.Labels,
			grant.Grants.Descriptor_.Description,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_KEY_ACCESS_GRANTS.String(),
			bGrant,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	_, err = suite.kagServer.CreateKeyAccessGrants(context.Background(), grant)

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *KeyAccessGrantSuite) Test_ListKeyAccessGrants_Returns_Internal_Error_When_Database_Error() {
	selector := &commonv1.ResourceSelector{
		Namespace: "opentdf",
		Version:   1,
	}

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_KEY_ACCESS_GRANTS.String(), selector.Namespace, int32(1)).
		WillReturnError(errors.New("error listing key access grants"))

	_, err := suite.kagServer.ListKeyAccessGrants(context.Background(), &kagv1.ListKeyAccessGrantsRequest{
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

func (suite *KeyAccessGrantSuite) Test_ListKeyAccessGrants_Returns_OK_When_Successful() {
	// Copy Global Test Data to Local
	grant := keyAccessGrants

	bGrant, err := protojson.Marshal(grant.Grants)

	assert.NoError(suite.T(), err)

	selector := &commonv1.ResourceSelector{
		Namespace: "opentdf",
		Version:   1,
	}

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_KEY_ACCESS_GRANTS.String(), selector.Namespace, int32(1)).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).AddRow(int32(1), bGrant))

	_, err = suite.kagServer.ListKeyAccessGrants(context.Background(), &kagv1.ListKeyAccessGrantsRequest{
		Selector: selector,
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *KeyAccessGrantSuite) Test_GetKeyAccessGrant_Returns_Internal_Error_When_Database_Error() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_KEY_ACCESS_GRANTS.String()).
		WillReturnError(errors.New("error getting key access grants"))

	_, err := suite.kagServer.GetKeyAccessGrant(context.Background(), &kagv1.GetKeyAccessGrantRequest{
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

func (suite *KeyAccessGrantSuite) Test_GetKeyAccessGrant_Returns_NotFound_Error_When_No_Grants_Found() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_KEY_ACCESS_GRANTS.String()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}))

	_, err := suite.kagServer.GetKeyAccessGrant(context.Background(), &kagv1.GetKeyAccessGrantRequest{
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

func (suite *KeyAccessGrantSuite) Test_GetKeyAccessGrant_Returns_OK_When_Successful() {
	// Copy Global Test Data to Local
	grant := keyAccessGrants

	bGrant, err := protojson.Marshal(grant.Grants)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_KEY_ACCESS_GRANTS.String()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).AddRow(int32(1), bGrant))

	_, err = suite.kagServer.GetKeyAccessGrant(context.Background(), &kagv1.GetKeyAccessGrantRequest{
		Id: 1,
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *KeyAccessGrantSuite) Test_UpdateKeyAccessGrants_Returns_Internal_Error_When_Database_Error() {
	// Copy Global Test Data to Local
	grant := keyAccessGrants

	bGrants, err := protojson.Marshal(grant.Grants)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(grant.Grants.Descriptor_.Name,
			grant.Grants.Descriptor_.Namespace,
			grant.Grants.Descriptor_.Version,
			grant.Grants.Descriptor_.Description,
			grant.Grants.Descriptor_.Fqn,
			grant.Grants.Descriptor_.Labels,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_KEY_ACCESS_GRANTS.String(),
			bGrants,
			int32(1),
		).
		WillReturnError(errors.New("error updating key access grant"))

	_, err = suite.kagServer.UpdateKeyAccessGrants(context.Background(), &kagv1.UpdateKeyAccessGrantsRequest{
		Id:     1,
		Grants: grant.Grants,
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

func (suite *KeyAccessGrantSuite) Test_UpdateKeyAccessGrants_Returns_OK_When_Successful() {
	// Copy Global Test Data to Local
	grant := keyAccessGrants

	bGrants, err := protojson.Marshal(grant.Grants)

	assert.NoError(suite.T(), err)

	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(grant.Grants.Descriptor_.Name,
			grant.Grants.Descriptor_.Namespace,
			grant.Grants.Descriptor_.Version,
			grant.Grants.Descriptor_.Description,
			grant.Grants.Descriptor_.Fqn,
			grant.Grants.Descriptor_.Labels,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_KEY_ACCESS_GRANTS.String(),
			bGrants,
			int32(1),
		).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	_, err = suite.kagServer.UpdateKeyAccessGrants(context.Background(), &kagv1.UpdateKeyAccessGrantsRequest{
		Id:     1,
		Grants: grant.Grants,
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *KeyAccessGrantSuite) Test_DeleteKeyAccessGrants_Returns_Internal_Error_When_Database_Error() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_KEY_ACCESS_GRANTS.String()).
		WillReturnError(errors.New("error deleting key access grant"))

	_, err := suite.kagServer.DeleteKeyAccessGrants(context.Background(), &kagv1.DeleteKeyAccessGrantsRequest{
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

func (suite *KeyAccessGrantSuite) Test_DeleteKeyAccessGrants_Returns_OK_When_Successful() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_KEY_ACCESS_GRANTS.String()).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	_, err := suite.kagServer.DeleteKeyAccessGrants(context.Background(), &kagv1.DeleteKeyAccessGrantsRequest{
		Id: 1,
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}
