package attributes

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	attributesv1 "github.com/opentdf/opentdf-v2-poc/gen/attributes/v1"
	commonv1 "github.com/opentdf/opentdf-v2-poc/gen/common/v1"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/pkg/services"
	"github.com/pashagolub/pgxmock/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AttributesSuite struct {
	suite.Suite
	mock       pgxmock.PgxPoolIface
	attrServer *Attributes
}

func (suite *AttributesSuite) SetupSuite() {
	mock, err := pgxmock.NewPool()
	if err != nil {
		slog.Error("could not create pgxpool mock", slog.String("error", err.Error()))
	}
	suite.mock = mock

	suite.attrServer = &Attributes{
		dbClient: &db.Client{
			PgxIface: mock,
		},
	}
}

func (suite *AttributesSuite) TearDownSuite() {
	suite.mock.Close()
}

func TestAttributesSuite(t *testing.T) {
	suite.Run(t, new(AttributesSuite))
}

//nolint:gochecknoglobals // This is test data and should be reinitialized for each test
var attributeDefinition = &attributesv1.CreateAttributeRequest{
	Definition: &attributesv1.AttributeDefinition{
		Name: "relto",
		Rule: attributesv1.AttributeDefinition_ATTRIBUTE_RULE_TYPE_ANY_OF,
		Values: []*attributesv1.AttributeDefinitionValue{
			{
				Value: "USA",
			},
		},
		Descriptor_: &commonv1.ResourceDescriptor{
			Version:   1,
			Name:      "example attribute",
			Namespace: "demo.com",
			Fqn:       "http://demo.com/attr/relto",
			Labels: map[string]string{
				"origin": "Country of Origin",
			},
			Description: "The relto attribute is used to describe the relationship of the resource to the country of origin.",
			Type:        commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION,
		},
	},
}

//nolint:gochecknoglobals // This is test data and should be reinitialized for each test
var attributeGroup = &attributesv1.CreateAttributeGroupRequest{
	Group: &attributesv1.AttributeGroup{
		Descriptor_: &commonv1.ResourceDescriptor{
			Version:   1,
			Name:      "example attribute group",
			Namespace: "demo.com",
			Fqn:       "http://demo.com/attr/group",
			Labels:    map[string]string{},
			Type:      commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP,
		},
		MemberValues: []*attributesv1.AttributeValueReference{},
		GroupValue:   &attributesv1.AttributeValueReference{},
	},
}

func (suite *AttributesSuite) Test_CreateAttribute_Returns_InternalError_When_Database_Error() {
	// Copy Global Test Data to Local
	definition := attributeDefinition

	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(definition.Definition.Descriptor_.Name,
			definition.Definition.Descriptor_.Namespace,
			definition.Definition.Descriptor_.Version,
			definition.Definition.Descriptor_.Fqn,
			definition.Definition.Descriptor_.Labels,
			definition.Definition.Descriptor_.Description,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String(),
			definition.Definition,
		).
		WillReturnError(errors.New("error inserting resource"))

	_, err := suite.attrServer.CreateAttribute(context.Background(), definition)
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrCreatingResource)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AttributesSuite) Test_CreateAttribute_Returns_OK_When_Successful() {
	// Copy Global Test Data to Local
	definition := attributeDefinition

	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(definition.Definition.Descriptor_.Name,
			definition.Definition.Descriptor_.Namespace,
			definition.Definition.Descriptor_.Version,
			definition.Definition.Descriptor_.Fqn,
			definition.Definition.Descriptor_.Labels,
			definition.Definition.Descriptor_.Description,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String(),
			definition.Definition,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	_, err := suite.attrServer.CreateAttribute(context.Background(), definition)

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AttributesSuite) Test_CreateAttributeGroup_Returns_InternalError_When_Database_Error() {
	// Copy Global Test Data to Local
	group := attributeGroup

	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(group.Group.Descriptor_.Name,
			group.Group.Descriptor_.Namespace,
			group.Group.Descriptor_.Version,
			group.Group.Descriptor_.Fqn,
			group.Group.Descriptor_.Labels,
			group.Group.Descriptor_.Description,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(),
			group.Group,
		).
		WillReturnError(errors.New("error inserting resource"))

	_, err := suite.attrServer.CreateAttributeGroup(context.Background(), group)
	if assert.Error(suite.T(), err) {
		grpcStatus, _ := status.FromError(err)

		assert.Equal(suite.T(), codes.Internal, grpcStatus.Code())

		assert.Contains(suite.T(), grpcStatus.Message(), services.ErrCreatingResource)
	}

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AttributesSuite) Test_CreateAttributeGroup_Returns_OK_When_Successful() {
	// Copy Global Test Data to Local
	group := attributeGroup

	suite.mock.ExpectExec("INSERT INTO opentdf.resources").
		WithArgs(group.Group.Descriptor_.Name,
			group.Group.Descriptor_.Namespace,
			group.Group.Descriptor_.Version,
			group.Group.Descriptor_.Fqn,
			group.Group.Descriptor_.Labels,
			group.Group.Descriptor_.Description,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(),
			group.Group,
		).
		WillReturnResult(pgxmock.NewResult("INSERT", 1))

	_, err := suite.attrServer.CreateAttributeGroup(context.Background(), group)

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AttributesSuite) Test_ListAttributes_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String(), "opentdf", int32(1)).
		WillReturnError(errors.New("error listing attribute defintions"))

	_, err := suite.attrServer.ListAttributes(context.Background(), &attributesv1.ListAttributesRequest{
		Selector: &commonv1.ResourceSelector{
			Namespace: "opentdf",
			Version:   1,
		},
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

func (suite *AttributesSuite) Test_ListAttributes_Returns_OK_When_Successful() {
	// Copy Global Test Data to Local
	definition := attributeDefinition

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String(), "opentdf", int32(1)).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).
			AddRow(int32(1), definition.Definition))

	definitions, err := suite.attrServer.ListAttributes(context.Background(), &attributesv1.ListAttributesRequest{
		Selector: &commonv1.ResourceSelector{
			Namespace: "opentdf",
			Version:   1,
		},
	})

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), []*attributesv1.AttributeDefinition{definition.Definition}, definitions.Definitions)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AttributesSuite) Test_ListAttributeGroups_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(), "opentdf", int32(1)).
		WillReturnError(errors.New("error listing attribute groups"))

	_, err := suite.attrServer.ListAttributeGroups(context.Background(), &attributesv1.ListAttributeGroupsRequest{
		Selector: &commonv1.ResourceSelector{
			Namespace: "opentdf",
			Version:   1,
		},
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

func (suite *AttributesSuite) Test_ListAttributeGroups_Returns_OK_When_Successful() {
	// Copy Global Test Data to Local
	group := attributeGroup

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(), "opentdf", int32(1)).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).
			AddRow(int32(1), group.Group))

	groups, err := suite.attrServer.ListAttributeGroups(context.Background(), &attributesv1.ListAttributeGroupsRequest{
		Selector: &commonv1.ResourceSelector{
			Namespace: "opentdf",
			Version:   1,
		},
	})

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), []*attributesv1.AttributeGroup{group.Group}, groups.Groups)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AttributesSuite) Test_GetAttribute_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String()).
		WillReturnError(errors.New("error getting attribute definition"))

	_, err := suite.attrServer.GetAttribute(context.Background(), &attributesv1.GetAttributeRequest{
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

func (suite *AttributesSuite) Test_GetAttribute_Returns_NotFound_When_No_Resource_Found() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}))

	_, err := suite.attrServer.GetAttribute(context.Background(), &attributesv1.GetAttributeRequest{
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

func (suite *AttributesSuite) Test_GetAttribute_Returns_OK_When_Successful() {
	// Copy Global Test Data to Local
	definition := attributeDefinition

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).
			AddRow(int32(1), definition.Definition))

	resp, err := suite.attrServer.GetAttribute(context.Background(), &attributesv1.GetAttributeRequest{
		Id: 1,
	})

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), definition.Definition, resp.Definition)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AttributesSuite) Test_GetAttributeGroup_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String()).
		WillReturnError(errors.New("error getting attribute group"))

	_, err := suite.attrServer.GetAttributeGroup(context.Background(), &attributesv1.GetAttributeGroupRequest{
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

func (suite *AttributesSuite) Test_GetAttributeGroup_Returns_NotFound_When_No_Resource_Found() {
	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}))

	_, err := suite.attrServer.GetAttributeGroup(context.Background(), &attributesv1.GetAttributeGroupRequest{
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

func (suite *AttributesSuite) Test_GetAttributeGroup_Returns_OK_When_Successful() {
	// Copy Global Test Data to Local
	group := attributeGroup

	suite.mock.ExpectQuery("SELECT id, resource FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String()).
		WillReturnRows(pgxmock.NewRows([]string{"id", "resource"}).
			AddRow(int32(1), group.Group))

	resp, err := suite.attrServer.GetAttributeGroup(context.Background(), &attributesv1.GetAttributeGroupRequest{
		Id: 1,
	})

	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), group.Group, resp.Group)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AttributesSuite) Test_UpdateAttribute_Returns_InternalError_When_Database_Error() {
	// Copy Global Test Data to Local
	definition := attributeDefinition

	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(definition.Definition.Descriptor_.Name,
			definition.Definition.Descriptor_.Namespace,
			definition.Definition.Descriptor_.Version,
			definition.Definition.Descriptor_.Description,
			definition.Definition.Descriptor_.Fqn,
			definition.Definition.Descriptor_.Labels,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String(),
			definition.Definition,
			int32(1),
		).
		WillReturnError(errors.New("error updating attribute definition"))

	_, err := suite.attrServer.UpdateAttribute(context.Background(), &attributesv1.UpdateAttributeRequest{
		Definition: definition.Definition,
		Id:         1,
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

func (suite *AttributesSuite) Test_UpdateAttribute_Returns_OK_When_Successful() {
	// Copy Global Test Data to Local
	definition := attributeDefinition

	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(definition.Definition.Descriptor_.Name,
			definition.Definition.Descriptor_.Namespace,
			definition.Definition.Descriptor_.Version,
			definition.Definition.Descriptor_.Description,
			definition.Definition.Descriptor_.Fqn,
			definition.Definition.Descriptor_.Labels,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String(),
			definition.Definition,
			int32(1),
		).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	_, err := suite.attrServer.UpdateAttribute(context.Background(), &attributesv1.UpdateAttributeRequest{
		Definition: definition.Definition,
		Id:         1,
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AttributesSuite) Test_UpdateAttributeGroup_Returns_InternalError_When_Database_Error() {
	// Copy Global Test Data to Local
	group := attributeGroup

	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(group.Group.Descriptor_.Name,
			group.Group.Descriptor_.Namespace,
			group.Group.Descriptor_.Version,
			group.Group.Descriptor_.Description,
			group.Group.Descriptor_.Fqn,
			group.Group.Descriptor_.Labels,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(),
			group.Group,
			int32(1),
		).
		WillReturnError(errors.New("error updating attribute group"))

	_, err := suite.attrServer.UpdateAttributeGroup(context.Background(), &attributesv1.UpdateAttributeGroupRequest{
		Group: group.Group,
		Id:    1,
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

func (suite *AttributesSuite) Test_UpdateAttributeGroup_Returns_OK_When_Successful() {
	// Copy Global Test Data to Local
	group := attributeGroup

	suite.mock.ExpectExec("UPDATE opentdf.resources").
		WithArgs(group.Group.Descriptor_.Name,
			group.Group.Descriptor_.Namespace,
			group.Group.Descriptor_.Version,
			group.Group.Descriptor_.Description,
			group.Group.Descriptor_.Fqn,
			group.Group.Descriptor_.Labels,
			commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String(),
			group.Group,
			int32(1),
		).
		WillReturnResult(pgxmock.NewResult("UPDATE", 1))

	_, err := suite.attrServer.UpdateAttributeGroup(context.Background(), &attributesv1.UpdateAttributeGroupRequest{
		Group: group.Group,
		Id:    1,
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AttributesSuite) Test_DeleteAttribute_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String()).
		WillReturnError(errors.New("error deleting attribute definition"))

	_, err := suite.attrServer.DeleteAttribute(context.Background(), &attributesv1.DeleteAttributeRequest{
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

func (suite *AttributesSuite) Test_DeleteAttribute_Returns_OK_When_Successful() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION.String()).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	_, err := suite.attrServer.DeleteAttribute(context.Background(), &attributesv1.DeleteAttributeRequest{
		Id: 1,
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}

func (suite *AttributesSuite) Test_DeleteAttributeGroup_Returns_InternalError_When_Database_Error() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String()).
		WillReturnError(errors.New("error deleting attribute group"))

	_, err := suite.attrServer.DeleteAttributeGroup(context.Background(), &attributesv1.DeleteAttributeGroupRequest{
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

func (suite *AttributesSuite) Test_DeleteAttributeGroup_Returns_OK_When_Successful() {
	suite.mock.ExpectExec("DELETE FROM opentdf.resources").
		WithArgs(int32(1), commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_GROUP.String()).
		WillReturnResult(pgxmock.NewResult("DELETE", 1))

	_, err := suite.attrServer.DeleteAttributeGroup(context.Background(), &attributesv1.DeleteAttributeGroupRequest{
		Id: 1,
	})

	assert.NoError(suite.T(), err)

	if err := suite.mock.ExpectationsWereMet(); err != nil {
		suite.T().Errorf("there were unfulfilled expectations: %s", err)
	}
}
