package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/google/uuid"
	"github.com/opentdf/opentdf-v2-poc/internal/db"
	"github.com/opentdf/opentdf-v2-poc/sdk/common"
	"github.com/opentdf/opentdf-v2-poc/sdk/subjectmapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SubjectMappingsSuite struct {
	suite.Suite
	client *db.Client
	ctx    context.Context
}

func (s *SubjectMappingsSuite) SetupSuite() {
	slog.Info("setting up db.SubjectMappings test suite")
	s.ctx = context.Background()

	var err error
	// s.client, err = db.NewClient(Config.DB)
	s.client = DBClient
	if err != nil {
		slog.Error("issue creating database client", slog.String("error", err.Error()))
		panic(err)
	}

	// TODO: Create test suite schema (i.e. opentdf_test_subject_mappings)
	// TODO: Run migrations
	fixtures.provisionData()
}

func (s *SubjectMappingsSuite) TearDownSuite() {
	slog.Info("tearing down db.SubjectMappings test suite")

	// Temporarily: Truncate all tables
	fixtures.truncateAllTables()
}

func (s *SubjectMappingsSuite) Test_CreateSubjectMapping() {
	metadata := &common.MetadataMutable{}
	mapping := &subjectmapping.SubjectMappingCreateUpdate{
		AttributeValueId: uuid.New().String(),
		Operator:         subjectmapping.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
		SubjectAttribute: "subject_attribute--test",
		SubjectValues:    []string{"subject_attribute_values--test1", "subject_attribute_values--test2"},
		Metadata:         metadata,
	}
	createdMapping, err := s.client.CreateSubjectMapping(s.ctx, mapping)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdMapping)
}

func TestSubjectMappingSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping attributes integration tests")
	}
	suite.Run(t, new(SubjectMappingsSuite))
}
