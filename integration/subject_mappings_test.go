package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/internal/fixtures"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SubjectMappingsSuite struct {
	suite.Suite
	schema string
	f      fixtures.Fixtures
	db     fixtures.DBInterface
	ctx    context.Context
}

func (s *SubjectMappingsSuite) SetupSuite() {
	slog.Info("setting up db.SubjectMappings test suite")
	s.ctx = context.Background()
	s.schema = "test_opentdf_subject_mappings"
	s.db = fixtures.NewDBInterface(*Config)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
}

func (s *SubjectMappingsSuite) TearDownSuite() {
	slog.Info("tearing down db.SubjectMappings test suite")
	s.f.TearDown()
}

func (s *SubjectMappingsSuite) Test_CreateSubjectMapping() {
	metadata := &common.MetadataMutable{}

	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	mapping := &subjectmapping.SubjectMappingCreateUpdate{
		AttributeValueId: attrValue.Id,
		Operator:         subjectmapping.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
		SubjectAttribute: "subject_attribute--test",
		SubjectValues:    []string{"subject_attribute_values--test1", "subject_attribute_values--test2"},
		Metadata:         metadata,
	}
	createdMapping, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, mapping)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdMapping)
}

func (s *SubjectMappingsSuite) Test_GetSubjectMapping() {
	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	mapping := &subjectmapping.SubjectMappingCreateUpdate{
		AttributeValueId: attrValue.Id,
		Operator:         subjectmapping.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
		SubjectAttribute: "subject_attribute--test",
		SubjectValues:    []string{"subject_attribute_values--test1", "subject_attribute_values--test2"},
		Metadata:         &common.MetadataMutable{},
	}
	createdMapping, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, mapping)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdMapping)

	gotMapping, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, createdMapping.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), gotMapping)
}

func TestSubjectMappingSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subject_mappings integration tests")
	}
	suite.Run(t, new(SubjectMappingsSuite))
}
