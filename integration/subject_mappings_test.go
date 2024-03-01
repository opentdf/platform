package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/protocol/go/authorization"

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
	s.T().Skip("after DB changes")
	metadata := &common.MetadataMutable{}

	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	mapping := &subjectmapping.SubjectMappingCreateUpdate{
		AttributeValueId: attrValue.Id,
		Metadata:         metadata,
		SubjectSets: []*subjectmapping.SubjectSet{
			{
				ConditionGroups: []*subjectmapping.ConditionGroup{
					{
						Conditions: []*subjectmapping.Condition{
							{
								SubjectExternalField:  "Department",
								Operator:              subjectmapping.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								SubjectExternalValues: []string{"Marketing", "Sales"},
							},
						},
					},
				},
			},
		},
		Actions: []*authorization.Action{},
	}
	createdMapping, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, mapping)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdMapping)
}

func (s *SubjectMappingsSuite) Test_GetSubjectMapping() {
	s.T().Skip("after DB changes")
	attrValue := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	mapping := &subjectmapping.SubjectMappingCreateUpdate{
		AttributeValueId: attrValue.Id,
		SubjectSets: []*subjectmapping.SubjectSet{
			{
				ConditionGroups: []*subjectmapping.ConditionGroup{
					{
						Conditions: []*subjectmapping.Condition{
							{
								SubjectExternalField:  "usernames",
								Operator:              subjectmapping.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								SubjectExternalValues: []string{"hello@world.com", "tonystark@avengers.gov"},
							},
						},
					},
				},
			},
		},
		Actions:  []*authorization.Action{},
		Metadata: &common.MetadataMutable{},
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
