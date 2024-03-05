package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/internal/fixtures"
	"github.com/opentdf/platform/protocol/go/authorization"
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

// a set of easily accessible actions for use in tests
var (
	DECRYPT         = "DECRYPT"
	TRANSMIT        = "TRANSMIT"
	CUSTOM_DOWNLOAD = "CUSTOM_DOWNLOAD"
	CUSTOM_UPLOAD   = "CUSTOM_UPLOAD"

	fixtureActions = map[string]*authorization.Action{
		"DECRYPT": {
			Value: &authorization.Action_Standard{
				Standard: authorization.Action_STANDARD_ACTION_DECRYPT,
			},
		},
		"TRANSMIT": {
			Value: &authorization.Action_Standard{
				Standard: authorization.Action_STANDARD_ACTION_TRANSMIT,
			},
		},
		"CUSTOM_DOWNLOAD": {
			Value: &authorization.Action_Custom{
				Custom: "DOWNLOAD",
			},
		},
		"CUSTOM_UPLOAD": {
			Value: &authorization.Action_Custom{
				Custom: "UPLOAD",
			},
		},
	}

	nonExistentSubjectSetId = "9f9f3282-ffff-1111-924a-7b8eb43d5423"
)

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_ExistingSubjectConditionSetId() {
	fixtureAttrValId := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value2").Id
	fixtureSCSId := s.f.GetSubjectConditionSetKey("subject_condition_set1").Id

	aDecrypt := fixtureActions[DECRYPT]
	aTransmit := fixtureActions[TRANSMIT]
	new := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrValId,
		ExistingSubjectConditionSetId: fixtureSCSId,
		Actions:                       []*authorization.Action{aDecrypt, aTransmit},
	}

	sm, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), sm)
	assert.Equal(s.T(), new.AttributeValueId, sm.AttributeValue.Id)
	assert.Equal(s.T(), new.ExistingSubjectConditionSetId, sm.SubjectConditionSet.Id)
	assert.Equal(s.T(), 2, len(sm.Actions))
	assert.Equal(s.T(), sm.GetActions(), new.Actions)
}

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_NewSubjectConditionSet() {
	fixtureAttrValId := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value2").Id
	aTransmit := fixtureActions[TRANSMIT]

	scs := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*subjectmapping.SubjectSet{
			{
				ConditionGroups: []*subjectmapping.ConditionGroup{
					{
						BooleanOperator: subjectmapping.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
						Conditions: []*subjectmapping.Condition{
							{
								SubjectExternalField:  "email",
								Operator:              subjectmapping.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								SubjectExternalValues: []string{"hello@email.com"},
							},
						},
					},
				},
			},
		},
	}

	new := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:       fixtureAttrValId,
		Actions:                []*authorization.Action{aTransmit},
		NewSubjectConditionSet: scs,
	}

	sm, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), sm)
	assert.Equal(s.T(), new.AttributeValueId, sm.AttributeValue.Id)
	assert.Equal(s.T(), sm.GetActions(), new.Actions)

	// verify the new subject condition set created was returned properly
	assert.NotNil(s.T(), sm.SubjectConditionSet)
	assert.Equal(s.T(), len(scs.SubjectSets), len(sm.SubjectConditionSet.SubjectSets))

	expectedCGroups := scs.SubjectSets[0].ConditionGroups
	gotCGroups := sm.SubjectConditionSet.SubjectSets[0].ConditionGroups
	assert.Equal(s.T(), len(expectedCGroups), len(gotCGroups))
	assert.Equal(s.T(), len(expectedCGroups[0].Conditions), len(gotCGroups[0].Conditions))

	expectedCondition := expectedCGroups[0].Conditions[0]
	gotCondition := sm.SubjectConditionSet.SubjectSets[0].ConditionGroups[0].Conditions[0]
	assert.Equal(s.T(), expectedCondition.SubjectExternalField, gotCondition.SubjectExternalField)
	assert.Equal(s.T(), expectedCondition.Operator, gotCondition.Operator)
	assert.Equal(s.T(), expectedCondition.SubjectExternalValues, gotCondition.SubjectExternalValues)
}

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_PrefersExistingSubjectConditionSetIdWhenBothProvided() {
	fixtureAttrValId := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value1").Id
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set1")
	aTransmit := fixtureActions[TRANSMIT]

	scs := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*subjectmapping.SubjectSet{
			{
				ConditionGroups: []*subjectmapping.ConditionGroup{
					{
						BooleanOperator: subjectmapping.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
						Conditions: []*subjectmapping.Condition{
							{
								SubjectExternalField:  "field",
								Operator:              subjectmapping.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								SubjectExternalValues: []string{"value"},
							},
						},
					},
				},
			},
		},
		Name: "should_be_ignored",
	}

	new := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrValId,
		ExistingSubjectConditionSetId: fixtureScs.Id,
		Actions:                       []*authorization.Action{aTransmit},
		NewSubjectConditionSet:        scs,
	}

	sm, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), sm)

	// verify the new subject condition set was not used
	assert.NotNil(s.T(), sm.SubjectConditionSet)
	assert.Equal(s.T(), fixtureScs.Id, sm.SubjectConditionSet.Id)
	assert.NotEqual(s.T(), scs.Name, sm.SubjectConditionSet.Name)
}

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_NoActions_Fails() {
	fixtureAttrVal := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value1")
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	new := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrVal.Id,
		ExistingSubjectConditionSetId: fixtureScs.Id,
	}

	sm, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), sm)
	assert.ErrorIs(s.T(), err, db.ErrMissingRequiredValue)
}

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_NonExistentAttributeValueId_Fails() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	aTransmit := fixtureActions[TRANSMIT]
	new := &subjectmapping.CreateSubjectMappingRequest{
		Actions:                       []*authorization.Action{aTransmit},
		ExistingSubjectConditionSetId: fixtureScs.Id,
		AttributeValueId:              nonExistentAttributeValueUuid,
	}

	sm, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), sm)
	assert.ErrorIs(s.T(), err, db.ErrForeignKeyViolation)
}

// TODO: FIXME
// func (s *SubjectMappingsSuite) TestGetSubjectMapping() {
// 	fixture := s.f.GetSubjectMappingKey("subject_mapping_subject_attribute3")

// 	sm, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, fixture.Id)
// 	assert.Nil(s.T(), err)
// 	assert.NotNil(s.T(), sm)
// 	assert.Equal(s.T(), fixture.Id, sm.Id)
// 	assert.Equal(s.T(), fixture.Actions, sm.Actions)
// 	assert.Equal(s.T(), fixture.AttributeValueId, sm.AttributeValue.Id)
// 	assert.Equal(s.T(), fixture.SubjectConditionSetId, sm.SubjectConditionSet.Id)
// }

// CRUD tests for subject condition sets

func (s *SubjectMappingsSuite) TestCreateSubjectConditionSet_WithName() {
	new := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*subjectmapping.SubjectSet{
			{
				ConditionGroups: []*subjectmapping.ConditionGroup{
					{
						BooleanOperator: subjectmapping.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
						Conditions: []*subjectmapping.Condition{
							{
								SubjectExternalField:  "userId",
								Operator:              subjectmapping.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								SubjectExternalValues: []string{"email@gmail.com", "hello@yahoo.com"},
							},
						},
					},
				},
			},
		},
		Name: "subject_condition_set_create",
	}

	scs, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), scs)
	assert.Equal(s.T(), scs.Name, "subject_condition_set_create")
	assert.Equal(s.T(), len(new.SubjectSets), len(scs.SubjectSets))
}

func (s *SubjectMappingsSuite) TestCreateSubjectConditionSet_NoOptionalName() {
	new := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*subjectmapping.SubjectSet{
			{
				ConditionGroups: []*subjectmapping.ConditionGroup{
					{
						BooleanOperator: subjectmapping.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
						Conditions: []*subjectmapping.Condition{
							{
								SubjectExternalField:  "some_field",
								Operator:              subjectmapping.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN,
								SubjectExternalValues: []string{"some_value"},
							},
						},
					},
				},
			},
		},
	}

	scs, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), scs)
	assert.Equal(s.T(), "", scs.Name)
}

func (s *SubjectMappingsSuite) TestCreateSubjectConditionSet_OnNameConflict_Fails() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set1")
	new := &subjectmapping.SubjectConditionSetCreate{
		// DB does not validate subject condition sets; only protos do
		SubjectSets: []*subjectmapping.SubjectSet{},
		Name:        fixtureScs.Name,
	}

	scs, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, new)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), scs)
	assert.ErrorIs(s.T(), err, db.ErrUniqueConstraintViolation)
}

func (s *SubjectMappingsSuite) TestGetSubjectConditionSet_ById() {
	fixture := s.f.GetSubjectConditionSetKey("subject_condition_set1")

	scs, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, fixture.Id, "")
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), scs)
	assert.Equal(s.T(), fixture.Id, scs.Id)
	assert.Equal(s.T(), fixture.Name, scs.Name)
}

func (s *SubjectMappingsSuite) TestGetSubjectConditionSet_ByName() {
	fixture := s.f.GetSubjectConditionSetKey("subject_condition_set2")

	scs, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, "", fixture.Name)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), scs)
	assert.Equal(s.T(), fixture.Id, scs.Id)
	assert.Equal(s.T(), fixture.Name, scs.Name)
}

func (s *SubjectMappingsSuite) TestGetSubjectConditionSet_WithIdAndNamePrefersId() {
	fixture := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	fixtureWrong := s.f.GetSubjectConditionSetKey("subject_condition_set1")

	scs, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, fixture.Id, fixtureWrong.Name)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), scs)
	assert.Equal(s.T(), fixture.Id, scs.Id)
	assert.Equal(s.T(), fixture.Name, scs.Name)
	assert.NotEqual(s.T(), fixtureWrong.Id, scs.Id)
}

func (s *SubjectMappingsSuite) TestGetSubjectConditionSet_WithNoIdOrName_Fails() {
	scs, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, "", "")
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), scs)
	assert.ErrorIs(s.T(), err, db.ErrMissingRequiredValue)
}

func (s *SubjectMappingsSuite) TestGetSubjectConditionSet_NonexistentId_Fails() {
	scs, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, nonExistentSubjectSetId, "")
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), scs)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestGetSubjectConditionSet_NonexistentName_Fails() {
	scs, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, "", "nonexistent_name")
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), scs)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestListSubjectConditionSet() {
	list, err := s.db.PolicyClient.ListSubjectConditionSets(s.ctx)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), list)

	fixture1 := s.f.GetSubjectConditionSetKey("subject_condition_set1")
	found1 := false
	fixture2 := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	found2 := false
	fixture3 := s.f.GetSubjectConditionSetKey("subject_condition_set3")
	found3 := false
	fixture4 := s.f.GetSubjectConditionSetKey("subject_condition_omitted_optional_name")
	found4 := false

	assert.GreaterOrEqual(s.T(), len(list), 3)
	for _, scs := range list {
		if scs.Id == fixture1.Id {
			found1 = true
		} else if scs.Id == fixture2.Id {
			found2 = true
		} else if scs.Id == fixture3.Id {
			found3 = true
		} else if scs.Id == fixture4.Id {
			found4 = true
		}
	}
	assert.True(s.T(), found1)
	assert.True(s.T(), found2)
	assert.True(s.T(), found3)
	assert.True(s.T(), found4)
}

func (s *SubjectMappingsSuite) TestDeleteSubjectConditionSet() {
	// create a new subject condition set, delete it, and verify get fails with not found
	new := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*subjectmapping.SubjectSet{},
		Name:        "subject_condition_set_delete",
	}

	scs, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), scs)

	deleted, err := s.db.PolicyClient.DeleteSubjectConditionSet(s.ctx, scs.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), deleted)

	scs, err = s.db.PolicyClient.GetSubjectConditionSet(s.ctx, scs.Id, "")
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), scs)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)

	scs, err = s.db.PolicyClient.GetSubjectConditionSet(s.ctx, "", new.Name)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), scs)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestUpdateSubjectConditionSet() {
	new := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*subjectmapping.SubjectSet{
			{
				ConditionGroups: []*subjectmapping.ConditionGroup{
					{
						BooleanOperator: subjectmapping.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
						Conditions: []*subjectmapping.Condition{
							{
								SubjectExternalField:  "origin",
								Operator:              subjectmapping.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								SubjectExternalValues: []string{"USA", "Canada"},
							},
						},
					},
				},
			},
		},
		Name: "subject_condition_set_update",
	}

	scs, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), scs)

	// update the subject condition set
	newName := "subject_condition_set_update_updated"
	update := &subjectmapping.SubjectConditionSetUpdate{
		UpdatedName: newName,
	}

	updated, err := s.db.PolicyClient.UpdateSubjectConditionSet(s.ctx, scs.Id, update)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updated)
	assert.Equal(s.T(), scs.Id, updated.Id)
	assert.Equal(s.T(), newName, updated.Name)
}

func TestSubjectMappingSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subject_mappings integration tests")
	}
	suite.Run(t, new(SubjectMappingsSuite))
}
