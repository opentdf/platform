package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/internal/fixtures"
	"github.com/opentdf/platform/protocol/go/authorization"
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

	nonExistentSubjectSetId     = "9f9f3282-ffff-1111-924a-7b8eb43d5423"
	nonExistentSubjectMappingId = "32977f0b-f2b9-44b5-8afd-e2e224ea8352"
)

/*--------------------------------------------------------
 *-------------------- SubjectMappings -------------------
 *-------------------------------------------------------*/

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

	smId, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), smId)

	// verify the subject mapping was created
	sm, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, smId)
	assert.Nil(s.T(), err)
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

	smId, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), smId)

	// verify the new subject condition set created was returned properly
	sm, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, smId)
	assert.Nil(s.T(), err)
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

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_NoActions_Fails() {
	fixtureAttrVal := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value1")
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	new := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrVal.Id,
		ExistingSubjectConditionSetId: fixtureScs.Id,
	}

	createdId, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.NotNil(s.T(), err)
	assert.Zero(s.T(), createdId)
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

	createdId, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.NotNil(s.T(), err)
	assert.Zero(s.T(), createdId)
	assert.ErrorIs(s.T(), err, db.ErrForeignKeyViolation)
}

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_NonExistentSubjectConditionSetId_Fails() {
	fixtureAttrVal := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value1")
	aTransmit := fixtureActions[TRANSMIT]
	new := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrVal.Id,
		Actions:                       []*authorization.Action{aTransmit},
		ExistingSubjectConditionSetId: nonExistentSubjectSetId,
	}

	createdId, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.NotNil(s.T(), err)
	assert.Zero(s.T(), createdId)
	assert.ErrorIs(s.T(), err, db.ErrForeignKeyViolation)
}

func (s *SubjectMappingsSuite) TestUpdateSubjectMapping_Actions() {
	// create a new one, update it, and verify the update
	fixtureAttrValId := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value2").Id
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set3")
	aTransmit := fixtureActions[TRANSMIT]
	aCustomUpload := fixtureActions[CUSTOM_UPLOAD]

	new := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrValId,
		Actions:                       []*authorization.Action{aTransmit, aCustomUpload},
		ExistingSubjectConditionSetId: fixtureScs.Id,
	}

	createdId, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), createdId)

	// update the subject mapping
	newActions := []*authorization.Action{aTransmit}
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id:            createdId,
		UpdateActions: newActions,
	}

	updatedId, err := s.db.PolicyClient.UpdateSubjectMapping(s.ctx, update)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), createdId, updatedId)

	// verify the actions were updated but nothing else
	got, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, createdId)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), len(newActions), len(got.Actions))
	assert.Equal(s.T(), got.GetActions(), newActions)
	assert.Equal(s.T(), new.AttributeValueId, got.AttributeValue.Id)
	assert.Equal(s.T(), new.ExistingSubjectConditionSetId, got.SubjectConditionSet.Id)
}

func (s *SubjectMappingsSuite) TestUpdateSubjectMapping_SubjectConditionSetId() {
	// create a new one, update it, and verify the update
	fixtureAttrValId := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value1").Id
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set1")
	aTransmit := fixtureActions[TRANSMIT]

	new := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrValId,
		Actions:                       []*authorization.Action{aTransmit},
		ExistingSubjectConditionSetId: fixtureScs.Id,
	}

	createdId, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), createdId)

	// update the subject mapping
	newScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id:                          createdId,
		UpdateSubjectConditionSetId: newScs.Id,
	}

	updatedId, err := s.db.PolicyClient.UpdateSubjectMapping(s.ctx, update)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), createdId, updatedId)

	// verify the subject condition set was updated but nothing else
	got, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, createdId)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), new.AttributeValueId, got.AttributeValue.Id)
	assert.Equal(s.T(), newScs.Id, got.SubjectConditionSet.Id)
	assert.Equal(s.T(), len(new.Actions), len(got.Actions))
	assert.Equal(s.T(), new.Actions, got.GetActions())
}

func (s *SubjectMappingsSuite) TestUpdateSubjectMapping_UpdateAllAllowedFields() {
	// create a new one, update it, and verify the update
	fixtureAttrValId := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value1").Id
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set1")
	aTransmit := fixtureActions[TRANSMIT]

	new := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrValId,
		Actions:                       []*authorization.Action{aTransmit},
		ExistingSubjectConditionSetId: fixtureScs.Id,
	}

	createdId, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), createdId)

	// update the subject mapping
	newScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	newActions := []*authorization.Action{fixtureActions[CUSTOM_DOWNLOAD]}
	metadata := &common.MetadataMutable{
		Labels: map[string]string{"key": "value"},
	}
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id:                          createdId,
		UpdateActions:               newActions,
		UpdateSubjectConditionSetId: newScs.Id,
		UpdateMetadata:              metadata,
	}

	updatedId, err := s.db.PolicyClient.UpdateSubjectMapping(s.ctx, update)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), createdId, updatedId)

	// verify the subject mapping was updated
	got, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, createdId)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), createdId, got.Id)
	assert.Equal(s.T(), new.AttributeValueId, got.AttributeValue.Id)
	assert.Equal(s.T(), newScs.Id, got.SubjectConditionSet.Id)
	assert.Equal(s.T(), len(newActions), len(got.Actions))
	assert.Equal(s.T(), newActions, got.GetActions())
	assert.Equal(s.T(), metadata.Labels["key"], got.Metadata.Labels["key"])
}

func (s *SubjectMappingsSuite) TestUpdateSubjectMapping_NonExistentId_Fails() {
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id: nonExistentSubjectMappingId,
	}

	smId, err := s.db.PolicyClient.UpdateSubjectMapping(s.ctx, update)
	assert.NotNil(s.T(), err)
	assert.Zero(s.T(), smId)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestUpdateSubjectMapping_NonExistentSubjectConditionSetId_Fails() {
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id:                          s.f.GetSubjectMappingKey("subject_mapping_subject_attribute3").Id,
		UpdateSubjectConditionSetId: nonExistentSubjectSetId,
	}

	smId, err := s.db.PolicyClient.UpdateSubjectMapping(s.ctx, update)
	assert.NotNil(s.T(), err)
	assert.Zero(s.T(), smId)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestGetSubjectMapping() {
	fixture := s.f.GetSubjectMappingKey("subject_mapping_subject_attribute3")

	sm, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, fixture.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), sm)
	assert.Equal(s.T(), fixture.Id, sm.Id)
	assert.Equal(s.T(), fixture.AttributeValueId, sm.AttributeValue.Id)
	assert.True(s.T(), sm.AttributeValue.Active.Value)
	assert.Equal(s.T(), fixture.SubjectConditionSetId, sm.SubjectConditionSet.Id)

	// verify the actions
	for i, a := range sm.Actions {
		assert.NotNil(s.T(), a)
		// In protos, standard actions are an enum and custom actions are a string,
		// so their string representations are slightly different
		if fixture.Actions[i].Standard != "" {
			assert.Equal(s.T(), "standard:"+fixture.Actions[i].Standard, a.String())
		} else {
			assert.Equal(s.T(), "custom:\""+fixture.Actions[i].Custom+"\"", a.String())
		}
	}
}

func (s *SubjectMappingsSuite) TestGetSubjectMapping_NonExistentId_Fails() {
	sm, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, nonExistentSubjectMappingId)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), sm)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestListSubjectMappings() {
	list, err := s.db.PolicyClient.ListSubjectMappings(s.ctx)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), list)

	fixture1 := s.f.GetSubjectMappingKey("subject_mapping_subject_attribute1")
	found1 := false
	fixture2 := s.f.GetSubjectMappingKey("subject_mapping_subject_attribute2")
	found2 := false
	fixture3 := s.f.GetSubjectMappingKey("subject_mapping_subject_attribute3")
	found3 := false
	assert.GreaterOrEqual(s.T(), len(list), 3)

	assertEqual := func(sm *subjectmapping.SubjectMapping, fixture fixtures.FixtureDataSubjectMapping) {
		assert.Equal(s.T(), fixture.AttributeValueId, sm.AttributeValue.Id)
		assert.True(s.T(), sm.AttributeValue.Active.Value)
		assert.Equal(s.T(), fixture.SubjectConditionSetId, sm.SubjectConditionSet.Id)
		assert.Equal(s.T(), len(fixture.Actions), len(sm.Actions))
	}
	for _, sm := range list {
		if sm.Id == fixture1.Id {
			assertEqual(sm, fixture1)
			found1 = true
		}
		if sm.Id == fixture2.Id {
			assertEqual(sm, fixture2)
			found2 = true
		}
		if sm.Id == fixture3.Id {
			assertEqual(sm, fixture3)
			found3 = true
		}
	}
	assert.True(s.T(), found1)
	assert.True(s.T(), found2)
	assert.True(s.T(), found3)
}

func (s *SubjectMappingsSuite) TestDeleteSubjectMapping() {
	// create a new subject mapping, delete it, and verify get fails with not found
	fixtureAttrValId := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value1").Id
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	aTransmit := fixtureActions[TRANSMIT]

	new := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrValId,
		Actions:                       []*authorization.Action{aTransmit},
		ExistingSubjectConditionSetId: fixtureScs.Id,
	}

	createdId, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), createdId)

	deletedId, err := s.db.PolicyClient.DeleteSubjectMapping(s.ctx, createdId)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), createdId, deletedId)

	got, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, createdId)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), got)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestDeleteSubjectMapping_WithNonExistentId_Fails() {
	deletedId, err := s.db.PolicyClient.DeleteSubjectMapping(s.ctx, nonExistentSubjectMappingId)
	assert.NotNil(s.T(), err)
	assert.Zero(s.T(), deletedId)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestDeleteSubjectMapping_DoesNotDeleteSubjectConditionSet() {
	// create a new subject mapping, delete it, and verify the subject condition set still exists
	fixtureAttrValId := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value2").Id
	newScs := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*subjectmapping.SubjectSet{
			{
				ConditionGroups: []*subjectmapping.ConditionGroup{
					{
						BooleanOperator: subjectmapping.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
						Conditions: []*subjectmapping.Condition{
							{
								SubjectExternalField:  "idp_field",
								Operator:              subjectmapping.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								SubjectExternalValues: []string{"idp_value"},
							},
						},
					},
				},
			},
		},
	}
	aTransmit := fixtureActions[TRANSMIT]

	new := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:       fixtureAttrValId,
		Actions:                []*authorization.Action{aTransmit},
		NewSubjectConditionSet: newScs,
	}

	createdId, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), createdId)

	sm, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, createdId)
	assert.Nil(s.T(), err)
	deletedId, err := s.db.PolicyClient.DeleteSubjectMapping(s.ctx, sm.Id)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), deletedId)

	scs, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, sm.SubjectConditionSet.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), scs)
	assert.Equal(s.T(), sm.SubjectConditionSet.Id, scs.Id)
}

/*--------------------------------------------------------
 *----------------- SubjectConditionSets -----------------
 *-------------------------------------------------------*/

func (s *SubjectMappingsSuite) TestCreateSubjectConditionSet() {
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
}

func (s *SubjectMappingsSuite) TestGetSubjectConditionSet_ById() {
	fixture := s.f.GetSubjectConditionSetKey("subject_condition_set1")

	scs, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, fixture.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), scs)
	assert.Equal(s.T(), fixture.Id, scs.Id)
}

func (s *SubjectMappingsSuite) TestGetSubjectConditionSet_WithNoId_Fails() {
	scs, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, "")
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), scs)
	assert.ErrorIs(s.T(), err, db.ErrUuidInvalid)
}

func (s *SubjectMappingsSuite) TestGetSubjectConditionSet_NonExistentId_Fails() {
	scs, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, nonExistentSubjectSetId)
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
	fixture4 := s.f.GetSubjectConditionSetKey("subject_condition_simple_in")
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
	}

	created, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), created)

	deletedId, err := s.db.PolicyClient.DeleteSubjectConditionSet(s.ctx, created.Id)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), created.Id, deletedId)

	got, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, created.Id)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), got)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestDeleteSubjectConditionSet_WithNonExistentId_Fails() {
	deletedId, err := s.db.PolicyClient.DeleteSubjectConditionSet(s.ctx, nonExistentSubjectSetId)
	assert.NotNil(s.T(), err)
	assert.Zero(s.T(), deletedId)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestUpdateSubjectConditionSet_NewSubjectSets() {
	// create a new one, update nothing but the subject sets, and verify the solo update
	new := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*subjectmapping.SubjectSet{
			{},
		},
	}

	created, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), created)

	// update the subject condition set
	ss := []*subjectmapping.SubjectSet{
		{
			ConditionGroups: []*subjectmapping.ConditionGroup{
				{
					BooleanOperator: subjectmapping.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
					Conditions: []*subjectmapping.Condition{
						{
							SubjectExternalField:  "origin",
							Operator:              subjectmapping.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN,
							SubjectExternalValues: []string{"USA", "Canada"},
						},
					},
				},
			},
		},
	}

	update := &subjectmapping.UpdateSubjectConditionSetRequest{
		UpdateSubjectSets: ss,
		Id:                created.Id,
	}

	id, err := s.db.PolicyClient.UpdateSubjectConditionSet(s.ctx, update)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), created.Id, id)

	// verify the subject condition set was updated
	got, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, created.Id)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), created.Id, got.Id)
	assert.Equal(s.T(), len(ss), len(got.SubjectSets))
	assert.Equal(s.T(), ss[0].ConditionGroups[0].Conditions[0].SubjectExternalField, got.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalField)
}

func (s *SubjectMappingsSuite) TestUpdateSubjectConditionSet_AllAllowedFields() {
	// create a new one, update it, and verify the update
	new := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*subjectmapping.SubjectSet{
			{},
		},
	}

	created, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), created.Id)

	// update the subject condition set
	ss := []*subjectmapping.SubjectSet{
		{
			ConditionGroups: []*subjectmapping.ConditionGroup{
				{
					BooleanOperator: subjectmapping.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
					Conditions: []*subjectmapping.Condition{
						{
							SubjectExternalField:  "somewhere",
							Operator:              subjectmapping.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN,
							SubjectExternalValues: []string{"neither here", "nor there"},
						},
					},
				},
			},
		},
	}
	metadata := &common.MetadataMutable{
		Labels: map[string]string{"key_example": "value_example"},
	}
	update := &subjectmapping.UpdateSubjectConditionSetRequest{
		UpdateSubjectSets: ss,
		UpdateMetadata:    metadata,
		Id:                created.Id,
	}

	id, err := s.db.PolicyClient.UpdateSubjectConditionSet(s.ctx, update)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), created.Id, id)

	// verify the subject condition set was updated
	got, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, created.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), created.Id, got.Id)
	assert.Equal(s.T(), len(ss), len(got.SubjectSets))
	assert.Equal(s.T(), ss[0].ConditionGroups[0].Conditions[0].SubjectExternalField, got.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalField)
	assert.Equal(s.T(), metadata.Labels["key_example"], got.Metadata.Labels["key_example"])
}

func (s *SubjectMappingsSuite) TestUpdateSubjectConditionSet_NonExistentId_Fails() {
	update := &subjectmapping.UpdateSubjectConditionSetRequest{
		Id: nonExistentSubjectSetId,
	}

	id, err := s.db.PolicyClient.UpdateSubjectConditionSet(s.ctx, update)
	assert.NotNil(s.T(), err)
	assert.Zero(s.T(), id)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestGetSubjectEntitlements_InOne() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set1")
	externalField := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalField
	externalValues := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalValues

	props := []*subjectmapping.SubjectProperty{
		{
			ExternalField: externalField,
			ExternalValue: externalValues[0],
		},
	}

	sm, err := s.db.PolicyClient.GetSubjectEntitlements(s.ctx, props)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), sm)
	assert.Equal(s.T(), fixtureScs.Id, sm[0].SubjectConditionSet.Id)
}

func (s *SubjectMappingsSuite) TestGetSubjectEntitlements_DoesNotReturnNotInWhenMatches() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_simple_not_in")
	externalField := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalField
	externalValues := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalValues

	props := []*subjectmapping.SubjectProperty{
		{
			ExternalField: externalField,
			ExternalValue: externalValues[0],
		},
	}

	smList, err := s.db.PolicyClient.GetSubjectEntitlements(s.ctx, props)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), smList)
	assert.Equal(s.T(), 0, len(smList))
}

func (s *SubjectMappingsSuite) TestGetSubjectEntitlements_NotInOneMatch() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_simple_not_in")
	externalField := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalField

	expectedMappedFixture := s.f.GetSubjectMappingKey("subject_mapping_subject_simple_not_in")

	props := []*subjectmapping.SubjectProperty{
		{
			ExternalField: externalField,
			ExternalValue: "random_value",
		},
	}

	smList, err := s.db.PolicyClient.GetSubjectEntitlements(s.ctx, props)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), smList)
	assert.Equal(s.T(), 1, len(smList))
	assert.Equal(s.T(), fixtureScs.Id, smList[0].SubjectConditionSet.Id)
	assert.Equal(s.T(), expectedMappedFixture.Id, smList[0].Id)
}

func (s *SubjectMappingsSuite) TestGetSubjectEntitlements_MissingFieldInProperty_Fails() {
	props := []*subjectmapping.SubjectProperty{
		{
			ExternalValue: "some_value",
		},
	}

	sm, err := s.db.PolicyClient.GetSubjectEntitlements(s.ctx, props)
	assert.ErrorIs(s.T(), err, db.ErrMissingRequiredValue)
	assert.Zero(s.T(), sm)
}

func (s *SubjectMappingsSuite) TestGetSubjectEntitlements_MissingValueInProperty_Fails() {
	props := []*subjectmapping.SubjectProperty{
		{
			ExternalField: "some_field",
		},
	}

	sm, err := s.db.PolicyClient.GetSubjectEntitlements(s.ctx, props)
	assert.ErrorIs(s.T(), err, db.ErrMissingRequiredValue)
	assert.Zero(s.T(), sm)
}

func (s *SubjectMappingsSuite) TestGetSubjectEntitlements_NoPropertiesProvided_Fails() {
	props := []*subjectmapping.SubjectProperty{}

	sm, err := s.db.PolicyClient.GetSubjectEntitlements(s.ctx, props)
	assert.ErrorIs(s.T(), err, db.ErrMissingRequiredValue)
	assert.Zero(s.T(), sm)
}

func (s *SubjectMappingsSuite) TestGetSubjectEntitlements_InMultiple() {
	simpleScs := s.f.GetSubjectConditionSetKey("subject_condition_simple_in")
	simpleExternalField := simpleScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalField
	simpleExternalValues := simpleScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalValues

	otherScs := s.f.GetSubjectConditionSetKey("subject_condition_set1")
	otherExternalField := otherScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalField
	otherExternalValues := otherScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalValues

	props := []*subjectmapping.SubjectProperty{
		{
			ExternalField: simpleExternalField,
			ExternalValue: simpleExternalValues[0],
		},
		{
			ExternalField: otherExternalField,
			ExternalValue: otherExternalValues[0],
		},
	}

	gotEntitlements, err := s.db.PolicyClient.GetSubjectEntitlements(s.ctx, props)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), gotEntitlements)
	assert.GreaterOrEqual(s.T(), len(gotEntitlements), 2)

	mappedSimple := s.f.GetSubjectMappingKey("subject_mapping_subject_simple_in")
	foundMappedSimple := false
	mappedSubjectConditionSet1 := s.f.GetSubjectMappingKey("subject_mapping_subject_attribute1")
	foundMappedSubjectConditionSet1 := false

	for _, sm := range gotEntitlements {
		if sm.SubjectConditionSet.Id == mappedSimple.SubjectConditionSetId {
			foundMappedSimple = true
		} else if sm.SubjectConditionSet.Id == mappedSubjectConditionSet1.SubjectConditionSetId {
			foundMappedSubjectConditionSet1 = true
		}
	}
	assert.True(s.T(), foundMappedSimple)
	assert.True(s.T(), foundMappedSubjectConditionSet1)
}

func (s *SubjectMappingsSuite) TestGetSubjectEntitlements_NotInMultiple() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_simple_not_in")
	externalField := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalField
	expectedMappedFixture := s.f.GetSubjectMappingKey("subject_mapping_subject_simple_not_in")

	otherFixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set3")
	otherExternalField1 := otherFixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[1].SubjectExternalField
	otherExpectedMatchedFixture := s.f.GetSubjectMappingKey("subject_mapping_subject_attribute3")

	props := []*subjectmapping.SubjectProperty{
		{
			ExternalField: externalField,
			ExternalValue: "random_value_definitely_not_in_fixtures",
		},
		{
			ExternalField: otherExternalField1,
			ExternalValue: "random_value_definitely_not_in_fixtures",
		},
	}

	smList, err := s.db.PolicyClient.GetSubjectEntitlements(s.ctx, props)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), smList)
	assert.Equal(s.T(), 2, len(smList))
	for _, sm := range smList {
		if sm.SubjectConditionSet.Id == fixtureScs.Id {
			assert.Equal(s.T(), expectedMappedFixture.Id, sm.Id)
		} else if sm.SubjectConditionSet.Id == otherFixtureScs.Id {
			assert.Equal(s.T(), otherExpectedMatchedFixture.Id, sm.Id)
		}
	}
}

func (s *SubjectMappingsSuite) TestGetSubjectEntitlements_InOneAndNotInASecond() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_simple_in")
	externalField := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalField
	externalValues := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalValues
	expectedMappedFixture := s.f.GetSubjectMappingKey("subject_mapping_subject_simple_in")

	otherFixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_simple_not_in")
	otherExternalField := otherFixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalField
	expectedMappedOtherFixture := s.f.GetSubjectMappingKey("subject_mapping_subject_simple_not_in")

	props := []*subjectmapping.SubjectProperty{
		{
			ExternalField: externalField,
			ExternalValue: externalValues[0],
		},
		{
			ExternalField: otherExternalField,
			ExternalValue: "random_value_987654321",
		},
	}

	smList, err := s.db.PolicyClient.GetSubjectEntitlements(s.ctx, props)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), smList)
	for _, sm := range smList {
		if sm.SubjectConditionSet.Id == fixtureScs.Id {
			assert.Equal(s.T(), expectedMappedFixture.Id, sm.Id)
		} else if sm.SubjectConditionSet.Id == otherFixtureScs.Id {
			assert.Equal(s.T(), expectedMappedOtherFixture.Id, sm.Id)
		}
	}
}

func (s *SubjectMappingsSuite) TestGetSubjectEntitlements_NonExistentField_ReturnsNoMappings() {
	props := []*subjectmapping.SubjectProperty{
		{
			ExternalField: "non_existent_field",
			ExternalValue: "non_existent_value",
		},
	}
	sm, err := s.db.PolicyClient.GetSubjectEntitlements(s.ctx, props)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), sm)
	assert.Equal(s.T(), 0, len(sm))
}

func TestSubjectMappingSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subject_mappings integration tests")
	}
	suite.Run(t, new(SubjectMappingsSuite))
}
