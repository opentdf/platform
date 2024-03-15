package integration

import (
	"context"
	"log/slog"
	"testing"

	"github.com/opentdf/platform/internal/db"
	"github.com/opentdf/platform/internal/fixtures"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SubjectMappingsSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context
}

func (s *SubjectMappingsSuite) SetupSuite() {
	slog.Info("setting up db.SubjectMappings test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_subject_mappings"
	s.db = fixtures.NewDBInterface(c)
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

	fixtureActions = map[string]*policy.Action{
		"DECRYPT": {
			Value: &policy.Action_Standard{
				Standard: policy.Action_STANDARD_ACTION_DECRYPT,
			},
		},
		"TRANSMIT": {
			Value: &policy.Action_Standard{
				Standard: policy.Action_STANDARD_ACTION_TRANSMIT,
			},
		},
		"CUSTOM_DOWNLOAD": {
			Value: &policy.Action_Custom{
				Custom: "DOWNLOAD",
			},
		},
		"CUSTOM_UPLOAD": {
			Value: &policy.Action_Custom{
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
		Actions:                       []*policy.Action{aDecrypt, aTransmit},
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), created)

	// verify the subject mapping was created
	sm, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, created.Id)
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
		SubjectSets: []*policy.SubjectSet{
			{
				ConditionGroups: []*policy.ConditionGroup{
					{
						BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
						Conditions: []*policy.Condition{
							{
								SubjectExternalField:  "email",
								Operator:              policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
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
		Actions:                []*policy.Action{aTransmit},
		NewSubjectConditionSet: scs,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), created)

	// verify the new subject condition set created was returned properly
	sm, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, created.Id)
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

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), created)
	assert.ErrorIs(s.T(), err, db.ErrMissingValue)
}

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_NonExistentAttributeValueId_Fails() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	aTransmit := fixtureActions[TRANSMIT]
	new := &subjectmapping.CreateSubjectMappingRequest{
		Actions:                       []*policy.Action{aTransmit},
		ExistingSubjectConditionSetId: fixtureScs.Id,
		AttributeValueId:              nonExistentAttributeValueUuid,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), created)
	assert.ErrorIs(s.T(), err, db.ErrForeignKeyViolation)
}

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_NonExistentSubjectConditionSetId_Fails() {
	fixtureAttrVal := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value1")
	aTransmit := fixtureActions[TRANSMIT]
	new := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrVal.Id,
		Actions:                       []*policy.Action{aTransmit},
		ExistingSubjectConditionSetId: nonExistentSubjectSetId,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), created)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestUpdateSubjectMapping_Actions() {
	// create a new one, update it, and verify the update
	fixtureAttrValId := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value2").Id
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set3")
	aTransmit := fixtureActions[TRANSMIT]
	aCustomUpload := fixtureActions[CUSTOM_UPLOAD]

	new := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrValId,
		Actions:                       []*policy.Action{aTransmit, aCustomUpload},
		ExistingSubjectConditionSetId: fixtureScs.Id,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), created)

	// update the subject mapping
	newActions := []*policy.Action{aTransmit}
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id:      created.Id,
		Actions: newActions,
	}

	updated, err := s.db.PolicyClient.UpdateSubjectMapping(s.ctx, update)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updated)
	assert.Equal(s.T(), created.Id, updated.Id)

	// verify the actions were updated but nothing else
	got, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, created.Id)
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
		Actions:                       []*policy.Action{aTransmit},
		ExistingSubjectConditionSetId: fixtureScs.Id,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), created)

	// update the subject mapping
	newScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id:                    created.Id,
		SubjectConditionSetId: newScs.Id,
	}

	updated, err := s.db.PolicyClient.UpdateSubjectMapping(s.ctx, update)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updated)
	assert.Equal(s.T(), created.Id, updated.Id)

	// verify the subject condition set was updated but nothing else
	got, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, created.Id)
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
		Actions:                       []*policy.Action{aTransmit},
		ExistingSubjectConditionSetId: fixtureScs.Id,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), created)

	// update the subject mapping
	newScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	newActions := []*policy.Action{fixtureActions[CUSTOM_DOWNLOAD]}
	metadata := &common.MetadataMutable{
		Labels: map[string]string{"key": "value"},
	}
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id:                     created.Id,
		SubjectConditionSetId:  newScs.Id,
		Actions:                newActions,
		Metadata:               metadata,
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	}

	updated, err := s.db.PolicyClient.UpdateSubjectMapping(s.ctx, update)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updated)
	assert.Equal(s.T(), created.Id, updated.Id)

	// verify the subject mapping was updated
	got, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, created.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), created.Id, got.Id)
	assert.Equal(s.T(), new.AttributeValueId, got.AttributeValue.Id)
	assert.Equal(s.T(), newScs.Id, got.SubjectConditionSet.Id)
	assert.Equal(s.T(), len(newActions), len(got.Actions))
	assert.Equal(s.T(), newActions, got.GetActions())
	assert.Equal(s.T(), metadata.Labels["key"], got.Metadata.Labels["key"])
}

func (s *SubjectMappingsSuite) TestUpdateSubjectMapping_NonExistentId_Fails() {
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id: nonExistentSubjectMappingId,
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{"key": "value"},
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE,
	}

	sm, err := s.db.PolicyClient.UpdateSubjectMapping(s.ctx, update)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), sm)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestUpdateSubjectMapping_NonExistentSubjectConditionSetId_Fails() {
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id:                    s.f.GetSubjectMappingKey("subject_mapping_subject_attribute3").Id,
		SubjectConditionSetId: nonExistentSubjectSetId,
	}

	sm, err := s.db.PolicyClient.UpdateSubjectMapping(s.ctx, update)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), sm)
	assert.ErrorIs(s.T(), err, db.ErrForeignKeyViolation)
}

func (s *SubjectMappingsSuite) TestGetSubjectMapping() {
	fixture := s.f.GetSubjectMappingKey("subject_mapping_subject_attribute2")

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
	got, err := s.db.PolicyClient.GetAttributeValue(s.ctx, fixture.AttributeValueId)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), fixture.AttributeValueId, got.Id)
	assert.True(s.T(), len(got.Members) > 0)
	equalMembers(s.T(), got, sm.AttributeValue, false)
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

	assertEqual := func(sm *policy.SubjectMapping, fixture fixtures.FixtureDataSubjectMapping) {
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
		Actions:                       []*policy.Action{aTransmit},
		ExistingSubjectConditionSetId: fixtureScs.Id,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), created)

	deleted, err := s.db.PolicyClient.DeleteSubjectMapping(s.ctx, created.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), deleted)

	got, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, created.Id)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), got)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestDeleteSubjectMapping_WithNonExistentId_Fails() {
	deleted, err := s.db.PolicyClient.DeleteSubjectMapping(s.ctx, nonExistentSubjectMappingId)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), deleted)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestDeleteSubjectMapping_DoesNotDeleteSubjectConditionSet() {
	// create a new subject mapping, delete it, and verify the subject condition set still exists
	fixtureAttrValId := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value2").Id
	newScs := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{
				ConditionGroups: []*policy.ConditionGroup{
					{
						BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
						Conditions: []*policy.Condition{
							{
								SubjectExternalField:  "idp_field",
								Operator:              policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
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
		Actions:                []*policy.Action{aTransmit},
		NewSubjectConditionSet: newScs,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), created)

	sm, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, created.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), sm)
	deleted, err := s.db.PolicyClient.DeleteSubjectMapping(s.ctx, sm.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), deleted)
	assert.NotZero(s.T(), deleted.Id)

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
		SubjectSets: []*policy.SubjectSet{
			{
				ConditionGroups: []*policy.ConditionGroup{
					{
						BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
						Conditions: []*policy.Condition{
							{
								SubjectExternalField:  "some_field",
								Operator:              policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN,
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
		SubjectSets: []*policy.SubjectSet{},
	}

	created, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), created)

	deleted, err := s.db.PolicyClient.DeleteSubjectConditionSet(s.ctx, created.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), deleted)
	assert.Equal(s.T(), created.Id, deleted.Id)

	got, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, created.Id)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), got)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestDeleteSubjectConditionSet_WithNonExistentId_Fails() {
	deleted, err := s.db.PolicyClient.DeleteSubjectConditionSet(s.ctx, nonExistentSubjectSetId)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), deleted)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestUpdateSubjectConditionSet_NewSubjectSets() {
	// create a new one, update nothing but the subject sets, and verify the solo update
	new := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{},
		},
	}

	created, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), created)

	// update the subject condition set
	ss := []*policy.SubjectSet{
		{
			ConditionGroups: []*policy.ConditionGroup{
				{
					BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
					Conditions: []*policy.Condition{
						{
							SubjectExternalField:  "origin",
							Operator:              policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN,
							SubjectExternalValues: []string{"USA", "Canada"},
						},
					},
				},
			},
		},
	}

	update := &subjectmapping.UpdateSubjectConditionSetRequest{
		SubjectSets:            ss,
		Id:                     created.Id,
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE,
	}

	updated, err := s.db.PolicyClient.UpdateSubjectConditionSet(s.ctx, update)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updated)
	assert.Equal(s.T(), created.Id, updated.Id)

	// verify the subject condition set was updated
	got, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, created.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), created.Id, got.Id)
	assert.Equal(s.T(), len(ss), len(got.SubjectSets))
	assert.Equal(s.T(), ss[0].ConditionGroups[0].Conditions[0].SubjectExternalField, got.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalField)
}

func (s *SubjectMappingsSuite) TestUpdateSubjectConditionSet_AllAllowedFields() {
	// create a new one, update it, and verify the update
	new := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{},
		},
	}

	created, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, new)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), created)

	// update the subject condition set
	ss := []*policy.SubjectSet{
		{
			ConditionGroups: []*policy.ConditionGroup{
				{
					BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
					Conditions: []*policy.Condition{
						{
							SubjectExternalField:  "somewhere",
							Operator:              policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN,
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
		SubjectSets:            ss,
		Metadata:               metadata,
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE,
		Id:                     created.Id,
	}

	updated, err := s.db.PolicyClient.UpdateSubjectConditionSet(s.ctx, update)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updated)
	assert.Equal(s.T(), created.Id, updated.Id)

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
		Id:          nonExistentSubjectSetId,
		SubjectSets: []*policy.SubjectSet{},
	}

	updated, err := s.db.PolicyClient.UpdateSubjectConditionSet(s.ctx, update)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), updated)
	assert.ErrorIs(s.T(), err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_InOne() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set1")
	externalField := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalField
	externalValues := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalValues

	props := []*policy.SubjectProperty{
		{
			ExternalField: externalField,
			ExternalValue: externalValues[0],
		},
	}

	sm, err := s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), sm)
	assert.Equal(s.T(), fixtureScs.Id, sm[0].SubjectConditionSet.Id)
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_DoesNotReturnNotInWhenMatches() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_simple_not_in")
	externalField := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalField
	externalValues := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalValues

	props := []*policy.SubjectProperty{
		{
			ExternalField: externalField,
			ExternalValue: externalValues[0],
		},
	}

	smList, err := s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), smList)
	assert.Equal(s.T(), 0, len(smList))
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_NotInOneMatch() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_simple_not_in")
	externalField := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalField

	expectedMappedFixture := s.f.GetSubjectMappingKey("subject_mapping_subject_simple_not_in")

	props := []*policy.SubjectProperty{
		{
			ExternalField: externalField,
			ExternalValue: "random_value",
		},
	}

	smList, err := s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), smList)
	assert.Equal(s.T(), 1, len(smList))
	assert.Equal(s.T(), fixtureScs.Id, smList[0].SubjectConditionSet.Id)
	assert.Equal(s.T(), expectedMappedFixture.Id, smList[0].Id)
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_MissingFieldInProperty_Fails() {
	props := []*policy.SubjectProperty{
		{
			ExternalValue: "some_value",
		},
	}

	sm, err := s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
	assert.ErrorIs(s.T(), err, db.ErrMissingValue)
	assert.Zero(s.T(), sm)
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_MissingValueInProperty_Fails() {
	props := []*policy.SubjectProperty{
		{
			ExternalField: "some_field",
		},
	}

	sm, err := s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
	assert.ErrorIs(s.T(), err, db.ErrMissingValue)
	assert.Zero(s.T(), sm)
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_NoPropertiesProvided_Fails() {
	props := []*policy.SubjectProperty{}

	sm, err := s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
	assert.ErrorIs(s.T(), err, db.ErrMissingValue)
	assert.Zero(s.T(), sm)
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_InMultiple() {
	simpleScs := s.f.GetSubjectConditionSetKey("subject_condition_simple_in")
	simpleExternalField := simpleScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalField
	simpleExternalValues := simpleScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalValues

	otherScs := s.f.GetSubjectConditionSetKey("subject_condition_set1")
	otherExternalField := otherScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalField
	otherExternalValues := otherScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalValues

	props := []*policy.SubjectProperty{
		{
			ExternalField: simpleExternalField,
			ExternalValue: simpleExternalValues[0],
		},
		{
			ExternalField: otherExternalField,
			ExternalValue: otherExternalValues[0],
		},
	}

	gotEntitlements, err := s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
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

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_NotInMultiple() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_simple_not_in")
	externalField := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalField
	expectedMappedFixture := s.f.GetSubjectMappingKey("subject_mapping_subject_simple_not_in")

	otherFixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set3")
	otherExternalField1 := otherFixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[1].SubjectExternalField
	otherExpectedMatchedFixture := s.f.GetSubjectMappingKey("subject_mapping_subject_attribute3")

	props := []*policy.SubjectProperty{
		{
			ExternalField: externalField,
			ExternalValue: "random_value_definitely_not_in_fixtures",
		},
		{
			ExternalField: otherExternalField1,
			ExternalValue: "random_value_definitely_not_in_fixtures",
		},
	}

	smList, err := s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
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

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_InOneAndNotInASecond() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_simple_in")
	externalField := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalField
	externalValues := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalValues
	expectedMappedFixture := s.f.GetSubjectMappingKey("subject_mapping_subject_simple_in")

	otherFixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_simple_not_in")
	otherExternalField := otherFixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalField
	expectedMappedOtherFixture := s.f.GetSubjectMappingKey("subject_mapping_subject_simple_not_in")

	props := []*policy.SubjectProperty{
		{
			ExternalField: externalField,
			ExternalValue: externalValues[0],
		},
		{
			ExternalField: otherExternalField,
			ExternalValue: "random_value_987654321",
		},
	}

	smList, err := s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
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

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_NonExistentField_ReturnsNoMappings() {
	props := []*policy.SubjectProperty{
		{
			ExternalField: "non_existent_field",
			ExternalValue: "non_existent_value",
		},
	}
	sm, err := s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
	assert.Nil(s.T(), err)
	assert.NotZero(s.T(), sm)
	assert.Equal(s.T(), 0, len(sm))
}

func (s *SubjectMappingsSuite) TestUpdateSubjectConditionSet_MetadataVariations() {
	fixedLabel := "fixed label"
	updateLabel := "update label"
	updatedLabel := "true"
	newLabel := "new label"

	labels := map[string]string{
		"fixed":  fixedLabel,
		"update": updateLabel,
	}
	updateLabels := map[string]string{
		"update": updatedLabel,
		"new":    newLabel,
	}
	expectedLabels := map[string]string{
		"fixed":  fixedLabel,
		"update": updatedLabel,
		"new":    newLabel,
	}

	created, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{},
		},
		Metadata: &common.MetadataMutable{
			Labels: labels,
		},
	})
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), created)

	// update with no changes
	updatedWithoutChange, err := s.db.PolicyClient.UpdateSubjectConditionSet(s.ctx, &subjectmapping.UpdateSubjectConditionSetRequest{
		Id: created.Id,
	})
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updatedWithoutChange)
	assert.Equal(s.T(), created.Id, updatedWithoutChange.Id)

	// update with changes
	updatedWithChange, err := s.db.PolicyClient.UpdateSubjectConditionSet(s.ctx, &subjectmapping.UpdateSubjectConditionSetRequest{
		Id:                     created.Id,
		Metadata:               &common.MetadataMutable{Labels: updateLabels},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updatedWithChange)
	assert.Equal(s.T(), created.Id, updatedWithChange.Id)

	// verify the metadata was extended
	got, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, created.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), created.Id, got.Id)
	assert.Equal(s.T(), expectedLabels, got.Metadata.Labels)

	// update with replace
	updatedWithReplace, err := s.db.PolicyClient.UpdateSubjectConditionSet(s.ctx, &subjectmapping.UpdateSubjectConditionSetRequest{
		Id:                     created.Id,
		Metadata:               &common.MetadataMutable{Labels: labels},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE,
	})
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), updatedWithReplace)
	assert.Equal(s.T(), created.Id, updatedWithReplace.Id)

	// verify the metadata was replaced
	got, err = s.db.PolicyClient.GetSubjectConditionSet(s.ctx, created.Id)
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), got)
	assert.Equal(s.T(), created.Id, got.Id)
	assert.Equal(s.T(), labels, got.Metadata.Labels)
}

func TestSubjectMappingSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subject_mappings integration tests")
	}
	suite.Run(t, new(SubjectMappingsSuite))
}
