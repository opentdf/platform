package integration

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	"github.com/stretchr/testify/suite"
)

type SubjectMappingsSuite struct {
	suite.Suite
	f  fixtures.Fixtures
	db fixtures.DBInterface
}

func (s *SubjectMappingsSuite) SetupSuite() {
	slog.Info("setting up db.SubjectMappings test suite")
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

	nonExistentSubjectSetID     = "9f9f3282-ffff-1111-924a-7b8eb43d5423"
	nonExistentSubjectMappingID = "32977f0b-f2b9-44b5-8afd-e2e224ea8352"
)

/*--------------------------------------------------------
 *-------------------- SubjectMappings -------------------
 *-------------------------------------------------------*/

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_ExistingSubjectConditionSetId() {
	fixtureAttrValID := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value2").Id
	fixtureSCSId := s.f.GetSubjectConditionSetKey("subject_condition_set1").Id

	aDecrypt := fixtureActions[DECRYPT]
	aTransmit := fixtureActions[TRANSMIT]
	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrValID,
		ExistingSubjectConditionSetId: fixtureSCSId,
		Actions:                       []*policy.Action{aDecrypt, aTransmit},
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(context.Background(), newSubjectMapping)
	s.Require().NoError(err)
	s.NotNil(created)

	// verify the subject mapping was created
	sm, err := s.db.PolicyClient.GetSubjectMapping(context.Background(), created.GetId())
	s.Require().NoError(err)
	s.Equal(newSubjectMapping.GetAttributeValueId(), sm.GetAttributeValue().GetId())
	s.Equal(newSubjectMapping.GetExistingSubjectConditionSetId(), sm.GetSubjectConditionSet().GetId())
	s.Len(sm.GetActions(), 2)
	s.Equal(sm.GetActions(), newSubjectMapping.GetActions())
}

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_NewSubjectConditionSet() {
	fixtureAttrValID := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value2").Id
	aTransmit := fixtureActions[TRANSMIT]

	scs := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{
				ConditionGroups: []*policy.ConditionGroup{
					{
						BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
						Conditions: []*policy.Condition{
							{
								SubjectExternalSelectorValue: ".email",
								Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								SubjectExternalValues:        []string{"hello@email.com"},
							},
						},
					},
				},
			},
		},
	}

	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:       fixtureAttrValID,
		Actions:                []*policy.Action{aTransmit},
		NewSubjectConditionSet: scs,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(context.Background(), newSubjectMapping)
	s.Require().NoError(err)
	s.NotNil(created)

	// verify the new subject condition set created was returned properly
	sm, err := s.db.PolicyClient.GetSubjectMapping(context.Background(), created.GetId())
	s.Require().NoError(err)
	s.NotNil(sm.GetSubjectConditionSet())
	s.Equal(len(scs.GetSubjectSets()), len(sm.GetSubjectConditionSet().GetSubjectSets()))

	expectedCGroups := scs.GetSubjectSets()[0].GetConditionGroups()
	gotCGroups := sm.GetSubjectConditionSet().GetSubjectSets()[0].GetConditionGroups()
	s.Equal(len(expectedCGroups), len(gotCGroups))
	s.Equal(len(expectedCGroups[0].GetConditions()), len(gotCGroups[0].GetConditions()))

	expectedCondition := expectedCGroups[0].GetConditions()[0]
	gotCondition := sm.GetSubjectConditionSet().GetSubjectSets()[0].GetConditionGroups()[0].GetConditions()[0]
	s.Equal(expectedCondition.GetSubjectExternalSelectorValue(), gotCondition.GetSubjectExternalSelectorValue())
	s.Equal(expectedCondition.GetOperator(), gotCondition.GetOperator())
	s.Equal(expectedCondition.GetSubjectExternalValues(), gotCondition.GetSubjectExternalValues())
}

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_NoActions_Fails() {
	fixtureAttrVal := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value1")
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrVal.Id,
		ExistingSubjectConditionSetId: fixtureScs.Id,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(context.Background(), newSubjectMapping)
	s.Require().Error(err)
	s.Nil(created)
	s.ErrorIs(err, db.ErrMissingValue)
}

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_NonExistentAttributeValueId_Fails() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	aTransmit := fixtureActions[TRANSMIT]
	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		Actions:                       []*policy.Action{aTransmit},
		ExistingSubjectConditionSetId: fixtureScs.Id,
		AttributeValueId:              nonExistentAttributeValueUUID,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(context.Background(), newSubjectMapping)
	s.Require().Error(err)
	s.Nil(created)
	s.ErrorIs(err, db.ErrForeignKeyViolation)
}

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_NonExistentSubjectConditionSetId_Fails() {
	fixtureAttrVal := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value1")
	aTransmit := fixtureActions[TRANSMIT]
	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrVal.Id,
		Actions:                       []*policy.Action{aTransmit},
		ExistingSubjectConditionSetId: nonExistentSubjectSetID,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(context.Background(), newSubjectMapping)
	s.Require().Error(err)
	s.Nil(created)
	s.ErrorIs(err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestUpdateSubjectMapping_Actions() {
	// create a new one, update it, and verify the update
	fixtureAttrValID := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value2").Id
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set3")
	aTransmit := fixtureActions[TRANSMIT]
	aCustomUpload := fixtureActions[CUSTOM_UPLOAD]

	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrValID,
		Actions:                       []*policy.Action{aTransmit, aCustomUpload},
		ExistingSubjectConditionSetId: fixtureScs.Id,
	}
	start := time.Now().Add(-time.Second)
	created, err := s.db.PolicyClient.CreateSubjectMapping(context.Background(), newSubjectMapping)
	end := time.Now().Add(time.Second)
	metadata := created.GetMetadata()
	updatedAt := metadata.GetUpdatedAt()
	createdAt := metadata.GetCreatedAt()
	s.True(createdAt.AsTime().After(start))
	s.True(createdAt.AsTime().Before(end))
	s.Require().NoError(err)
	s.NotNil(created)

	// update the subject mapping
	newActions := []*policy.Action{aTransmit}
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id:      created.GetId(),
		Actions: newActions,
	}

	updated, err := s.db.PolicyClient.UpdateSubjectMapping(context.Background(), update)
	s.Require().NoError(err)
	s.NotNil(updated)
	s.Equal(created.GetId(), updated.GetId())

	// verify the actions were updated but nothing else
	got, err := s.db.PolicyClient.GetSubjectMapping(context.Background(), created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(len(newActions), len(got.GetActions()))
	s.Equal(got.GetActions(), newActions)
	s.Equal(newSubjectMapping.GetAttributeValueId(), got.GetAttributeValue().GetId())
	s.Equal(newSubjectMapping.GetExistingSubjectConditionSetId(), got.GetSubjectConditionSet().GetId())
	s.True(got.GetMetadata().GetUpdatedAt().AsTime().After(updatedAt.AsTime()))
}

func (s *SubjectMappingsSuite) TestUpdateSubjectMapping_SubjectConditionSetId() {
	// create a new one, update it, and verify the update
	fixtureAttrValID := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value1").Id
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set1")
	aTransmit := fixtureActions[TRANSMIT]

	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrValID,
		Actions:                       []*policy.Action{aTransmit},
		ExistingSubjectConditionSetId: fixtureScs.Id,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(context.Background(), newSubjectMapping)
	s.Require().NoError(err)
	s.NotNil(created)

	// update the subject mapping
	newScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id:                    created.GetId(),
		SubjectConditionSetId: newScs.Id,
	}

	updated, err := s.db.PolicyClient.UpdateSubjectMapping(context.Background(), update)
	s.Require().NoError(err)
	s.NotNil(updated)
	s.Equal(created.GetId(), updated.GetId())

	// verify the subject condition set was updated but nothing else
	got, err := s.db.PolicyClient.GetSubjectMapping(context.Background(), created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(newSubjectMapping.GetAttributeValueId(), got.GetAttributeValue().GetId())
	s.Equal(newScs.Id, got.GetSubjectConditionSet().GetId())
	s.Equal(len(newSubjectMapping.GetActions()), len(got.GetActions()))
	s.Equal(newSubjectMapping.GetActions(), got.GetActions())
}

func (s *SubjectMappingsSuite) TestUpdateSubjectMapping_UpdateAllAllowedFields() {
	// create a new one, update it, and verify the update
	fixtureAttrValID := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value1").Id
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set1")
	aTransmit := fixtureActions[TRANSMIT]

	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrValID,
		Actions:                       []*policy.Action{aTransmit},
		ExistingSubjectConditionSetId: fixtureScs.Id,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(context.Background(), newSubjectMapping)
	s.Require().NoError(err)
	s.NotNil(created)

	// update the subject mapping
	newScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	newActions := []*policy.Action{fixtureActions[CUSTOM_DOWNLOAD]}
	metadata := &common.MetadataMutable{
		Labels: map[string]string{"key": "value"},
	}
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id:                     created.GetId(),
		SubjectConditionSetId:  newScs.Id,
		Actions:                newActions,
		Metadata:               metadata,
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	}

	updated, err := s.db.PolicyClient.UpdateSubjectMapping(context.Background(), update)
	s.Require().NoError(err)
	s.NotNil(updated)
	s.Equal(created.GetId(), updated.GetId())

	// verify the subject mapping was updated
	got, err := s.db.PolicyClient.GetSubjectMapping(context.Background(), created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Equal(newSubjectMapping.GetAttributeValueId(), got.GetAttributeValue().GetId())
	s.Equal(newScs.Id, got.GetSubjectConditionSet().GetId())
	s.Equal(len(newActions), len(got.GetActions()))
	s.Equal(newActions, got.GetActions())
	s.Equal(metadata.GetLabels()["key"], got.GetMetadata().GetLabels()["key"])
}

func (s *SubjectMappingsSuite) TestUpdateSubjectMapping_NonExistentId_Fails() {
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id: nonExistentSubjectMappingID,
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{"key": "value"},
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE,
	}

	sm, err := s.db.PolicyClient.UpdateSubjectMapping(context.Background(), update)
	s.Require().Error(err)
	s.Nil(sm)
	s.ErrorIs(err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestUpdateSubjectMapping_NonExistentSubjectConditionSetId_Fails() {
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id:                    s.f.GetSubjectMappingKey("subject_mapping_subject_attribute3").Id,
		SubjectConditionSetId: nonExistentSubjectSetID,
	}

	sm, err := s.db.PolicyClient.UpdateSubjectMapping(context.Background(), update)
	s.Require().Error(err)
	s.Nil(sm)
	s.ErrorIs(err, db.ErrForeignKeyViolation)
}

func (s *SubjectMappingsSuite) TestGetSubjectMapping() {
	fixture := s.f.GetSubjectMappingKey("subject_mapping_subject_attribute2")

	sm, err := s.db.PolicyClient.GetSubjectMapping(context.Background(), fixture.Id)
	s.Require().NoError(err)
	s.NotNil(sm)
	s.Equal(fixture.Id, sm.GetId())
	s.Equal(fixture.AttributeValueId, sm.GetAttributeValue().GetId())
	s.True(sm.GetAttributeValue().GetActive().GetValue())
	s.Equal(fixture.SubjectConditionSetId, sm.GetSubjectConditionSet().GetId())

	// verify the actions
	for i, a := range sm.GetActions() {
		s.NotNil(a)
		// In protos, standard actions are an enum and custom actions are a string,
		// so their string representations are slightly different
		if fixture.Actions[i].Standard != "" {
			s.Equal("standard:"+fixture.Actions[i].Standard, a.String())
		} else {
			s.Equal("custom:\""+fixture.Actions[i].Custom+"\"", a.String())
		}
	}
	got, err := s.db.PolicyClient.GetAttributeValue(context.Background(), fixture.AttributeValueId)
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(fixture.AttributeValueId, got.GetId())
	s.NotEmpty(got.GetMembers())
	equalMembers(s.T(), got, sm.GetAttributeValue(), false)
	metadata := sm.GetMetadata()
	createdAt := metadata.GetCreatedAt()
	updatedAt := metadata.GetUpdatedAt()
	s.True(createdAt.IsValid() && createdAt.AsTime().Unix() > 0)
	s.True(updatedAt.IsValid() && updatedAt.AsTime().Unix() > 0)
}

func (s *SubjectMappingsSuite) TestGetSubjectMapping_NonExistentId_Fails() {
	sm, err := s.db.PolicyClient.GetSubjectMapping(context.Background(), nonExistentSubjectMappingID)
	s.Require().Error(err)
	s.Nil(sm)
	s.ErrorIs(err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestListSubjectMappings() {
	list, err := s.db.PolicyClient.ListSubjectMappings(context.Background())
	s.Require().NoError(err)
	s.NotNil(list)

	fixture1 := s.f.GetSubjectMappingKey("subject_mapping_subject_attribute1")
	found1 := false
	fixture2 := s.f.GetSubjectMappingKey("subject_mapping_subject_attribute2")
	found2 := false
	fixture3 := s.f.GetSubjectMappingKey("subject_mapping_subject_attribute3")
	found3 := false
	s.GreaterOrEqual(len(list), 3)

	assertEqual := func(sm *policy.SubjectMapping, fixture fixtures.FixtureDataSubjectMapping) {
		s.Equal(fixture.AttributeValueId, sm.GetAttributeValue().GetId())
		s.True(sm.GetAttributeValue().GetActive().GetValue())
		s.Equal(fixture.SubjectConditionSetId, sm.GetSubjectConditionSet().GetId())
		s.Equal(len(fixture.Actions), len(sm.GetActions()))
	}
	for _, sm := range list {
		if sm.GetId() == fixture1.Id {
			assertEqual(sm, fixture1)
			found1 = true
		}
		if sm.GetId() == fixture2.Id {
			assertEqual(sm, fixture2)
			found2 = true
		}
		if sm.GetId() == fixture3.Id {
			assertEqual(sm, fixture3)
			found3 = true
		}
	}
	s.True(found1)
	s.True(found2)
	s.True(found3)
}

func (s *SubjectMappingsSuite) TestDeleteSubjectMapping() {
	// create a new subject mapping, delete it, and verify get fails with not found
	fixtureAttrValID := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value1").Id
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	aTransmit := fixtureActions[TRANSMIT]

	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrValID,
		Actions:                       []*policy.Action{aTransmit},
		ExistingSubjectConditionSetId: fixtureScs.Id,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(context.Background(), newSubjectMapping)
	s.Require().NoError(err)
	s.NotNil(created)

	deleted, err := s.db.PolicyClient.DeleteSubjectMapping(context.Background(), created.GetId())
	s.Require().NoError(err)
	s.NotNil(deleted)

	got, err := s.db.PolicyClient.GetSubjectMapping(context.Background(), created.GetId())
	s.Require().Error(err)
	s.Nil(got)
	s.ErrorIs(err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestDeleteSubjectMapping_WithNonExistentId_Fails() {
	deleted, err := s.db.PolicyClient.DeleteSubjectMapping(context.Background(), nonExistentSubjectMappingID)
	s.Require().Error(err)
	s.Nil(deleted)
	s.ErrorIs(err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestDeleteSubjectMapping_DoesNotDeleteSubjectConditionSet() {
	// create a new subject mapping, delete it, and verify the subject condition set still exists
	fixtureAttrValID := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value2").Id
	newScs := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{
				ConditionGroups: []*policy.ConditionGroup{
					{
						BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
						Conditions: []*policy.Condition{
							{
								SubjectExternalSelectorValue: ".idp_field",
								Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								SubjectExternalValues:        []string{"idp_value"},
							},
						},
					},
				},
			},
		},
	}
	aTransmit := fixtureActions[TRANSMIT]

	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:       fixtureAttrValID,
		Actions:                []*policy.Action{aTransmit},
		NewSubjectConditionSet: newScs,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(context.Background(), newSubjectMapping)
	s.Require().NoError(err)
	s.NotNil(created)

	sm, err := s.db.PolicyClient.GetSubjectMapping(context.Background(), created.GetId())
	s.Require().NoError(err)
	s.NotNil(sm)
	deleted, err := s.db.PolicyClient.DeleteSubjectMapping(context.Background(), sm.GetId())
	s.Require().NoError(err)
	s.NotNil(deleted)
	s.NotZero(deleted.GetId())

	scs, err := s.db.PolicyClient.GetSubjectConditionSet(context.Background(), sm.GetSubjectConditionSet().GetId())
	s.Require().NoError(err)
	s.NotNil(scs)
	s.Equal(sm.GetSubjectConditionSet().GetId(), scs.GetId())
}

/*--------------------------------------------------------
 *----------------- SubjectConditionSets -----------------
 *-------------------------------------------------------*/

func (s *SubjectMappingsSuite) TestCreateSubjectConditionSet() {
	newConditionSet := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{
				ConditionGroups: []*policy.ConditionGroup{
					{
						BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
						Conditions: []*policy.Condition{
							{
								SubjectExternalSelectorValue: ".someField[1]",
								Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN,
								SubjectExternalValues:        []string{"some_value"},
							},
						},
					},
				},
			},
		},
	}

	scs, err := s.db.PolicyClient.CreateSubjectConditionSet(context.Background(), newConditionSet)
	s.Require().NoError(err)
	s.NotNil(scs)
}

func (s *SubjectMappingsSuite) TestGetSubjectConditionSet_ById() {
	fixture := s.f.GetSubjectConditionSetKey("subject_condition_set1")

	scs, err := s.db.PolicyClient.GetSubjectConditionSet(context.Background(), fixture.Id)
	s.Require().NoError(err)
	s.NotNil(scs)
	s.Equal(fixture.Id, scs.GetId())
	metadata := scs.GetMetadata()
	createdAt := metadata.GetCreatedAt()
	updatedAt := metadata.GetUpdatedAt()
	s.True(createdAt.IsValid() && createdAt.AsTime().Unix() > 0)
	s.True(updatedAt.IsValid() && updatedAt.AsTime().Unix() > 0)
}

func (s *SubjectMappingsSuite) TestGetSubjectConditionSet_WithNoId_Fails() {
	scs, err := s.db.PolicyClient.GetSubjectConditionSet(context.Background(), "")
	s.Require().Error(err)
	s.Nil(scs)
	s.ErrorIs(err, db.ErrUUIDInvalid)
}

func (s *SubjectMappingsSuite) TestGetSubjectConditionSet_NonExistentId_Fails() {
	scs, err := s.db.PolicyClient.GetSubjectConditionSet(context.Background(), nonExistentSubjectSetID)
	s.Require().Error(err)
	s.Nil(scs)
	s.ErrorIs(err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestListSubjectConditionSet() {
	list, err := s.db.PolicyClient.ListSubjectConditionSets(context.Background())
	s.Require().NoError(err)
	s.NotNil(list)

	fixture1 := s.f.GetSubjectConditionSetKey("subject_condition_set1")
	found1 := false
	fixture2 := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	found2 := false
	fixture3 := s.f.GetSubjectConditionSetKey("subject_condition_set3")
	found3 := false
	fixture4 := s.f.GetSubjectConditionSetKey("subject_condition_simple_in")
	found4 := false

	s.GreaterOrEqual(len(list), 3)
	for _, scs := range list {
		switch scs.GetId() {
		case fixture1.Id:
			found1 = true
		case fixture2.Id:
			found2 = true
		case fixture3.Id:
			found3 = true
		case fixture4.Id:
			found4 = true
		}
	}
	s.True(found1)
	s.True(found2)
	s.True(found3)
	s.True(found4)
}

func (s *SubjectMappingsSuite) TestDeleteSubjectConditionSet() {
	// create a new subject condition set, delete it, and verify get fails with not found
	newConditionSet := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{},
	}

	created, err := s.db.PolicyClient.CreateSubjectConditionSet(context.Background(), newConditionSet)
	s.Require().NoError(err)
	s.NotNil(created)

	deleted, err := s.db.PolicyClient.DeleteSubjectConditionSet(context.Background(), created.GetId())
	s.Require().NoError(err)
	s.NotNil(deleted)
	s.Equal(created.GetId(), deleted.GetId())

	got, err := s.db.PolicyClient.GetSubjectConditionSet(context.Background(), created.GetId())
	s.Require().Error(err)
	s.Nil(got)
	s.ErrorIs(err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestDeleteSubjectConditionSet_WithNonExistentId_Fails() {
	deleted, err := s.db.PolicyClient.DeleteSubjectConditionSet(context.Background(), nonExistentSubjectSetID)
	s.Require().Error(err)
	s.Nil(deleted)
	s.ErrorIs(err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestUpdateSubjectConditionSet_NewSubjectSets() {
	// create a new one, update nothing but the subject sets, and verify the solo update
	newConditionSet := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{},
		},
	}
	start := time.Now().Add(-time.Second)
	created, err := s.db.PolicyClient.CreateSubjectConditionSet(context.Background(), newConditionSet)
	end := time.Now().Add(time.Second)
	metadata := created.GetMetadata()
	updatedAt := metadata.GetUpdatedAt()
	createdAt := metadata.GetCreatedAt()
	s.True(createdAt.AsTime().After(start))
	s.True(createdAt.AsTime().Before(end))
	s.Require().NoError(err)
	s.NotNil(created)

	// update the subject condition set
	ss := []*policy.SubjectSet{
		{
			ConditionGroups: []*policy.ConditionGroup{
				{
					BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
					Conditions: []*policy.Condition{
						{
							SubjectExternalSelectorValue: ".origin.country",
							Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN,
							SubjectExternalValues:        []string{"USA", "Canada"},
						},
					},
				},
			},
		},
	}

	update := &subjectmapping.UpdateSubjectConditionSetRequest{
		SubjectSets:            ss,
		Id:                     created.GetId(),
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE,
	}

	updated, err := s.db.PolicyClient.UpdateSubjectConditionSet(context.Background(), update)
	s.Require().NoError(err)
	s.NotNil(updated)
	s.Equal(created.GetId(), updated.GetId())

	// verify the subject condition set was updated
	got, err := s.db.PolicyClient.GetSubjectConditionSet(context.Background(), created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Equal(len(ss), len(got.GetSubjectSets()))
	s.Equal(ss[0].GetConditionGroups()[0].GetConditions()[0].GetSubjectExternalSelectorValue(), got.GetSubjectSets()[0].GetConditionGroups()[0].GetConditions()[0].GetSubjectExternalSelectorValue())
	s.True(got.GetMetadata().GetUpdatedAt().AsTime().After(updatedAt.AsTime()))
}

func (s *SubjectMappingsSuite) TestUpdateSubjectConditionSet_AllAllowedFields() {
	// create a new one, update it, and verify the update
	newConditionSet := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{},
		},
	}

	created, err := s.db.PolicyClient.CreateSubjectConditionSet(context.Background(), newConditionSet)
	s.Require().NoError(err)
	s.NotNil(created)

	// update the subject condition set
	ss := []*policy.SubjectSet{
		{
			ConditionGroups: []*policy.ConditionGroup{
				{
					BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
					Conditions: []*policy.Condition{
						{
							SubjectExternalSelectorValue: ".origin",
							Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN,
							SubjectExternalValues:        []string{"neither here", "nor there"},
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
		Id:                     created.GetId(),
	}

	updated, err := s.db.PolicyClient.UpdateSubjectConditionSet(context.Background(), update)
	s.Require().NoError(err)
	s.NotNil(updated)
	s.Equal(created.GetId(), updated.GetId())

	// verify the subject condition set was updated
	got, err := s.db.PolicyClient.GetSubjectConditionSet(context.Background(), created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Equal(len(ss), len(got.GetSubjectSets()))
	s.Equal(ss[0].GetConditionGroups()[0].GetConditions()[0].GetSubjectExternalSelectorValue(), got.GetSubjectSets()[0].GetConditionGroups()[0].GetConditions()[0].GetSubjectExternalSelectorValue())
	s.Equal(metadata.GetLabels()["key_example"], got.GetMetadata().GetLabels()["key_example"])
}

func (s *SubjectMappingsSuite) TestUpdateSubjectConditionSet_NonExistentId_Fails() {
	update := &subjectmapping.UpdateSubjectConditionSetRequest{
		Id:          nonExistentSubjectSetID,
		SubjectSets: []*policy.SubjectSet{},
	}

	updated, err := s.db.PolicyClient.UpdateSubjectConditionSet(context.Background(), update)
	s.Require().Error(err)
	s.Nil(updated)
	s.ErrorIs(err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_InOne() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set1")
	externalSelectorValue := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalSelectorValue
	externalValues := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalValues

	props := []*policy.SubjectProperty{
		{
			ExternalSelectorValue: externalSelectorValue,
			ExternalValue:         externalValues[0],
		},
	}

	sm, err := s.db.PolicyClient.GetMatchedSubjectMappings(context.Background(), props)
	s.Require().NoError(err)
	s.NotZero(sm)
	s.Equal(fixtureScs.Id, sm[0].GetSubjectConditionSet().GetId())
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_DoesNotReturnNotInWhenMatches() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_simple_not_in")
	externalSelectorValue := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalSelectorValue
	externalValues := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalValues

	props := []*policy.SubjectProperty{
		{
			ExternalSelectorValue: externalSelectorValue,
			ExternalValue:         externalValues[0],
		},
	}

	smList, err := s.db.PolicyClient.GetMatchedSubjectMappings(context.Background(), props)
	s.Require().NoError(err)
	s.NotZero(smList)
	s.Empty(smList)
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_NotInOneMatch() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_simple_not_in")
	externalSelectorValue := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalSelectorValue

	expectedMappedFixture := s.f.GetSubjectMappingKey("subject_mapping_subject_simple_not_in")

	props := []*policy.SubjectProperty{
		{
			ExternalSelectorValue: externalSelectorValue,
			ExternalValue:         "random_value",
		},
	}

	smList, err := s.db.PolicyClient.GetMatchedSubjectMappings(context.Background(), props)
	s.Require().NoError(err)
	s.NotZero(smList)
	s.Require().Len(smList, 1)
	s.Equal(fixtureScs.Id, smList[0].GetSubjectConditionSet().GetId())
	s.Equal(expectedMappedFixture.Id, smList[0].GetId())
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_MissingFieldInProperty_Fails() {
	props := []*policy.SubjectProperty{
		{
			ExternalValue: "some_value",
		},
	}

	sm, err := s.db.PolicyClient.GetMatchedSubjectMappings(context.Background(), props)
	s.Require().ErrorIs(err, db.ErrMissingValue)
	s.Zero(sm)
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_MissingValueInProperty_Fails() {
	props := []*policy.SubjectProperty{
		{
			ExternalSelectorValue: ".some_field",
		},
	}

	sm, err := s.db.PolicyClient.GetMatchedSubjectMappings(context.Background(), props)
	s.Require().ErrorIs(err, db.ErrMissingValue)
	s.Zero(sm)
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_NoPropertiesProvided_Fails() {
	props := []*policy.SubjectProperty{}

	sm, err := s.db.PolicyClient.GetMatchedSubjectMappings(context.Background(), props)
	s.Require().ErrorIs(err, db.ErrMissingValue)
	s.Zero(sm)
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_InMultiple() {
	simpleScs := s.f.GetSubjectConditionSetKey("subject_condition_simple_in")
	simpleexternalSelectorValue := simpleScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalSelectorValue
	simpleExternalValues := simpleScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalValues

	otherScs := s.f.GetSubjectConditionSetKey("subject_condition_set1")
	otherexternalSelectorValue := otherScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalSelectorValue
	otherExternalValues := otherScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalValues

	props := []*policy.SubjectProperty{
		{
			ExternalSelectorValue: simpleexternalSelectorValue,
			ExternalValue:         simpleExternalValues[0],
		},
		{
			ExternalSelectorValue: otherexternalSelectorValue,
			ExternalValue:         otherExternalValues[0],
		},
	}

	gotEntitlements, err := s.db.PolicyClient.GetMatchedSubjectMappings(context.Background(), props)
	s.Require().NoError(err)
	s.NotZero(gotEntitlements)
	s.GreaterOrEqual(len(gotEntitlements), 2)

	mappedSimple := s.f.GetSubjectMappingKey("subject_mapping_subject_simple_in")
	foundMappedSimple := false
	mappedSubjectConditionSet1 := s.f.GetSubjectMappingKey("subject_mapping_subject_attribute1")
	foundMappedSubjectConditionSet1 := false

	for _, sm := range gotEntitlements {
		if sm.GetSubjectConditionSet().GetId() == mappedSimple.SubjectConditionSetId {
			foundMappedSimple = true
		} else if sm.GetSubjectConditionSet().GetId() == mappedSubjectConditionSet1.SubjectConditionSetId {
			foundMappedSubjectConditionSet1 = true
		}
	}
	s.True(foundMappedSimple)
	s.True(foundMappedSubjectConditionSet1)
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_NotInMultiple() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_simple_not_in")
	externalSelectorValue := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalSelectorValue
	expectedMappedFixture := s.f.GetSubjectMappingKey("subject_mapping_subject_simple_not_in")

	otherFixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set3")
	otherexternalSelectorValue1 := otherFixtureScs.Condition.SubjectSets[0].ConditionGroups[1].Conditions[1].SubjectExternalSelectorValue
	otherExpectedMatchedFixture := s.f.GetSubjectMappingKey("subject_mapping_subject_attribute3")

	props := []*policy.SubjectProperty{
		{
			ExternalSelectorValue: externalSelectorValue,
			ExternalValue:         "random_value_definitely_not_in_fixtures",
		},
		{
			ExternalSelectorValue: otherexternalSelectorValue1,
			ExternalValue:         "random_value_definitely_not_in_fixtures",
		},
	}

	smList, err := s.db.PolicyClient.GetMatchedSubjectMappings(context.Background(), props)
	s.Require().NoError(err)
	s.NotZero(smList)
	s.Len(smList, 2)
	for _, sm := range smList {
		if sm.GetSubjectConditionSet().GetId() == fixtureScs.Id {
			s.Equal(expectedMappedFixture.Id, sm.GetId())
		} else if sm.GetSubjectConditionSet().GetId() == otherFixtureScs.Id {
			s.Equal(otherExpectedMatchedFixture.Id, sm.GetId())
		}
	}
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_InOneAndNotInASecond() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_simple_in")
	externalSelectorValue := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalSelectorValue
	externalValues := fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalValues
	expectedMappedFixture := s.f.GetSubjectMappingKey("subject_mapping_subject_simple_in")

	otherFixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_simple_not_in")
	otherexternalSelectorValue := otherFixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalSelectorValue
	expectedMappedOtherFixture := s.f.GetSubjectMappingKey("subject_mapping_subject_simple_not_in")

	props := []*policy.SubjectProperty{
		{
			ExternalSelectorValue: externalSelectorValue,
			ExternalValue:         externalValues[0],
		},
		{
			ExternalSelectorValue: otherexternalSelectorValue,
			ExternalValue:         "random_value_987654321",
		},
	}

	smList, err := s.db.PolicyClient.GetMatchedSubjectMappings(context.Background(), props)
	s.Require().NoError(err)
	s.NotZero(smList)
	for _, sm := range smList {
		if sm.GetSubjectConditionSet().GetId() == fixtureScs.Id {
			s.Equal(expectedMappedFixture.Id, sm.GetId())
		} else if sm.GetSubjectConditionSet().GetId() == otherFixtureScs.Id {
			s.Equal(expectedMappedOtherFixture.Id, sm.GetId())
		}
	}
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_NonExistentField_ReturnsNoMappings() {
	props := []*policy.SubjectProperty{
		{
			ExternalSelectorValue: ".non_existent_field[1]",
			ExternalValue:         "non_existent_value",
		},
	}
	sm, err := s.db.PolicyClient.GetMatchedSubjectMappings(context.Background(), props)
	s.Require().NoError(err)
	s.NotZero(sm)
	s.Empty(sm)
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

	created, err := s.db.PolicyClient.CreateSubjectConditionSet(context.Background(), &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{},
		},
		Metadata: &common.MetadataMutable{
			Labels: labels,
		},
	})
	s.Require().NoError(err)
	s.NotNil(created)

	// update with no changes
	updatedWithoutChange, err := s.db.PolicyClient.UpdateSubjectConditionSet(context.Background(), &subjectmapping.UpdateSubjectConditionSetRequest{
		Id: created.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(updatedWithoutChange)
	s.Equal(created.GetId(), updatedWithoutChange.GetId())

	// update with changes
	updatedWithChange, err := s.db.PolicyClient.UpdateSubjectConditionSet(context.Background(), &subjectmapping.UpdateSubjectConditionSetRequest{
		Id:                     created.GetId(),
		Metadata:               &common.MetadataMutable{Labels: updateLabels},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	s.Require().NoError(err)
	s.NotNil(updatedWithChange)
	s.Equal(created.GetId(), updatedWithChange.GetId())

	// verify the metadata was extended
	got, err := s.db.PolicyClient.GetSubjectConditionSet(context.Background(), created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Equal(expectedLabels, got.GetMetadata().GetLabels())

	// update with replace
	updatedWithReplace, err := s.db.PolicyClient.UpdateSubjectConditionSet(context.Background(), &subjectmapping.UpdateSubjectConditionSetRequest{
		Id:                     created.GetId(),
		Metadata:               &common.MetadataMutable{Labels: labels},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE,
	})
	s.Require().NoError(err)
	s.NotNil(updatedWithReplace)
	s.Equal(created.GetId(), updatedWithReplace.GetId())

	// verify the metadata was replaced
	got, err = s.db.PolicyClient.GetSubjectConditionSet(context.Background(), created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Equal(labels, got.GetMetadata().GetLabels())
}

func TestSubjectMappingSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subject_mappings integration tests")
	}
	suite.Run(t, new(SubjectMappingsSuite))
}
