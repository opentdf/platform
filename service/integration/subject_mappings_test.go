package integration

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	policydb "github.com/opentdf/platform/service/policy/db"
	"github.com/stretchr/testify/suite"
	"google.golang.org/protobuf/proto"
)

const (
	nonExistentAttributeValueUUID = "78909865-8888-9999-9999-000000000000"
	nonExistingActionUUID         = "5dff18c8-1192-4f2e-aa21-2d793c9d97b2"
)

type SubjectMappingsSuite struct {
	suite.Suite
	f  fixtures.Fixtures
	db fixtures.DBInterface
	//nolint:containedctx // Only used for test suite
	ctx context.Context
}

func (s *SubjectMappingsSuite) SetupSuite() {
	slog.Info("setting up db.SubjectMappings test suite")
	s.ctx = context.Background()
	c := *Config
	c.DB.Schema = "test_opentdf_subject_mappings"
	s.db = fixtures.NewDBInterface(s.ctx, c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision(s.ctx)
}

func (s *SubjectMappingsSuite) TearDownSuite() {
	slog.Info("tearing down db.SubjectMappings test suite")
	s.f.TearDown(s.ctx)
}

// a set of easily accessible actions for use in tests
var (
	fixtureActionCustomDownload = &policy.Action{Name: "custom_download"}
	fixtureActionCustomUpload   = &policy.Action{Name: "custom_upload"}

	nonExistentSubjectSetID     = "9f9f3282-ffff-1111-924a-7b8eb43d5423"
	nonExistentSubjectMappingID = "32977f0b-f2b9-44b5-8afd-e2e224ea8352"
)

/*--------------------------------------------------------
 *-------------------- SubjectMappings -------------------
 *-------------------------------------------------------*/

func TestSubjectMappingSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping subject_mappings integration tests")
	}
	suite.Run(t, new(SubjectMappingsSuite))
}

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_ExistingSubjectConditionSetId() {
	fixtureAttrValID := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value2").ID
	fixtureSCSId := s.f.GetSubjectConditionSetKey("subject_condition_set1").ID
	actionRead := s.f.GetStandardAction(policydb.ActionRead.String())
	actionCreate := s.f.GetStandardAction(policydb.ActionCreate.String())
	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrValID,
		ExistingSubjectConditionSetId: fixtureSCSId,
		Actions:                       []*policy.Action{actionRead, actionCreate},
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, newSubjectMapping)
	s.Require().NoError(err)
	s.NotNil(created)

	// verify the subject mapping was created
	sm, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.Equal(newSubjectMapping.GetAttributeValueId(), sm.GetAttributeValue().GetId())
	s.Equal(newSubjectMapping.GetExistingSubjectConditionSetId(), sm.GetSubjectConditionSet().GetId())
	s.Len(sm.GetActions(), 2)
	foundRead := false
	foundCreate := false
	for _, a := range sm.GetActions() {
		if a.GetName() == actionRead.GetName() {
			foundRead = true
		}
		if a.GetName() == actionCreate.GetName() {
			foundCreate = true
		}
	}
	s.True(foundRead)
	s.True(foundCreate)
}

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_NewSubjectConditionSet() {
	fixtureAttrValID := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value2").ID
	actionCreate := s.f.GetStandardAction(policydb.ActionCreate.String())
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
		Actions:                []*policy.Action{actionCreate},
		NewSubjectConditionSet: scs,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, newSubjectMapping)
	s.Require().NoError(err)
	s.NotNil(created)

	// verify the new subject condition set created was returned properly
	sm, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(sm.GetSubjectConditionSet())
	s.Len(scs.GetSubjectSets(), len(sm.GetSubjectConditionSet().GetSubjectSets()))

	expectedCGroups := scs.GetSubjectSets()[0].GetConditionGroups()
	gotCGroups := sm.GetSubjectConditionSet().GetSubjectSets()[0].GetConditionGroups()
	s.Len(expectedCGroups, len(gotCGroups))
	s.Len(expectedCGroups[0].GetConditions(), len(gotCGroups[0].GetConditions()))

	expectedCondition := expectedCGroups[0].GetConditions()[0]
	gotCondition := sm.GetSubjectConditionSet().GetSubjectSets()[0].GetConditionGroups()[0].GetConditions()[0]
	s.Equal(expectedCondition.GetSubjectExternalSelectorValue(), gotCondition.GetSubjectExternalSelectorValue())
	s.Equal(expectedCondition.GetOperator(), gotCondition.GetOperator())
	s.Equal(expectedCondition.GetSubjectExternalValues(), gotCondition.GetSubjectExternalValues())
}

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_NonExistentAttributeValueId_Fails() {
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	actionCreate := s.f.GetStandardAction(policydb.ActionCreate.String())

	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		Actions:                       []*policy.Action{actionCreate},
		ExistingSubjectConditionSetId: fixtureScs.ID,
		AttributeValueId:              nonExistentAttributeValueUUID,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, newSubjectMapping)
	s.Require().Error(err)
	s.Nil(created)
	s.Require().ErrorIs(err, db.ErrForeignKeyViolation)
}

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_NonExistentSubjectConditionSetId_Fails() {
	fixtureAttrVal := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value1")
	actionRead := s.f.GetStandardAction(policydb.ActionRead.String())
	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrVal.ID,
		Actions:                       []*policy.Action{actionRead},
		ExistingSubjectConditionSetId: nonExistentSubjectSetID,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, newSubjectMapping)
	s.Require().Error(err)
	s.Nil(created)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_NonExistentActionId_Fails() {
	fixtureAttrVal := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value1")
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set3")

	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId: fixtureAttrVal.ID,
		Actions: []*policy.Action{
			{
				Id: nonExistingActionUUID,
			},
		},
		ExistingSubjectConditionSetId: fixtureScs.ID,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, newSubjectMapping)
	s.Require().Error(err)
	s.Nil(created)
	s.Require().ErrorIs(err, db.ErrForeignKeyViolation)
}

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_BrandNewActionNames_Succeeds() {
	fixtureAttrVal := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value2")
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set1")
	newNameOne := "NewAction-Testing-SMCreate-1"
	newNameTwo := "NewAction_Testing_SMCreate_2"

	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId: fixtureAttrVal.ID,
		Actions: []*policy.Action{
			{
				Name: newNameOne,
			},
			{
				Name: newNameTwo,
			},
		},
		ExistingSubjectConditionSetId: fixtureScs.ID,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, newSubjectMapping)
	s.NotNil(created)
	s.Require().NoError(err)

	got, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)

	foundNewActionOne := false
	foundNewActionTwo := false
	for _, a := range got.GetActions() {
		if a.GetName() == strings.ToLower(newNameOne) {
			foundNewActionOne = true
		}
		if a.GetName() == strings.ToLower(newNameTwo) {
			foundNewActionTwo = true
		}
		s.NotEmpty(a.GetId())
	}
	s.True(foundNewActionOne)
	s.True(foundNewActionTwo)
}

func (s *SubjectMappingsSuite) TestCreateSubjectMapping_DeprecatedProtoEnums_Fails() {
	s.T().Skip("Skipping test while deprecation of proto actions is in flight")

	fixtureAttrVal := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")

	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId: fixtureAttrVal.ID,
		Actions: []*policy.Action{
			{
				Value: &policy.Action_Standard{
					Standard: policy.Action_STANDARD_ACTION_DECRYPT,
				},
			},
		},
		ExistingSubjectConditionSetId: fixtureScs.ID,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, newSubjectMapping)
	s.Nil(created)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrMissingValue)

	newSubjectMapping.GetActions()[0].Value = &policy.Action_Standard{
		Standard: policy.Action_STANDARD_ACTION_TRANSMIT,
	}

	created, err = s.db.PolicyClient.CreateSubjectMapping(s.ctx, newSubjectMapping)
	s.Nil(created)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrMissingValue)
}

func (s *SubjectMappingsSuite) TestUpdateSubjectMapping_Actions() {
	// create a new one SM with actions, update it with different actions, and verify the update
	fixtureAttrValID := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value2").ID
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set3")
	actionUpdate := s.f.GetStandardAction(policydb.ActionUpdate.String())
	actionDelete := s.f.GetStandardAction(policydb.ActionDelete.String())

	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrValID,
		Actions:                       []*policy.Action{actionUpdate, fixtureActionCustomUpload},
		ExistingSubjectConditionSetId: fixtureScs.ID,
	}
	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, newSubjectMapping)
	s.Require().NoError(err)
	s.NotNil(created)

	got, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Len(newSubjectMapping.GetActions(), len(got.GetActions()))

	// update the subject mapping by removing one of the original actions
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id:      created.GetId(),
		Actions: []*policy.Action{actionUpdate},
	}

	updated, err := s.db.PolicyClient.UpdateSubjectMapping(s.ctx, update)
	s.Require().NoError(err)
	s.NotNil(updated)
	s.Equal(created.GetId(), updated.GetId())

	// verify one action was dropped with no other changes
	got, err = s.db.PolicyClient.GetSubjectMapping(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	// actions
	s.Len(update.GetActions(), len(got.GetActions()))
	s.Equal(actionUpdate.GetName(), got.GetActions()[0].GetName())
	// attr value
	s.Equal(newSubjectMapping.GetAttributeValueId(), got.GetAttributeValue().GetId())
	// scs
	s.Equal(newSubjectMapping.GetExistingSubjectConditionSetId(), got.GetSubjectConditionSet().GetId())
	// metadata
	metadata := got.GetMetadata()
	createdAt := metadata.GetCreatedAt()
	updatedAt := metadata.GetUpdatedAt()
	s.False(createdAt.AsTime().IsZero())
	s.False(updatedAt.AsTime().IsZero())
	s.True(updatedAt.AsTime().After(createdAt.AsTime()))

	// update with actions not in the current
	newActionName := "NewAction-Testing-SM-UPDATE"
	update = &subjectmapping.UpdateSubjectMappingRequest{
		Id:      created.GetId(),
		Actions: []*policy.Action{actionDelete, {Name: newActionName}},
	}
	updated, err = s.db.PolicyClient.UpdateSubjectMapping(s.ctx, update)
	s.Require().NoError(err)
	s.NotNil(updated)

	// verify the action was added
	got, err = s.db.PolicyClient.GetSubjectMapping(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Len(update.GetActions(), len(got.GetActions()))
	foundDelete := false
	foundNewAction := false
	for _, a := range got.GetActions() {
		if a.GetName() == actionDelete.GetName() {
			foundDelete = true
		}
		if a.GetName() == strings.ToLower(newActionName) {
			foundNewAction = true
		}
	}
	s.True(foundDelete)
	s.True(foundNewAction)
}

func (s *SubjectMappingsSuite) TestUpdateSubjectMapping_Actions_NonExistentActionID_Fails() {
	fixtureAttrValID := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value1").ID
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	actionRead := s.f.GetStandardAction(policydb.ActionRead.String())

	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrValID,
		Actions:                       []*policy.Action{actionRead},
		ExistingSubjectConditionSetId: fixtureScs.ID,
	}
	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, newSubjectMapping)
	s.Require().NoError(err)
	s.NotNil(created)

	got, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Len(newSubjectMapping.GetActions(), len(got.GetActions()))

	// update with a non-existent action
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id:      created.GetId(),
		Actions: []*policy.Action{{Id: nonExistingActionUUID}},
	}

	updated, err := s.db.PolicyClient.UpdateSubjectMapping(s.ctx, update)
	s.Nil(updated)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrForeignKeyViolation)
}

func (s *SubjectMappingsSuite) TestUpdateSubjectMapping_Actions_DeprecatedProtoEnums_Fails() {
	s.T().Skip("Skipping test while deprecation of proto actions is in flight")

	fixtureAttrVal := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value1")
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set1")

	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId: fixtureAttrVal.ID,
		Actions: []*policy.Action{
			{Name: policydb.ActionRead.String()},
		},
		ExistingSubjectConditionSetId: fixtureScs.ID,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, newSubjectMapping)
	s.NotNil(created)
	s.Require().NoError(err)

	updateReq := &subjectmapping.UpdateSubjectMappingRequest{
		Id: created.GetId(),
		Actions: []*policy.Action{
			{
				Value: &policy.Action_Standard{
					Standard: policy.Action_STANDARD_ACTION_DECRYPT,
				},
			},
		},
	}

	updated, err := s.db.PolicyClient.UpdateSubjectMapping(s.ctx, updateReq)
	s.Nil(updated)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrMissingValue)

	updateReq.Actions[0].Value = &policy.Action_Standard{
		Standard: policy.Action_STANDARD_ACTION_TRANSMIT,
	}

	updated, err = s.db.PolicyClient.UpdateSubjectMapping(s.ctx, updateReq)
	s.Nil(updated)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrMissingValue)
}

func (s *SubjectMappingsSuite) TestUpdateSubjectMapping_SubjectConditionSetId() {
	// create a new one, update it, and verify the update
	fixtureAttrValID := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value1").ID
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set1")
	actionDelete := s.f.GetStandardAction(policydb.ActionDelete.String())

	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrValID,
		Actions:                       []*policy.Action{actionDelete},
		ExistingSubjectConditionSetId: fixtureScs.ID,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, newSubjectMapping)
	s.Require().NoError(err)
	s.NotNil(created)
	s.Len(created.GetActions(), len(newSubjectMapping.GetActions()))

	// update the subject mapping
	newScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id:                    created.GetId(),
		SubjectConditionSetId: newScs.ID,
	}

	updated, err := s.db.PolicyClient.UpdateSubjectMapping(s.ctx, update)
	s.Require().NoError(err)
	s.NotNil(updated)
	s.Equal(created.GetId(), updated.GetId())

	// verify the subject condition set was updated but nothing else
	got, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(newSubjectMapping.GetAttributeValueId(), got.GetAttributeValue().GetId())
	s.Equal(newScs.ID, got.GetSubjectConditionSet().GetId())
	s.Len(newSubjectMapping.GetActions(), len(got.GetActions()))
	// s.Equal(newSubjectMapping.GetActions(), got.GetActions())
}

func (s *SubjectMappingsSuite) Test_UpdateSubjectMapping_UpdateAllAllowedFields() {
	// create a new one, update it, and verify the update
	fixtureAttrValID := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value1").ID
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set1")
	actionCreate := s.f.GetStandardAction(policydb.ActionCreate.String())
	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrValID,
		Actions:                       []*policy.Action{actionCreate},
		ExistingSubjectConditionSetId: fixtureScs.ID,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, newSubjectMapping)
	s.Require().NoError(err)
	s.NotNil(created)

	// update the subject mapping
	newScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	newActions := []*policy.Action{fixtureActionCustomUpload}
	metadata := &common.MetadataMutable{
		Labels: map[string]string{"key": "value"},
	}
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id:                     created.GetId(),
		SubjectConditionSetId:  newScs.ID,
		Actions:                newActions,
		Metadata:               metadata,
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	}

	updated, err := s.db.PolicyClient.UpdateSubjectMapping(s.ctx, update)
	s.Require().NoError(err)
	s.NotNil(updated)
	s.Equal(created.GetId(), updated.GetId())

	// verify the subject mapping was updated
	got, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Equal(newSubjectMapping.GetAttributeValueId(), got.GetAttributeValue().GetId())
	s.Equal(newScs.ID, got.GetSubjectConditionSet().GetId())
	s.Len(newActions, len(got.GetActions()))
	// s.Equal(newActions, got.GetActions())
	s.Equal(metadata.GetLabels()["key"], got.GetMetadata().GetLabels()["key"])
}

func (s *SubjectMappingsSuite) TestUpdateSubjectMapping_NonExistentId_Fails() {
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id: nonExistentSubjectMappingID,
	}

	sm, err := s.db.PolicyClient.UpdateSubjectMapping(s.ctx, update)
	s.Require().Error(err)
	s.Nil(sm)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestUpdateSubjectMapping_NonExistentSubjectConditionSetId_Fails() {
	update := &subjectmapping.UpdateSubjectMappingRequest{
		Id:                    s.f.GetSubjectMappingKey("subject_mapping_subject_attribute3").ID,
		SubjectConditionSetId: nonExistentSubjectSetID,
	}

	sm, err := s.db.PolicyClient.UpdateSubjectMapping(s.ctx, update)
	s.Require().Error(err)
	s.Nil(sm)
	s.Require().ErrorIs(err, db.ErrForeignKeyViolation)
}

func (s *SubjectMappingsSuite) TestGetSubjectMapping() {
	fixture := s.f.GetSubjectMappingKey("subject_mapping_subject_attribute2")

	sm, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, fixture.ID)
	s.Require().NoError(err)
	s.NotNil(sm)
	s.Equal(fixture.ID, sm.GetId())
	s.Equal(fixture.AttributeValueID, sm.GetAttributeValue().GetId())
	s.True(sm.GetAttributeValue().GetActive().GetValue())
	s.Equal(fixture.SubjectConditionSetID, sm.GetSubjectConditionSet().GetId())

	foundRead := false
	foundCreate := false
	// verify the actions
	for _, a := range sm.GetActions() {
		s.NotNil(a)
		if a.GetName() == "read" {
			foundRead = true
		}
		if a.GetName() == "create" {
			foundCreate = true
		}
	}
	s.True(foundRead)
	s.True(foundCreate)

	got, err := s.db.PolicyClient.GetAttributeValue(s.ctx, fixture.AttributeValueID)
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(fixture.AttributeValueID, got.GetId())
	metadata := sm.GetMetadata()
	createdAt := metadata.GetCreatedAt()
	updatedAt := metadata.GetUpdatedAt()
	s.True(createdAt.IsValid() && createdAt.AsTime().Unix() > 0)
	s.True(updatedAt.IsValid() && updatedAt.AsTime().Unix() > 0)
}

func (s *SubjectMappingsSuite) Test_GetSubjectMapping_NonExistentId_Fails() {
	sm, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, nonExistentSubjectMappingID)
	s.Require().Error(err)
	s.Nil(sm)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) Test_ListSubjectMappings_NoPagination_Succeeds() {
	listRsp, err := s.db.PolicyClient.ListSubjectMappings(context.Background(), &subjectmapping.ListSubjectMappingsRequest{})
	s.Require().NoError(err)
	s.NotNil(listRsp)
	listed := listRsp.GetSubjectMappings()
	s.NotEmpty(listed)

	fixture1 := s.f.GetSubjectMappingKey("subject_mapping_subject_attribute1")
	found1 := false
	fixture2 := s.f.GetSubjectMappingKey("subject_mapping_subject_attribute2")
	found2 := false
	fixture3 := s.f.GetSubjectMappingKey("subject_mapping_subject_attribute3")
	found3 := false
	s.GreaterOrEqual(len(listed), 3)

	assertEqual := func(sm *policy.SubjectMapping, fixture fixtures.FixtureDataSubjectMapping) {
		s.Equal(fixture.AttributeValueID, sm.GetAttributeValue().GetId())
		s.True(sm.GetAttributeValue().GetActive().GetValue())
		s.Equal(fixture.SubjectConditionSetID, sm.GetSubjectConditionSet().GetId())
		// s.Equal(len(fixture.Actions), len(sm.GetActions()))
	}
	for _, sm := range listed {
		if sm.GetId() == fixture1.ID {
			assertEqual(sm, fixture1)
			s.Equal("https://example.com/attr/attr1/value/value1", sm.GetAttributeValue().GetFqn())
			found1 = true
		}
		if sm.GetId() == fixture2.ID {
			assertEqual(sm, fixture2)
			s.Equal("https://example.com/attr/attr1/value/value2", sm.GetAttributeValue().GetFqn())
			found2 = true
		}
		if sm.GetId() == fixture3.ID {
			assertEqual(sm, fixture3)
			s.Equal("https://example.com/attr/attr1/value/value1", sm.GetAttributeValue().GetFqn())
			found3 = true
		}
	}
	s.True(found1)
	s.True(found2)
	s.True(found3)
}

func (s *SubjectMappingsSuite) Test_ListSubjectMappings_OrdersByCreatedAt_Succeeds() {
	fixtureAttrValID := s.f.GetAttributeValueKey("example.net/attr/attr1/value/value2").ID
	actionRead := s.f.GetStandardAction(policydb.ActionRead.String())

	createMapping := func(email string) string {
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
									SubjectExternalValues:        []string{email},
								},
							},
						},
					},
				},
			},
		}

		created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, &subjectmapping.CreateSubjectMappingRequest{
			AttributeValueId:       fixtureAttrValID,
			SubjectConditionSet:    scs,
			Actions:                []*policy.Action{actionRead},
			OnlyExistingActions:    true,
			AllowExistingCondition: true,
		})
		s.Require().NoError(err)
		s.Require().NotEmpty(created.GetId())
		return created.GetId()
	}

	firstID := createMapping("order-test-1@example.com")
	time.Sleep(5 * time.Millisecond)
	secondID := createMapping("order-test-2@example.com")
	time.Sleep(5 * time.Millisecond)
	thirdID := createMapping("order-test-3@example.com")

	listRsp, err := s.db.PolicyClient.ListSubjectMappings(context.Background(), &subjectmapping.ListSubjectMappingsRequest{})
	s.Require().NoError(err)

	positions := map[string]int{}
	for i, sm := range listRsp.GetSubjectMappings() {
		id := sm.GetId()
		if id == firstID || id == secondID || id == thirdID {
			positions[id] = i
		}
	}

	s.Require().Len(positions, 3)
	first := positions[firstID]
	second := positions[secondID]
	third := positions[thirdID]

	s.True(first < second)
	s.True(second < third)
}

func (s *SubjectMappingsSuite) Test_ListSubjectMappings_Limit_Succeeds() {
	var limit int32 = 3
	listRsp, err := s.db.PolicyClient.ListSubjectMappings(context.Background(), &subjectmapping.ListSubjectMappingsRequest{
		Pagination: &policy.PageRequest{
			Limit: limit,
		},
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)

	listed := listRsp.GetSubjectMappings()
	s.NotEmpty(listed)

	for _, sm := range listed {
		s.NotEmpty(sm.GetId())
		s.NotEmpty(sm.GetAttributeValue())
		s.NotNil(sm.GetSubjectConditionSet())
	}

	// request with one below maximum
	listRsp, err = s.db.PolicyClient.ListSubjectMappings(context.Background(), &subjectmapping.ListSubjectMappingsRequest{
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax - 1,
		},
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)
}

func (s *NamespacesSuite) Test_ListSubjectMappings_Limit_TooLarge_Fails() {
	listRsp, err := s.db.PolicyClient.ListSubjectMappings(context.Background(), &subjectmapping.ListSubjectMappingsRequest{
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax + 1,
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrListLimitTooLarge)
	s.Nil(listRsp)
}

func (s *SubjectMappingsSuite) Test_ListSubjectMappings_Offset_Succeeds() {
	req := &subjectmapping.ListSubjectMappingsRequest{}
	totalListRsp, err := s.db.PolicyClient.ListSubjectMappings(context.Background(), req)
	s.Require().NoError(err)
	s.NotNil(totalListRsp)

	totalList := totalListRsp.GetSubjectMappings()
	s.NotEmpty(totalList)

	// set the offset pagination
	offset := 2
	req.Pagination = &policy.PageRequest{
		Offset: int32(offset),
	}

	offetListRsp, err := s.db.PolicyClient.ListSubjectMappings(context.Background(), req)
	s.Require().NoError(err)
	s.NotNil(offetListRsp)

	offsetList := offetListRsp.GetSubjectMappings()
	s.NotEmpty(offsetList)

	// length is reduced by the offset amount
	s.Equal(len(offsetList), len(totalList)-offset)

	// objects are equal between offset and original list beginning at offset index
	for i, sm := range offsetList {
		s.True(proto.Equal(sm, totalList[i+offset]))
	}
}

func (s *SubjectMappingsSuite) TestDeleteSubjectMapping() {
	// create a new subject mapping, delete it, and verify get fails with not found
	fixtureAttrValID := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value1").ID
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set2")

	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrValID,
		Actions:                       []*policy.Action{fixtureActionCustomDownload},
		ExistingSubjectConditionSetId: fixtureScs.ID,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, newSubjectMapping)
	s.Require().NoError(err)
	s.NotNil(created)

	deleted, err := s.db.PolicyClient.DeleteSubjectMapping(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(deleted)

	got, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, created.GetId())
	s.Require().Error(err)
	s.Nil(got)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestDeleteSubjectMapping_WithNonExistentId_Fails() {
	deleted, err := s.db.PolicyClient.DeleteSubjectMapping(s.ctx, nonExistentSubjectMappingID)
	s.Require().Error(err)
	s.Nil(deleted)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestDeleteSubjectMapping_DoesNotDeleteSubjectConditionSet() {
	// create a new subject mapping, delete it, and verify the subject condition set still exists
	fixtureAttrValID := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value2").ID
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
	actionRead := s.f.GetStandardAction(policydb.ActionRead.String())

	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:       fixtureAttrValID,
		Actions:                []*policy.Action{actionRead, fixtureActionCustomDownload},
		NewSubjectConditionSet: newScs,
	}

	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, newSubjectMapping)
	s.Require().NoError(err)
	s.NotNil(created)

	sm, err := s.db.PolicyClient.GetSubjectMapping(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(sm)
	deleted, err := s.db.PolicyClient.DeleteSubjectMapping(s.ctx, sm.GetId())
	s.Require().NoError(err)
	s.NotNil(deleted)
	s.NotEmpty(deleted.GetId())

	scs, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, sm.GetSubjectConditionSet().GetId())
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

	scs, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, newConditionSet)
	s.Require().NoError(err)
	s.NotNil(scs)
}

func (s *SubjectMappingsSuite) TestCreateSubjectConditionSetContains() {
	newConditionSet := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{
				ConditionGroups: []*policy.ConditionGroup{
					{
						BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR,
						Conditions: []*policy.Condition{
							{
								SubjectExternalSelectorValue: ".someField[1]",
								Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS,
								SubjectExternalValues:        []string{"some_partial_value"},
							},
						},
					},
				},
			},
		},
	}

	scs, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, newConditionSet)
	s.Require().NoError(err)
	s.NotNil(scs)
}

func (s *SubjectMappingsSuite) TestGetSubjectConditionSet_ById() {
	fixture := s.f.GetSubjectConditionSetKey("subject_condition_set1")

	scs, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, fixture.ID)
	s.Require().NoError(err)
	s.NotNil(scs)
	s.Equal(fixture.ID, scs.GetId())
	metadata := scs.GetMetadata()
	createdAt := metadata.GetCreatedAt()
	updatedAt := metadata.GetUpdatedAt()
	s.True(createdAt.IsValid() && createdAt.AsTime().Unix() > 0)
	s.True(updatedAt.IsValid() && updatedAt.AsTime().Unix() > 0)
}

func (s *SubjectMappingsSuite) TestGetSubjectConditionSet_WithNoId_Fails() {
	scs, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, "")
	s.Require().Error(err)
	s.Nil(scs)
	s.Require().ErrorIs(err, db.ErrUUIDInvalid)
}

func (s *SubjectMappingsSuite) TestGetSubjectConditionSet_NonExistentId_Fails() {
	scs, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, nonExistentSubjectSetID)
	s.Require().Error(err)
	s.Nil(scs)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) Test_ListSubjectConditionSet_NoPagination_Succeeds() {
	listRsp, err := s.db.PolicyClient.ListSubjectConditionSets(context.Background(), &subjectmapping.ListSubjectConditionSetsRequest{})
	s.Require().NoError(err)
	s.NotNil(listRsp)
	listed := listRsp.GetSubjectConditionSets()

	fixture1 := s.f.GetSubjectConditionSetKey("subject_condition_set1")
	found1 := false
	fixture2 := s.f.GetSubjectConditionSetKey("subject_condition_set2")
	found2 := false
	fixture3 := s.f.GetSubjectConditionSetKey("subject_condition_set3")
	found3 := false
	fixture4 := s.f.GetSubjectConditionSetKey("subject_condition_simple_in")
	found4 := false

	s.GreaterOrEqual(len(listed), 3)
	for _, scs := range listed {
		switch scs.GetId() {
		case fixture1.ID:
			found1 = true
		case fixture2.ID:
			found2 = true
		case fixture3.ID:
			found3 = true
		case fixture4.ID:
			found4 = true
		}
	}
	s.True(found1)
	s.True(found2)
	s.True(found3)
	s.True(found4)
}

func (s *SubjectMappingsSuite) Test_ListSubjectConditionSet_OrdersByCreatedAt_Succeeds() {
	create := func(email string) string {
		req := &subjectmapping.CreateSubjectConditionSetRequest{
			Condition: &subjectmapping.SubjectConditionSetCreate{
				SubjectSets: []*policy.SubjectSet{
					{
						ConditionGroups: []*policy.ConditionGroup{
							{
								BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
								Conditions: []*policy.Condition{
									{
										SubjectExternalSelectorValue: ".email",
										Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
										SubjectExternalValues:        []string{email},
									},
								},
							},
						},
					},
				},
			},
		}
		created, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, req)
		s.Require().NoError(err)
		s.Require().NotNil(created)
		return created.GetId()
	}

	firstID := create("order-scs-1@example.com")
	time.Sleep(5 * time.Millisecond)
	secondID := create("order-scs-2@example.com")
	time.Sleep(5 * time.Millisecond)
	thirdID := create("order-scs-3@example.com")
	defer func() {
		_, _ = s.db.PolicyClient.DeleteSubjectConditionSet(s.ctx, firstID)
		_, _ = s.db.PolicyClient.DeleteSubjectConditionSet(s.ctx, secondID)
		_, _ = s.db.PolicyClient.DeleteSubjectConditionSet(s.ctx, thirdID)
	}()

	listRsp, err := s.db.PolicyClient.ListSubjectConditionSets(context.Background(), &subjectmapping.ListSubjectConditionSetsRequest{})
	s.Require().NoError(err)
	s.NotNil(listRsp)

	assertIDsInOrder(s.T(), listRsp.GetSubjectConditionSets(), func(scs *policy.SubjectConditionSet) string { return scs.GetId() }, firstID, secondID, thirdID)
}

func (s *SubjectMappingsSuite) Test_ListSubjectConditionSet_Limit_Succeeds() {
	var limit int32 = 3
	listRsp, err := s.db.PolicyClient.ListSubjectConditionSets(context.Background(), &subjectmapping.ListSubjectConditionSetsRequest{
		Pagination: &policy.PageRequest{
			Limit: limit,
		},
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)

	listed := listRsp.GetSubjectConditionSets()
	s.NotEmpty(listed)

	for _, sm := range listed {
		s.NotEmpty(sm.GetId())
		s.NotEmpty(sm.GetSubjectSets())
	}

	// request with one below maximum
	listRsp, err = s.db.PolicyClient.ListSubjectConditionSets(context.Background(), &subjectmapping.ListSubjectConditionSetsRequest{
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax - 1,
		},
	})
	s.Require().NoError(err)
	s.NotNil(listRsp)
}

func (s *NamespacesSuite) Test_ListSubjectConditionSets_Limit_TooLarge_Fails() {
	listRsp, err := s.db.PolicyClient.ListSubjectConditionSets(context.Background(), &subjectmapping.ListSubjectConditionSetsRequest{
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax + 1,
		},
	})
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrListLimitTooLarge)
	s.Nil(listRsp)
}

func (s *SubjectMappingsSuite) Test_ListSubjectConditionSet_Offset_Succeeds() {
	req := &subjectmapping.ListSubjectConditionSetsRequest{}
	totalListRsp, err := s.db.PolicyClient.ListSubjectConditionSets(context.Background(), req)
	s.Require().NoError(err)
	s.NotNil(totalListRsp)

	totalList := totalListRsp.GetSubjectConditionSets()
	s.NotEmpty(totalList)

	// set the offset pagination
	offset := 5
	req.Pagination = &policy.PageRequest{
		Offset: int32(offset),
	}

	offetListRsp, err := s.db.PolicyClient.ListSubjectConditionSets(context.Background(), req)
	s.Require().NoError(err)
	s.NotNil(offetListRsp)

	offsetList := offetListRsp.GetSubjectConditionSets()
	s.NotEmpty(offsetList)

	// length is reduced by the offset amount
	s.Equal(len(offsetList), len(totalList)-offset)

	// objects are equal between offset and original list beginning at offset index
	for i, scs := range offsetList {
		s.True(proto.Equal(scs, totalList[i+offset]))
	}
}

func (s *SubjectMappingsSuite) TestDeleteSubjectConditionSet() {
	// create a new subject condition set, delete it, and verify get fails with not found
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

	created, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, newConditionSet)
	s.Require().NoError(err)
	s.NotNil(created)

	deleted, err := s.db.PolicyClient.DeleteSubjectConditionSet(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(deleted)
	s.Equal(created.GetId(), deleted.GetId())

	got, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, created.GetId())
	s.Require().Error(err)
	s.Nil(got)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestDeleteSubjectConditionSet_WithNonExistentId_Fails() {
	deleted, err := s.db.PolicyClient.DeleteSubjectConditionSet(s.ctx, nonExistentSubjectSetID)
	s.Require().Error(err)
	s.Nil(deleted)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestDeleteAllUnmappedSubjectConditionSets() {
	// create two new subject condition sets, create a subject mapping with one of them, then verify only the unmapped is deleted
	newSCS := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{
				ConditionGroups: []*policy.ConditionGroup{
					{
						Conditions: []*policy.Condition{
							{
								SubjectExternalSelectorValue: ".some_selector",
							},
						},
					},
				},
			},
		},
	}

	unmapped, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, newSCS)
	s.Require().NoError(err)
	s.NotNil(unmapped)

	mapped, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, newSCS)
	s.Require().NoError(err)
	s.NotNil(mapped)

	sm, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              s.f.GetAttributeValueKey("example.net/attr/attr1/value/value2").ID,
		Actions:                       []*policy.Action{s.f.GetStandardAction("read")},
		ExistingSubjectConditionSetId: mapped.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(sm)

	deleted, err := s.db.PolicyClient.DeleteAllUnmappedSubjectConditionSets(s.ctx)
	s.Require().NoError(err)
	s.NotEmpty(deleted)
	unmappedDeleted := true
	mappedDeleted := false
	for _, scs := range deleted {
		deletedID := scs.GetId()
		if deletedID == unmapped.GetId() {
			unmappedDeleted = true
		}
		if deletedID == mapped.GetId() {
			mappedDeleted = true
		}
	}
	s.True(unmappedDeleted)
	s.False(mappedDeleted)

	// cannot get after pruning
	got, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, unmapped.GetId())
	s.Nil(got)
	s.Require().Error(err)
	s.ErrorIs(err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestUpdateSubjectConditionSet_NewSubjectSets() {
	// create a new one, update nothing but the subject sets, and verify the solo update
	newConditionSet := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{},
		},
	}
	created, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, newConditionSet)
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

	updated, err := s.db.PolicyClient.UpdateSubjectConditionSet(s.ctx, update)
	s.Require().NoError(err)
	s.NotNil(updated)
	s.Equal(created.GetId(), updated.GetId())

	// verify the subject condition set was updated
	got, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Len(ss, len(got.GetSubjectSets()))
	s.Equal(ss[0].GetConditionGroups()[0].GetConditions()[0].GetSubjectExternalSelectorValue(), got.GetSubjectSets()[0].GetConditionGroups()[0].GetConditions()[0].GetSubjectExternalSelectorValue())
	metadata := got.GetMetadata()
	createdAt := metadata.GetCreatedAt()
	updatedAt := metadata.GetUpdatedAt()
	s.False(createdAt.AsTime().IsZero())
	s.False(updatedAt.AsTime().IsZero())
	s.True(updatedAt.AsTime().After(createdAt.AsTime()))
}

func (s *SubjectMappingsSuite) TestUpdateSubjectConditionSet_AllAllowedFields() {
	// create a new one, update it, and verify the update
	newConditionSet := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{},
		},
	}

	created, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, newConditionSet)
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

	updated, err := s.db.PolicyClient.UpdateSubjectConditionSet(s.ctx, update)
	s.Require().NoError(err)
	s.NotNil(updated)
	s.Equal(created.GetId(), updated.GetId())

	// verify the subject condition set was updated
	got, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Len(ss, len(got.GetSubjectSets()))
	s.Equal(ss[0].GetConditionGroups()[0].GetConditions()[0].GetSubjectExternalSelectorValue(), got.GetSubjectSets()[0].GetConditionGroups()[0].GetConditions()[0].GetSubjectExternalSelectorValue())
	s.Equal(metadata.GetLabels()["key_example"], got.GetMetadata().GetLabels()["key_example"])
}

func (s *SubjectMappingsSuite) TestUpdateSubjectConditionSet_ChangeOperator() {
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

	created, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, newConditionSet)
	s.Require().NoError(err)
	s.NotNil(created)

	// update the subject condition set
	newSS := []*policy.SubjectSet{
		{
			ConditionGroups: []*policy.ConditionGroup{
				{
					BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
					Conditions: []*policy.Condition{
						{
							SubjectExternalSelectorValue: ".someField[1]",
							Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS,
							SubjectExternalValues:        []string{"some_partial_value"},
						},
					},
				},
			},
		},
	}

	update := &subjectmapping.UpdateSubjectConditionSetRequest{
		SubjectSets: newSS,
		Id:          created.GetId(),
	}
	updated, err := s.db.PolicyClient.UpdateSubjectConditionSet(s.ctx, update)
	s.Require().NoError(err)
	s.NotNil(updated)

	got, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	condition := got.GetSubjectSets()[0].GetConditionGroups()[0].GetConditions()[0]
	s.Equal(policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS, condition.GetOperator())
	s.Equal(".someField[1]", condition.GetSubjectExternalSelectorValue())
	s.Len(condition.GetSubjectExternalValues(), 1)
	s.Equal("some_partial_value", condition.GetSubjectExternalValues()[0])
}

func (s *SubjectMappingsSuite) TestUpdateSubjectConditionSet_NonExistentId_Fails() {
	update := &subjectmapping.UpdateSubjectConditionSetRequest{
		Id:          nonExistentSubjectSetID,
		SubjectSets: []*policy.SubjectSet{},
	}

	updated, err := s.db.PolicyClient.UpdateSubjectConditionSet(s.ctx, update)
	s.Require().Error(err)
	s.Nil(updated)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_SingleMatch() {
	externalSelector := ".testing_matched_sm"
	fixtureAttrVal := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1")
	newScs := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{
				ConditionGroups: []*policy.ConditionGroup{
					{
						BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
						Conditions: []*policy.Condition{
							{
								SubjectExternalSelectorValue: externalSelector,
								Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								SubjectExternalValues:        []string{"match"},
							},
						},
					},
				},
			},
		},
	}

	subjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:       fixtureAttrVal.ID,
		Actions:                []*policy.Action{s.f.GetStandardAction("create")},
		NewSubjectConditionSet: newScs,
	}
	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, subjectMapping)
	s.Require().NoError(err)
	s.NotNil(created)

	props := []*policy.SubjectProperty{
		{
			ExternalSelectorValue: externalSelector,
		},
	}

	smList, err := s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
	s.Require().NoError(err)
	s.NotZero(smList)
	matched := smList[0]
	s.Equal(created.GetId(), matched.GetId())
	s.NotEmpty(matched.GetAttributeValue().GetId())
	s.True(strings.HasSuffix(matched.GetAttributeValue().GetFqn(), fixtureAttrVal.Value))
	s.NotEmpty(matched.GetId())
	s.NotNil(matched.GetActions())
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_IgnoresExternalValueInCondition() {
	externalSelector := ".testing_unmatched_condition"
	fixtureAttrVal := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value2")
	newScs := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{
				ConditionGroups: []*policy.ConditionGroup{
					{
						BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
						Conditions: []*policy.Condition{
							{
								SubjectExternalSelectorValue: externalSelector,
								Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								SubjectExternalValues:        []string{"idp_value"},
							},
						},
					},
				},
			},
		},
	}

	subjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:       fixtureAttrVal.ID,
		Actions:                []*policy.Action{s.f.GetStandardAction("delete")},
		NewSubjectConditionSet: newScs,
	}
	created, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, subjectMapping)
	s.Require().NoError(err)
	s.NotNil(created)

	props := []*policy.SubjectProperty{
		{
			ExternalSelectorValue: externalSelector,
			ExternalValue:         "unrelated",
		},
	}

	smList, err := s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
	s.Require().NoError(err)
	s.NotZero(smList)
	matched := smList[0]
	s.Equal(created.GetId(), matched.GetId())
	s.NotEmpty(matched.GetAttributeValue().GetId())
	s.NotEmpty(matched.GetId())
	s.NotNil(matched.GetActions())
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_MultipleMatches() {
	externalSelector1 := ".idp_field"
	externalSelector2 := ".org.attributes[]"
	// create a two subject mappings with different subject condition sets
	fixtureAttrValID := s.f.GetAttributeValueKey("example.com/attr/attr2/value/value2").ID
	newScs := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{
				ConditionGroups: []*policy.ConditionGroup{
					{
						BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
						Conditions: []*policy.Condition{
							{
								SubjectExternalSelectorValue: externalSelector1,
								Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								SubjectExternalValues:        []string{"idp_value"},
							},
						},
					},
				},
			},
		},
	}

	subjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:       fixtureAttrValID,
		Actions:                []*policy.Action{fixtureActionCustomUpload, fixtureActionCustomDownload},
		NewSubjectConditionSet: newScs,
	}

	subjectMappingFirst, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, subjectMapping)
	s.Require().NoError(err)
	s.NotNil(subjectMappingFirst)

	// create the second subject mapping with the second SCS
	newScs.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalSelectorValue = externalSelector2
	subjectMapping.NewSubjectConditionSet = newScs

	subjectMappingSecond, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, subjectMapping)
	s.Require().NoError(err)
	s.NotNil(subjectMappingSecond)

	props := []*policy.SubjectProperty{
		{
			ExternalSelectorValue: externalSelector1,
		},
		{
			ExternalSelectorValue: externalSelector2,
		},
	}

	candidateEntitlements, err := s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
	s.Require().NoError(err)
	s.NotZero(candidateEntitlements)
	s.GreaterOrEqual(len(candidateEntitlements), 2)

	foundFirstSM := false
	foundSecondSM := false
	for _, sm := range candidateEntitlements {
		if sm.GetId() == subjectMappingFirst.GetId() {
			foundFirstSM = true
		} else if sm.GetId() == subjectMappingSecond.GetId() {
			foundSecondSM = true
		}
		foundUpload := false
		foundDownload := false
		for _, a := range sm.GetActions() {
			s.NotEmpty(a.GetId())
			s.NotEmpty(a.GetName())
			if a.GetName() == fixtureActionCustomUpload.GetName() {
				foundUpload = true
			}
			if a.GetName() == fixtureActionCustomDownload.GetName() {
				foundDownload = true
			}
		}
		s.True(foundUpload)
		s.True(foundDownload)
	}

	s.True(foundFirstSM)
	s.True(foundSecondSM)
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_DeactivatedValueNotReturned() {
	// create a new subject mapping with a deactivated attribute value
	fixtureAttrVal := s.f.GetAttributeValueKey("deactivated.io/attr/deactivated_attr/value/deactivated_value")
	fixtureScs := s.f.GetSubjectConditionSetKey("subject_condition_set1")
	actionRead := s.f.GetStandardAction(policydb.ActionRead.String())

	newSubjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrVal.ID,
		Actions:                       []*policy.Action{actionRead},
		ExistingSubjectConditionSetId: fixtureScs.ID,
	}
	sm, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, newSubjectMapping)
	s.Require().NoError(err)
	s.NotNil(sm)

	// call GetMatchedSubjectMappings with the expected subject properties to match the new subject mapping
	props := []*policy.SubjectProperty{
		{
			ExternalSelectorValue: fixtureScs.Condition.SubjectSets[0].ConditionGroups[0].Conditions[0].SubjectExternalSelectorValue,
		},
	}
	smList, err := s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
	s.Require().NoError(err)
	s.NotZero(smList)

	// verify the list contains only active values and our deactivated value was not found as a match
	for _, sm := range smList {
		s.NotEqual(sm.GetAttributeValue().GetValue(), fixtureAttrVal.Value)
		s.NotEqual(sm.GetAttributeValue().GetId(), fixtureAttrVal.ID)
		s.True(sm.GetAttributeValue().GetActive().GetValue())
	}
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_ConditionSetReusedByMultipleSubjectMappings() {
	selector := ".hello_world"
	toCreate := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{
				ConditionGroups: []*policy.ConditionGroup{
					{
						BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
						Conditions: []*policy.Condition{
							{
								SubjectExternalSelectorValue: selector,
								Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								SubjectExternalValues:        []string{"goodnight_moon"},
							},
						},
					},
				},
			},
		},
	}
	createdSCS, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, toCreate)
	s.Require().NoError(err)
	s.NotNil(createdSCS)

	actionRead := s.f.GetStandardAction(policydb.ActionRead.String())
	actionDelete := s.f.GetStandardAction(policydb.ActionDelete.String())
	actionUpdate := s.f.GetStandardAction(policydb.ActionUpdate.String())

	// Create two subject mappings across different values that reuse the same subject condition set
	attrVal1 := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value1").ID
	sm1, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              attrVal1,
		ExistingSubjectConditionSetId: createdSCS.GetId(),
		Actions:                       []*policy.Action{actionRead, actionDelete, actionUpdate},
	})
	s.Require().NoError(err)
	s.NotNil(sm1)
	attrVal2 := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value2").ID
	sm2, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              attrVal2,
		ExistingSubjectConditionSetId: createdSCS.GetId(),
		Actions:                       []*policy.Action{actionUpdate},
	})
	s.Require().NoError(err)
	s.NotNil(sm2)

	// check matched subject mappings for the selector in the reused SCS
	props := []*policy.SubjectProperty{
		{
			ExternalSelectorValue: selector,
		},
	}

	smList, err := s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
	s.Require().NoError(err)
	s.NotZero(smList)
	s.Len(smList, 2)
	foundSm1 := false
	foundSm2 := false
	for _, sm := range smList {
		smID := sm.GetId()
		foundSCS := sm.GetSubjectConditionSet().GetId()
		foundAttrVal := sm.GetAttributeValue().GetId()
		s.Equal(foundSCS, createdSCS.GetId())
		if smID == sm1.GetId() {
			foundSm1 = true
			s.Equal(sm1.GetAttributeValue().GetId(), foundAttrVal)
		}
		if smID == sm2.GetId() {
			foundSm2 = true
			s.Equal(sm2.GetAttributeValue().GetId(), foundAttrVal)
		}
	}
	s.True(foundSm1)
	s.True(foundSm2)
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_OnlyMatchesOneProperty() {
	selector := ".only_matches_one[]"
	fixtureAttrValID := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value2").ID
	newScs := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{
				ConditionGroups: []*policy.ConditionGroup{
					{
						BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
						Conditions: []*policy.Condition{
							{
								SubjectExternalSelectorValue: selector,
								Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								SubjectExternalValues:        []string{"random_value"},
							},
						},
					},
				},
			},
		},
	}

	actionCreate := s.f.GetStandardAction(policydb.ActionCreate.String())
	actionRead := s.f.GetStandardAction(policydb.ActionRead.String())

	subjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:       fixtureAttrValID,
		Actions:                []*policy.Action{actionCreate, actionRead},
		NewSubjectConditionSet: newScs,
	}

	createdSM, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, subjectMapping)
	s.Require().NoError(err)
	s.NotNil(createdSM)

	props := []*policy.SubjectProperty{
		{
			ExternalSelectorValue: selector,
		},
		{
			ExternalSelectorValue: "random_value_987654321",
		},
	}

	smList, err := s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
	s.Require().NoError(err)
	s.Len(smList, 1)
	s.Equal(smList[0].GetId(), createdSM.GetId())
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_NonExistentField_ReturnsNoMappings() {
	props := []*policy.SubjectProperty{
		{
			ExternalSelectorValue: ".non_existent_field[1]",
		},
	}
	sm, err := s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
	s.Require().NoError(err)
	s.NotZero(sm)
	s.Empty(sm)
}

func (s *SubjectMappingsSuite) TestGetMatchedSubjectMappings_ResponsiveToUpdation() {
	// Create a Subject Condition Set with a specific selector
	initialSelector := ".test_updation_selector"
	updatedSelector := ".updated_selector" // Will be used later for the update

	subjectConditionSet := &subjectmapping.SubjectConditionSetCreate{
		SubjectSets: []*policy.SubjectSet{
			{
				ConditionGroups: []*policy.ConditionGroup{
					{
						BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
						Conditions: []*policy.Condition{
							{
								SubjectExternalSelectorValue: initialSelector,
								Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								SubjectExternalValues:        []string{"test_value"},
							},
						},
					},
				},
			},
		},
	}

	createdSCS, err := s.db.PolicyClient.CreateSubjectConditionSet(s.ctx, subjectConditionSet)
	s.Require().NoError(err)
	s.NotNil(createdSCS)

	// Create a Subject Mapping with the created SCS
	fixtureAttrValID := s.f.GetAttributeValueKey("example.com/attr/attr1/value/value2").ID
	actionRead := s.f.GetStandardAction(policydb.ActionRead.String())

	subjectMapping := &subjectmapping.CreateSubjectMappingRequest{
		AttributeValueId:              fixtureAttrValID,
		Actions:                       []*policy.Action{actionRead},
		ExistingSubjectConditionSetId: createdSCS.GetId(),
	}

	createdSM, err := s.db.PolicyClient.CreateSubjectMapping(s.ctx, subjectMapping)
	s.Require().NoError(err)
	s.NotNil(createdSM)

	// Validate the subject mapping is matched using the initial selector but not updated
	props := []*policy.SubjectProperty{
		{
			ExternalSelectorValue: initialSelector,
		},
	}

	matchedList, err := s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
	s.Require().NoError(err)
	s.Len(matchedList, 1)

	matchedSM := matchedList[0]
	s.Equal(createdSM.GetId(), matchedSM.GetId())

	updatedProps := []*policy.SubjectProperty{
		{
			ExternalSelectorValue: updatedSelector, // This selector is not yet in use
		},
	}

	matchedList, err = s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, updatedProps)
	s.Require().NoError(err)
	s.Empty(matchedList)

	// Update the Subject Condition Set with a different selector
	updateRequest := &subjectmapping.UpdateSubjectConditionSetRequest{
		Id: createdSCS.GetId(),
		SubjectSets: []*policy.SubjectSet{
			{
				ConditionGroups: []*policy.ConditionGroup{
					{
						BooleanOperator: policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND,
						Conditions: []*policy.Condition{
							{
								SubjectExternalSelectorValue: updatedSelector, // Changed selector
								Operator:                     policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN,
								SubjectExternalValues:        []string{"test_value"},
							},
						},
					},
				},
			},
		},
	}

	updatedSCS, err := s.db.PolicyClient.UpdateSubjectConditionSet(s.ctx, updateRequest)
	s.Require().NoError(err)
	s.NotNil(updatedSCS)

	matchedAfterUpdate, err := s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
	s.Require().NoError(err)
	s.Empty(matchedAfterUpdate)

	matchedList, err = s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, updatedProps)
	s.Require().NoError(err)
	s.Len(matchedList, 1)

	matchedSM = matchedList[0]
	s.Equal(createdSM.GetId(), matchedSM.GetId())

	matchedList, err = s.db.PolicyClient.GetMatchedSubjectMappings(s.ctx, props)
	s.Require().NoError(err)
	s.Empty(matchedList)
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
	s.Require().NoError(err)
	s.NotNil(created)

	// update with no changes
	updatedWithoutChange, err := s.db.PolicyClient.UpdateSubjectConditionSet(s.ctx, &subjectmapping.UpdateSubjectConditionSetRequest{
		Id: created.GetId(),
	})
	s.Require().NoError(err)
	s.NotNil(updatedWithoutChange)
	s.Equal(created.GetId(), updatedWithoutChange.GetId())

	// update with changes
	updatedWithChange, err := s.db.PolicyClient.UpdateSubjectConditionSet(s.ctx, &subjectmapping.UpdateSubjectConditionSetRequest{
		Id:                     created.GetId(),
		Metadata:               &common.MetadataMutable{Labels: updateLabels},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_EXTEND,
	})
	s.Require().NoError(err)
	s.NotNil(updatedWithChange)
	s.Equal(created.GetId(), updatedWithChange.GetId())

	// verify the metadata was extended
	got, err := s.db.PolicyClient.GetSubjectConditionSet(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Equal(expectedLabels, got.GetMetadata().GetLabels())

	// update with replace
	updatedWithReplace, err := s.db.PolicyClient.UpdateSubjectConditionSet(s.ctx, &subjectmapping.UpdateSubjectConditionSetRequest{
		Id:                     created.GetId(),
		Metadata:               &common.MetadataMutable{Labels: labels},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE,
	})
	s.Require().NoError(err)
	s.NotNil(updatedWithReplace)
	s.Equal(created.GetId(), updatedWithReplace.GetId())

	// verify the metadata was replaced
	got, err = s.db.PolicyClient.GetSubjectConditionSet(s.ctx, created.GetId())
	s.Require().NoError(err)
	s.NotNil(got)
	s.Equal(created.GetId(), got.GetId())
	s.Equal(labels, got.GetMetadata().GetLabels())
}
