package integration

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
	policydb "github.com/opentdf/platform/service/policy/db"
	"github.com/stretchr/testify/suite"
)

type ActionsSuite struct {
	suite.Suite
	f   fixtures.Fixtures
	db  fixtures.DBInterface
	ctx context.Context //nolint:containedctx // context is used in the test suite
}

func (s *ActionsSuite) SetupSuite() {
	slog.Info("setting up db.Actions test suite")
	s.ctx = context.Background()
	c := *Config

	c.DB.Schema = "test_opentdf_actions"
	s.db = fixtures.NewDBInterface(s.ctx, c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision(s.ctx)
}

func (s *ActionsSuite) TearDownSuite() {
	slog.Info("tearing down db.Actions test suite")
	s.f.TearDown(s.ctx)
}

func (s *ActionsSuite) Test_ListActions_NoPagination_Succeeds() {
	fixtureCustomAction1 := s.f.GetCustomActionKey("custom_action_1")
	fixtureCustomAction2 := s.f.GetCustomActionKey("other_special_action")

	list, err := s.db.PolicyClient.ListActions(s.ctx, &actions.ListActionsRequest{})
	s.NotNil(list)
	s.Require().NoError(err)

	foundCustomAction1 := false
	foundCustomAction2 := false
	foundRead := false
	foundCreate := false
	foundUpdate := false
	foundDelete := false

	for _, action := range list.GetActionsCustom() {
		switch action.GetName() {
		case fixtureCustomAction1.Name:
			foundCustomAction1 = true
		case fixtureCustomAction2.Name:
			foundCustomAction2 = true
		}
	}
	for _, action := range list.GetActionsStandard() {
		switch policydb.ActionStandard(action.GetName()) {
		case policydb.ActionRead:
			foundRead = true
		case policydb.ActionCreate:
			foundCreate = true
		case policydb.ActionUpdate:
			foundUpdate = true
		case policydb.ActionDelete:
			foundDelete = true
		}
	}
	s.True(foundCustomAction1)
	s.True(foundCustomAction2)
	s.True(foundRead)
	s.True(foundCreate)
	s.True(foundUpdate)
	s.True(foundDelete)
}

func (s *ActionsSuite) Test_ListActions_OrdersByCreatedAt_Succeeds() {
	suffix := time.Now().UnixNano()
	create := func(i int) string {
		name := fmt.Sprintf("order-test-action-%d-%d", i, suffix)
		created, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
			Name: name,
		})
		s.Require().NoError(err)
		s.Require().NotNil(created)
		return created.GetId()
	}

	firstID := create(1)
	time.Sleep(5 * time.Millisecond)
	secondID := create(2)
	time.Sleep(5 * time.Millisecond)
	thirdID := create(3)

	list, err := s.db.PolicyClient.ListActions(s.ctx, &actions.ListActionsRequest{})
	s.Require().NoError(err)
	s.NotNil(list)

	assertIDsInOrder(s.T(), list.GetActionsCustom(), func(a *policy.Action) string { return a.GetId() }, firstID, secondID, thirdID)
}

func (s *ActionsSuite) Test_ListActions_Pagination_Succeeds() {
	list, err := s.db.PolicyClient.ListActions(s.ctx, &actions.ListActionsRequest{})
	s.NotNil(list)
	s.Require().NoError(err)
	total := list.GetPagination().GetTotal()

	higherOffsetThanListCount := total + 1
	list, err = s.db.PolicyClient.ListActions(s.ctx, &actions.ListActionsRequest{
		Pagination: &policy.PageRequest{
			Offset: higherOffsetThanListCount,
		},
	})
	s.NotNil(list)
	s.Require().NoError(err)
	s.Equal(int32(0), list.GetPagination().GetNextOffset())
	s.Equal(higherOffsetThanListCount, list.GetPagination().GetCurrentOffset())

	list, err = s.db.PolicyClient.ListActions(s.ctx, &actions.ListActionsRequest{
		Pagination: &policy.PageRequest{
			Offset: 0,
			Limit:  total - 1,
		},
	})
	s.NotNil(list)
	s.Require().NoError(err)
	s.Equal(total, list.GetPagination().GetTotal())
	s.Equal(int32(0), list.GetPagination().GetCurrentOffset())
	s.Equal(total-1, list.GetPagination().GetNextOffset())
}

func (s *ActionsSuite) Test_ListActions_LimitLargerThanConfigured_Fails() {
	list, err := s.db.PolicyClient.ListActions(s.ctx, &actions.ListActionsRequest{
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax + 1,
		},
	})
	s.Nil(list)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrListLimitTooLarge)
}

func (s *ActionsSuite) Test_GetAction_Id_Succeeds() {
	fixtureCustomAction1 := s.f.GetCustomActionKey("custom_action_1")
	actionRead := s.f.GetStandardAction(policydb.ActionRead.String())

	action, err := s.db.PolicyClient.GetAction(s.ctx, &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Id{
			Id: fixtureCustomAction1.ID,
		},
	})
	s.NotNil(action)
	s.Require().NoError(err)

	s.Equal(fixtureCustomAction1.ID, action.GetId())
	s.Equal(fixtureCustomAction1.Name, action.GetName())
	s.NotNil(action.GetMetadata())

	action, err = s.db.PolicyClient.GetAction(s.ctx, &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Id{
			Id: actionRead.GetId(),
		},
	})
	s.NotNil(action)
	s.Require().NoError(err)
	s.Equal(actionRead.GetId(), action.GetId())
	s.Equal(actionRead.GetName(), action.GetName())
	s.NotNil(action.GetMetadata())
}

func (s *ActionsSuite) Test_GetAction_Name_Succeeds() {
	customAction := s.f.GetCustomActionKey("other_special_action")
	actionCreate := s.f.GetStandardAction(policydb.ActionCreate.String())
	action, err := s.db.PolicyClient.GetAction(s.ctx, &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Name{
			Name: customAction.Name,
		},
	})
	s.NotNil(action)
	s.Require().NoError(err)
	s.Equal(customAction.ID, action.GetId())
	s.Equal(customAction.Name, action.GetName())
	s.NotNil(action.GetMetadata())

	action, err = s.db.PolicyClient.GetAction(s.ctx, &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Name{
			Name: actionCreate.GetName(),
		},
	})
	s.NotNil(action)
	s.Require().NoError(err)
	s.Equal(actionCreate.GetName(), action.GetName())
	s.Equal(actionCreate.GetId(), action.GetId())
	s.NotNil(action.GetMetadata())
}

func (s *ActionsSuite) Test_GetAction_NonExistent_Fails() {
	action, err := s.db.PolicyClient.GetAction(s.ctx, &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Id{
			Id: nonExistingActionUUID,
		},
	})
	s.Nil(action)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)

	action, err = s.db.PolicyClient.GetAction(s.ctx, &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Name{
			Name: "totally_unknown_action",
		},
	})
	s.Nil(action)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *ActionsSuite) Test_CreateAction_Succeeds() {
	newName := "new_custom_action_createaction"
	action, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name: newName,
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"label1": "value1",
				"label2": "value2",
			},
		},
	})
	s.NotNil(action)
	s.Require().NoError(err)
	s.NotEmpty(action.GetId())
	s.Equal(newName, action.GetName())
	s.NotNil(action.GetMetadata())
	s.Equal("value1", action.GetMetadata().GetLabels()["label1"])
	s.Equal("value2", action.GetMetadata().GetLabels()["label2"])
}

func (s *ActionsSuite) Test_CreateAction_Conflict_Fails() {
	fixtureCustomAction := s.f.GetCustomActionKey("custom_action_1")
	action, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name: fixtureCustomAction.Name,
	},
	)
	s.Nil(action)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
}

func (s *ActionsSuite) Test_CreateAction_NormalizesToLowerCase() {
	newName := "New_Custom_Action_CreateAction_UPPER"
	action, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name: newName,
	},
	)
	s.NotNil(action)
	s.Require().NoError(err)
	s.Equal(strings.ToLower(newName), action.GetName())
}

func (s *ActionsSuite) Test_UpdateAction_Succeeds() {
	newAction, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name: "new_custom_action_updateaction",
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"original": "original_value",
			},
		},
	})
	s.NotNil(newAction)
	s.Require().NoError(err)
	s.NotEmpty(newAction.GetId())
	s.Equal("new_custom_action_updateaction", newAction.GetName())

	differentName := "new_custom_action_updateaction_renamed"
	updatedAction, err := s.db.PolicyClient.UpdateAction(s.ctx, &actions.UpdateActionRequest{
		Id:   newAction.GetId(),
		Name: differentName,
		Metadata: &common.MetadataMutable{
			Labels: map[string]string{
				"original": "replaced",
			},
		},
		MetadataUpdateBehavior: common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE,
	})
	s.NotNil(updatedAction)
	s.Require().NoError(err)

	got, err := s.db.PolicyClient.GetAction(s.ctx, &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Id{
			Id: updatedAction.GetId(),
		},
	})
	s.NotNil(got)
	s.Require().NoError(err)
	s.Equal(differentName, got.GetName())
	s.Equal("replaced", got.GetMetadata().GetLabels()["original"])
}

func (s *ActionsSuite) Test_UpdateAction_NormalizesToLowerCase() {
	newAction, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name: "testing_update_action_casing",
	})
	s.NotNil(newAction)
	s.Require().NoError(err)
	s.NotEmpty(newAction.GetId())
	s.Equal("testing_update_action_casing", newAction.GetName())

	differentName := "UppER_CasE_Change"
	updatedAction, err := s.db.PolicyClient.UpdateAction(s.ctx, &actions.UpdateActionRequest{
		Id:   newAction.GetId(),
		Name: differentName,
	})
	s.NotNil(updatedAction)
	s.Require().NoError(err)

	got, err := s.db.PolicyClient.GetAction(s.ctx, &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Id{
			Id: updatedAction.GetId(),
		},
	})
	s.NotNil(got)
	s.Require().NoError(err)
	s.Equal(strings.ToLower(differentName), got.GetName())
}

func (s *ActionsSuite) Test_UpdateAction_Conflict_Fails() {
	fixtureCustomAction := s.f.GetCustomActionKey("custom_action_1")
	fixtureCustomAction2 := s.f.GetCustomActionKey("other_special_action")
	action, err := s.db.PolicyClient.UpdateAction(s.ctx, &actions.UpdateActionRequest{
		Id:   fixtureCustomAction.ID,
		Name: fixtureCustomAction2.Name,
	})
	s.Nil(action)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
}

func (s *ActionsSuite) Test_UpdateAction_NonExistent_Fails() {
	action, err := s.db.PolicyClient.UpdateAction(s.ctx, &actions.UpdateActionRequest{
		Id:   nonExistingActionUUID,
		Name: "new_name_nonexistent",
	})
	s.Nil(action)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *ActionsSuite) Test_DeleteAction_Succeeds() {
	created, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name: "new_custom_action_deleteaction",
	})
	s.NotNil(created)
	s.Require().NoError(err)
	s.NotEmpty(created.GetId())

	deleted, err := s.db.PolicyClient.DeleteAction(s.ctx, &actions.DeleteActionRequest{
		Id: created.GetId(),
	})
	s.NotNil(deleted)
	s.Require().NoError(err)
	s.Equal(created.GetId(), deleted.GetId())

	got, err := s.db.PolicyClient.GetAction(s.ctx, &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Id{
			Id: created.GetId(),
		},
	})
	s.Nil(got)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *ActionsSuite) Test_DeleteAction_NonExistent_Fails() {
	action, err := s.db.PolicyClient.DeleteAction(s.ctx, &actions.DeleteActionRequest{
		Id: nonExistingActionUUID,
	})
	s.Nil(action)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *ActionsSuite) Test_DeleteAction_StandardAction_Fails() {
	actionRead := s.f.GetStandardAction(policydb.ActionRead.String())
	action, err := s.db.PolicyClient.DeleteAction(s.ctx, &actions.DeleteActionRequest{
		Id: actionRead.GetId(),
	})
	s.Nil(action)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrRestrictViolation)
	s.Contains(err.Error(), actionRead.GetName())
}

func TestActionsSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping actions integration tests")
	}
	suite.Run(t, new(ActionsSuite))
}
