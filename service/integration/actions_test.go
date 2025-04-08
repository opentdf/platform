package integration

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/actions"
	"github.com/opentdf/platform/service/internal/fixtures"
	"github.com/opentdf/platform/service/pkg/db"
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
	s.db = fixtures.NewDBInterface(c)
	s.f = fixtures.NewFixture(s.db)
	s.f.Provision()
}

func (s *ActionsSuite) TearDownSuite() {
	slog.Info("tearing down db.Actions test suite")
	s.f.TearDown()
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
		switch action.Name {
		case fixtureCustomAction1.Name:
			foundCustomAction1 = true
		case fixtureCustomAction2.Name:
			foundCustomAction2 = true
		}
	}
	for _, action := range list.GetActionsStandard() {
		switch action.Name {
		case "read":
			foundRead = true
		case "create":
			foundCreate = true
		case "update":
			foundUpdate = true
		case "delete":
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
	s.Equal(int32(total), list.GetPagination().GetTotal())
	s.Equal(int32(0), list.GetPagination().GetCurrentOffset())
	s.Equal(int32(total-1), list.GetPagination().GetNextOffset())
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
	actionRead := s.f.GetStandardAction("read")

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
			Id: actionRead.Id,
		},
	})
	s.NotNil(action)
	s.Require().NoError(err)
	s.Equal(actionRead.Id, action.GetId())
	s.Equal(actionRead.Name, action.GetName())
	s.NotNil(action.GetMetadata())
}

func (s *ActionsSuite) Test_GetAction_Name_Succeeds() {
	customAction := s.f.GetCustomActionKey("other_special_action")
	actionCreate := s.f.GetStandardAction("create")
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
			Name: actionCreate.Name,
		},
	})
	s.NotNil(action)
	s.Require().NoError(err)
	s.Equal(actionCreate.Name, action.GetName())
	s.Equal(actionCreate.Id, action.GetId())
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
	s.NotEqual("", action.GetId())
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

func TestActionsSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping actions integration tests")
	}
	suite.Run(t, new(ActionsSuite))
}
