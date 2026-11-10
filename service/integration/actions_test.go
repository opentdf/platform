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
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
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
	name1 := fmt.Sprintf("scoped-list-nopage-1-%d", time.Now().UnixNano())
	name2 := fmt.Sprintf("scoped-list-nopage-2-%d", time.Now().UnixNano())

	created1, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name:        name1,
		NamespaceId: s.defaultNamespaceID(),
	})
	s.Require().NoError(err)

	created2, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name:        name2,
		NamespaceId: s.defaultNamespaceID(),
	})
	s.Require().NoError(err)

	list, err := s.db.PolicyClient.ListActions(s.ctx, &actions.ListActionsRequest{NamespaceId: s.defaultNamespaceID()})
	s.NotNil(list)
	s.Require().NoError(err)

	foundCustomAction1 := false
	foundCustomAction2 := false
	foundRead := false
	foundCreate := false
	foundUpdate := false
	foundDelete := false

	for _, action := range list.GetActionsCustom() {
		switch action.GetId() {
		case created1.GetId():
			foundCustomAction1 = true
		case created2.GetId():
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
			Name:        name,
			NamespaceId: s.defaultNamespaceID(),
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

	list, err := s.db.PolicyClient.ListActions(s.ctx, &actions.ListActionsRequest{NamespaceId: s.defaultNamespaceID()})
	s.Require().NoError(err)
	s.NotNil(list)

	assertIDsInOrder(s.T(), list.GetActionsCustom(), func(a *policy.Action) string { return a.GetId() }, thirdID, secondID, firstID)
}

func (s *ActionsSuite) Test_ListActions_Pagination_Succeeds() {
	list, err := s.db.PolicyClient.ListActions(s.ctx, &actions.ListActionsRequest{NamespaceId: s.defaultNamespaceID()})
	s.NotNil(list)
	s.Require().NoError(err)
	total := list.GetPagination().GetTotal()

	higherOffsetThanListCount := total + 1
	list, err = s.db.PolicyClient.ListActions(s.ctx, &actions.ListActionsRequest{
		NamespaceId: s.defaultNamespaceID(),
		Pagination: &policy.PageRequest{
			Offset: higherOffsetThanListCount,
		},
	})
	s.NotNil(list)
	s.Require().NoError(err)
	s.Equal(int32(0), list.GetPagination().GetNextOffset())
	s.Equal(higherOffsetThanListCount, list.GetPagination().GetCurrentOffset())

	list, err = s.db.PolicyClient.ListActions(s.ctx, &actions.ListActionsRequest{
		NamespaceId: s.defaultNamespaceID(),
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
		NamespaceId: s.defaultNamespaceID(),
		Pagination: &policy.PageRequest{
			Limit: s.db.LimitMax + 1,
		},
	})
	s.Nil(list)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrListLimitTooLarge)
}

func (s *ActionsSuite) Test_ListActions_FiltersCustomActionsByNamespace_Succeeds() {
	name := fmt.Sprintf("scoped-list-action-%d", time.Now().UnixNano())

	first, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name:        name,
		NamespaceId: s.defaultNamespaceID(),
	})
	s.Require().NoError(err)

	second, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name:        name,
		NamespaceId: s.otherNamespaceID(),
	})
	s.Require().NoError(err)

	list, err := s.db.PolicyClient.ListActions(s.ctx, &actions.ListActionsRequest{NamespaceId: s.defaultNamespaceID()})
	s.Require().NoError(err)

	foundFirst := false
	foundSecond := false
	for _, action := range list.GetActionsCustom() {
		if action.GetId() == first.GetId() {
			foundFirst = true
			s.Equal(s.defaultNamespaceID(), action.GetNamespace().GetId())
		}
		if action.GetId() == second.GetId() {
			foundSecond = true
		}
	}

	s.True(foundFirst)
	s.False(foundSecond)
}

func (s *ActionsSuite) Test_ListActions_WithNamespace_DoesNotLeakStandardActionsFromOtherNamespaces() {
	createdNamespace, err := s.db.PolicyClient.CreateNamespace(s.ctx, &namespaces.CreateNamespaceRequest{
		Name: fmt.Sprintf("list-actions-standard-scope-%d", time.Now().UnixNano()),
	})
	s.Require().NoError(err)
	s.Require().NotNil(createdNamespace)

	list, err := s.db.PolicyClient.ListActions(s.ctx, &actions.ListActionsRequest{NamespaceId: createdNamespace.GetId()})
	s.Require().NoError(err)
	s.Require().NotNil(list)

	expected := map[string]bool{
		"create": false,
		"read":   false,
		"update": false,
		"delete": false,
	}

	for _, action := range list.GetActionsStandard() {
		s.Require().NotNil(action.GetNamespace())
		s.Equal(createdNamespace.GetId(), action.GetNamespace().GetId())
		if _, ok := expected[action.GetName()]; ok {
			expected[action.GetName()] = true
		}
	}

	for name, found := range expected {
		s.True(found, "expected standard action %s scoped to namespace", name)
	}
}

func (s *ActionsSuite) Test_ListActions_WithoutNamespace_ReturnsAcrossNamespaces_Succeeds() {
	name := fmt.Sprintf("global-list-action-%d", time.Now().UnixNano())

	inDefault, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name:        name,
		NamespaceId: s.defaultNamespaceID(),
	})
	s.Require().NoError(err)

	inOther, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name:        name,
		NamespaceId: s.otherNamespaceID(),
	})
	s.Require().NoError(err)

	list, err := s.db.PolicyClient.ListActions(s.ctx, &actions.ListActionsRequest{})
	s.Require().NoError(err)

	foundDefault := false
	foundOther := false
	for _, action := range list.GetActionsCustom() {
		if action.GetId() == inDefault.GetId() {
			foundDefault = true
			s.Equal(s.defaultNamespaceID(), action.GetNamespace().GetId())
		}
		if action.GetId() == inOther.GetId() {
			foundOther = true
			s.Equal(s.otherNamespaceID(), action.GetNamespace().GetId())
		}
	}

	s.True(foundDefault)
	s.True(foundOther)
}

func (s *ActionsSuite) Test_ListActions_LegacyCustomAction_ScopedExcluded_UnscopedIncluded_Succeeds() {
	legacy := s.f.GetCustomActionKey("custom_action_1")
	scopedName := fmt.Sprintf("scoped-list-action-%d", time.Now().UnixNano())
	scoped, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name:        scopedName,
		NamespaceId: s.defaultNamespaceID(),
	})
	s.Require().NoError(err)
	s.NotNil(scoped)

	assertLegacyAbsent := func(list *actions.ListActionsResponse) {
		s.T().Helper()
		found := false
		for _, action := range list.GetActionsCustom() {
			if action.GetId() == legacy.ID {
				found = true
			}
		}
		s.False(found)
	}

	listByID, err := s.db.PolicyClient.ListActions(s.ctx, &actions.ListActionsRequest{NamespaceId: s.defaultNamespaceID()})
	s.Require().NoError(err)
	assertLegacyAbsent(listByID)

	listByFQN, err := s.db.PolicyClient.ListActions(s.ctx, &actions.ListActionsRequest{NamespaceFqn: s.defaultNamespaceFQN()})
	s.Require().NoError(err)
	assertLegacyAbsent(listByFQN)

	listUnscoped, err := s.db.PolicyClient.ListActions(s.ctx, &actions.ListActionsRequest{})
	s.Require().NoError(err)

	foundUnscoped := false
	foundScoped := false
	for _, action := range listUnscoped.GetActionsCustom() {
		if action.GetId() == legacy.ID {
			foundUnscoped = true
			s.Nil(action.GetNamespace())
		}
		if action.GetId() == scoped.GetId() {
			foundScoped = true
			s.Require().NotNil(action.GetNamespace())
			s.Equal(s.defaultNamespaceID(), action.GetNamespace().GetId())
		}
	}
	s.True(foundUnscoped)
	s.True(foundScoped)
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
	name := fmt.Sprintf("get-by-name-action-%d", time.Now().UnixNano())
	customAction, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name:        name,
		NamespaceId: s.defaultNamespaceID(),
	})
	s.Require().NoError(err)
	s.NotNil(customAction)

	action, err := s.db.PolicyClient.GetAction(s.ctx, &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Name{
			Name: customAction.GetName(),
		},
		NamespaceId: s.defaultNamespaceID(),
	})
	s.NotNil(action)
	s.Require().NoError(err)
	s.Equal(customAction.GetId(), action.GetId())
	s.Equal(customAction.GetName(), action.GetName())
	s.Require().NotNil(action.GetNamespace())
	s.Equal(s.defaultNamespaceID(), action.GetNamespace().GetId())
	s.NotNil(action.GetMetadata())
}

func (s *ActionsSuite) Test_GetAction_Name_ResolvesByNamespace_Succeeds() {
	name := fmt.Sprintf("scoped-get-action-%d", time.Now().UnixNano())

	inDefaultNs, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name:        name,
		NamespaceId: s.defaultNamespaceID(),
	})
	s.Require().NoError(err)

	inOtherNs, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name:        name,
		NamespaceId: s.otherNamespaceID(),
	})
	s.Require().NoError(err)

	gotDefault, err := s.db.PolicyClient.GetAction(s.ctx, &actions.GetActionRequest{
		Identifier:  &actions.GetActionRequest_Name{Name: name},
		NamespaceId: s.defaultNamespaceID(),
	})
	s.Require().NoError(err)
	s.Equal(inDefaultNs.GetId(), gotDefault.GetId())
	s.Equal(s.defaultNamespaceID(), gotDefault.GetNamespace().GetId())

	gotOther, err := s.db.PolicyClient.GetAction(s.ctx, &actions.GetActionRequest{
		Identifier:  &actions.GetActionRequest_Name{Name: name},
		NamespaceId: s.otherNamespaceID(),
	})
	s.Require().NoError(err)
	s.Equal(inOtherNs.GetId(), gotOther.GetId())
	s.Equal(s.otherNamespaceID(), gotOther.GetNamespace().GetId())
}

func (s *ActionsSuite) Test_GetAction_Name_LegacyCustomAction_UnscopedSucceeds_ScopedFails() {
	legacy := s.f.GetCustomActionKey("other_special_action")

	byUnscoped, err := s.db.PolicyClient.GetAction(s.ctx, &actions.GetActionRequest{
		Identifier: &actions.GetActionRequest_Name{Name: legacy.Name},
	})
	s.Require().NoError(err)
	s.NotNil(byUnscoped)
	s.Equal(legacy.ID, byUnscoped.GetId())
	s.Nil(byUnscoped.GetNamespace())

	assertLegacyGet := func(action *policy.Action, err error) {
		s.T().Helper()
		s.Nil(action)
		s.Require().Error(err)
		s.Require().ErrorIs(err, db.ErrNotFound)
	}

	byID, err := s.db.PolicyClient.GetAction(s.ctx, &actions.GetActionRequest{
		Identifier:  &actions.GetActionRequest_Name{Name: legacy.Name},
		NamespaceId: s.defaultNamespaceID(),
	})
	assertLegacyGet(byID, err)

	byFQN, err := s.db.PolicyClient.GetAction(s.ctx, &actions.GetActionRequest{
		Identifier:   &actions.GetActionRequest_Name{Name: legacy.Name},
		NamespaceFqn: s.defaultNamespaceFQN(),
	})
	assertLegacyGet(byFQN, err)

	byOtherID, err := s.db.PolicyClient.GetAction(s.ctx, &actions.GetActionRequest{
		Identifier:  &actions.GetActionRequest_Name{Name: legacy.Name},
		NamespaceId: s.otherNamespaceID(),
	})
	assertLegacyGet(byOtherID, err)

	byOtherFQN, err := s.db.PolicyClient.GetAction(s.ctx, &actions.GetActionRequest{
		Identifier:   &actions.GetActionRequest_Name{Name: legacy.Name},
		NamespaceFqn: s.otherNamespaceFQN(),
	})
	assertLegacyGet(byOtherFQN, err)
}

func (s *ActionsSuite) Test_CreateListGetAction_WithNamespaceFQN_Succeeds() {
	name := fmt.Sprintf("fqn-scoped-action-%d", time.Now().UnixNano())

	created, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name:         name,
		NamespaceFqn: s.otherNamespaceFQN(),
	})
	s.Require().NoError(err)
	s.Equal(name, created.GetName())
	s.Equal(s.otherNamespaceID(), created.GetNamespace().GetId())
	s.Equal(s.otherNamespaceFQN(), created.GetNamespace().GetFqn())

	list, err := s.db.PolicyClient.ListActions(s.ctx, &actions.ListActionsRequest{NamespaceFqn: s.otherNamespaceFQN()})
	s.Require().NoError(err)

	found := false
	for _, action := range list.GetActionsCustom() {
		if action.GetId() == created.GetId() {
			found = true
			s.Equal(s.otherNamespaceID(), action.GetNamespace().GetId())
			s.Equal(s.otherNamespaceFQN(), action.GetNamespace().GetFqn())
		}
	}
	s.True(found)

	got, err := s.db.PolicyClient.GetAction(s.ctx, &actions.GetActionRequest{
		Identifier:   &actions.GetActionRequest_Name{Name: name},
		NamespaceFqn: s.otherNamespaceFQN(),
	})
	s.Require().NoError(err)
	s.Equal(created.GetId(), got.GetId())
	s.Equal(s.otherNamespaceID(), got.GetNamespace().GetId())
	s.Equal(s.otherNamespaceFQN(), got.GetNamespace().GetFqn())
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
		NamespaceId: s.defaultNamespaceID(),
	})
	s.Nil(action)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrNotFound)
}

func (s *ActionsSuite) Test_CreateAction_Succeeds() {
	newName := "new_custom_action_createaction"
	action, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name:        newName,
		NamespaceId: s.defaultNamespaceID(),
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
	name := fmt.Sprintf("create-conflict-action-%d", time.Now().UnixNano())
	_, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name:        name,
		NamespaceId: s.defaultNamespaceID(),
	})
	s.Require().NoError(err)

	action, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name:        name,
		NamespaceId: s.defaultNamespaceID(),
	})
	s.Nil(action)
	s.Require().Error(err)
	s.Require().ErrorIs(err, db.ErrUniqueConstraintViolation)
}

func (s *ActionsSuite) Test_CreateAction_MissingNamespace_SucceedsInLegacyMode() {
	action, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name: fmt.Sprintf("missing-namespace-%d", time.Now().UnixNano()),
	})
	s.Require().NoError(err)
	s.NotNil(action)
	s.Nil(action.GetNamespace())
}

func (s *ActionsSuite) Test_CreateAction_NormalizesToLowerCase() {
	newName := "New_Custom_Action_CreateAction_UPPER"
	action, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name:        newName,
		NamespaceId: s.defaultNamespaceID(),
	},
	)
	s.NotNil(action)
	s.Require().NoError(err)
	s.Equal(strings.ToLower(newName), action.GetName())
}

func (s *ActionsSuite) Test_UpdateAction_Succeeds() {
	newAction, err := s.db.PolicyClient.CreateAction(s.ctx, &actions.CreateActionRequest{
		Name:        "new_custom_action_updateaction",
		NamespaceId: s.defaultNamespaceID(),
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
		Name:        "testing_update_action_casing",
		NamespaceId: s.defaultNamespaceID(),
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
		Name:        "new_custom_action_deleteaction",
		NamespaceId: s.defaultNamespaceID(),
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

func (s *ActionsSuite) defaultNamespaceID() string {
	return s.f.GetNamespaceKey("example.com").ID
}

func (s *ActionsSuite) otherNamespaceID() string {
	return s.f.GetNamespaceKey("example.net").ID
}

func (s *ActionsSuite) defaultNamespaceFQN() string {
	return "https://" + s.f.GetNamespaceKey("example.com").Name
}

func (s *ActionsSuite) otherNamespaceFQN() string {
	return "https://" + s.f.GetNamespaceKey("example.net").Name
}

func TestActionsSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping actions integration tests")
	}
	suite.Run(t, new(ActionsSuite))
}
