package registeredresources

import (
	"context"

	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	policyconfig "github.com/opentdf/platform/service/policy/config"
)

type actionAdditionCounter interface {
	GetCountActionsWithNewAdditions(context.Context, string, string, []string) (int64, int64, error)
}

func registeredResourceActionNames(actionAttributeValues []*registeredresources.ActionAttributeValue) []string {
	actionNames := make([]string, 0, len(actionAttributeValues))
	for _, value := range actionAttributeValues {
		if name := value.GetActionName(); name != "" {
			actionNames = append(actionNames, name)
		}
	}
	return actionNames
}

func enforceActionAdditionLimit(ctx context.Context, client actionAdditionCounter, limit int64, namespaceID, namespaceFQN string, actionNames []string) error {
	if limit <= 0 || len(actionNames) == 0 {
		return nil
	}

	current, additions, err := client.GetCountActionsWithNewAdditions(ctx, namespaceID, namespaceFQN, actionNames)
	if err != nil {
		return err
	}
	return policyconfig.EnforceObjectLimit(policyconfig.ObjectTypeActionsPerNamespace, limit, current, int(additions))
}
