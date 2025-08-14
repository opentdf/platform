package cukes

import (
	"context"
	"errors"

	"github.com/cucumber/godog"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
)

const (
	createNamespaceResponseKey = "createNamespaceResponse"
)

type NamespacesStepDefinitions struct{}

func (ns *NamespacesStepDefinitions) thereIsAnError(ctx context.Context) (context.Context, error) {
	err := GetPlatformScenarioContext(ctx).GetError()
	if err == nil {
		return ctx, errors.New("error not present")
	}
	return ctx, nil
}

func (ns *NamespacesStepDefinitions) thereIsNoError(ctx context.Context) (context.Context, error) {
	err := GetPlatformScenarioContext(ctx).GetError()
	if err != nil {
		return ctx, errors.New("error is present")
	}
	return ctx, nil
}

func (ns *NamespacesStepDefinitions) aNamespace(ctx context.Context, namespaceName string, referenceID string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	resp, err := scenarioContext.SDK.Namespaces.CreateNamespace(ctx, &namespaces.CreateNamespaceRequest{Name: namespaceName})
	scenarioContext.SetError(err)
	scenarioContext.RecordObject(createNamespaceResponseKey, &resp)
	scenarioContext.RecordObject(referenceID, resp.GetNamespace().GetId())
	return ctx, nil
}

func RegisterNamespaceStepDefinitions(ctx *godog.ScenarioContext) {
	stepDefinitions := NamespacesStepDefinitions{}
	ctx.Step(`^I submit a request to create a namespace with name "([^"]*)" and reference id "([^"]*)"$`, stepDefinitions.aNamespace)
	ctx.Step(`the response should be successful$`, stepDefinitions.thereIsNoError)
	ctx.Step(`the response should be unsuccessful$`, stepDefinitions.thereIsAnError)
}
