package cukes

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/cucumber/godog"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
)

const (
	createNamespaceResponseKey = "createNamespaceResponse"
	namespaceIDKey             = "namespace_id"
	namespaceFQNKey            = "namespace_fqn"
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

func (ns *NamespacesStepDefinitions) thereIsAPermissionDeniedError(ctx context.Context) (context.Context, error) {
	err := GetPlatformScenarioContext(ctx).GetError()
	if err == nil {
		return ctx, errors.New("expected permission denied error, got nil")
	}
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		return ctx, fmt.Errorf("expected permission denied error, got %v: %w", connect.CodeOf(err), err)
	}
	return ctx, nil
}

func (ns *NamespacesStepDefinitions) aNamespace(ctx context.Context, namespaceName string, referenceID string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()
	resp, err := scenarioContext.SDK.Namespaces.CreateNamespace(ctx, &namespaces.CreateNamespaceRequest{Name: namespaceName})
	scenarioContext.SetError(err)
	scenarioContext.RecordObject(createNamespaceResponseKey, &resp)
	if err == nil {
		scenarioContext.RecordObject(referenceID, resp.GetNamespace().GetId())
		scenarioContext.RecordObject(referenceID+"_fqn", resp.GetNamespace().GetFqn())
	}
	return ctx, nil
}

func RegisterNamespaceStepDefinitions(ctx *godog.ScenarioContext) {
	stepDefinitions := NamespacesStepDefinitions{}
	ctx.Step(`^I submit a request to create a namespace with name "([^"]*)" and reference id "([^"]*)"$`, stepDefinitions.aNamespace)
	ctx.Step(`the response should be successful$`, stepDefinitions.thereIsNoError)
	ctx.Step(`the response should be unsuccessful$`, stepDefinitions.thereIsAnError)
	ctx.Step(`the response should be permission denied$`, stepDefinitions.thereIsAPermissionDeniedError)
}
