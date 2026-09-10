package cukes

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/cucumber/godog"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
)

const (
	createAttributeResponseKey = "createAttributeResponse"
)

type AttributesStepDefinitions struct {
	PlatformCukesContext *PlatformTestSuiteContext
}

func parseAttributeRule(rule string) (policy.AttributeRuleTypeEnum, error) {
	switch strings.TrimSpace(rule) {
	case "anyOf":
		return policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, nil
	case "allOf":
		return policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF, nil
	case "hierarchy":
		return policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY, nil
	default:
		return policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED, fmt.Errorf("unknown attribute rule type %s", rule)
	}
}

func (s *AttributesStepDefinitions) aAttributeDef(ctx context.Context, _ string, _ string) (context.Context, error) {
	return ctx, nil
}

func (s *AttributesStepDefinitions) iSendARequestToCreateAnAttributeWith(ctx context.Context, tbl *godog.Table) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	createAttrRequests, err := s.createAttributeRequestFromTable(scenarioContext, tbl)
	scenarioContext.ClearError()
	if err == nil {
		for _, req := range createAttrRequests {
			resp, respErr := scenarioContext.SDK.Attributes.CreateAttribute(ctx, req)
			scenarioContext.SetError(respErr)
			scenarioContext.RecordObject(createAttributeResponseKey, resp)
		}
	}
	return ctx, err
}

func (s *AttributesStepDefinitions) createAttributeRequestFromTable(scenarioContext *PlatformScenarioContext, tbl *godog.Table) ([]*attributes.CreateAttributeRequest, error) {
	cellMap := make(map[int]string)
	requests := []*attributes.CreateAttributeRequest{}
	for i, row := range tbl.Rows {
		if i == 0 {
			for c, cell := range row.Cells {
				cellMap[c] = cell.Value
			}
		} else {
			createAttributeRequest := attributes.CreateAttributeRequest{}
			for c, cell := range row.Cells {
				cellName := cellMap[c]
				switch cellName {
				case "namespace_id":
					id, ok := scenarioContext.GetObject(cell.Value).(string)
					if !ok {
						return nil, errors.New("unable to extract namespace ID")
					}
					createAttributeRequest.NamespaceId = id
				case nameKey:
					createAttributeRequest.Name = strings.TrimSpace(cell.Value)
				case "rule":
					switch strings.TrimSpace(cell.Value) {
					case "anyOf":
						createAttributeRequest.Rule = policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF
					case "allOf":
						createAttributeRequest.Rule = policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF
					case "hierarchy":
						createAttributeRequest.Rule = policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY
					default:
						return requests, fmt.Errorf("unknown attribute rule type %s", cell.Value)
					}
				case "values":
					values := []string{}
					for _, value := range strings.Split(cell.Value, ",") {
						values = append(values, strings.TrimSpace(value))
					}
					createAttributeRequest.Values = values
				default:
					return requests, fmt.Errorf("invalid table cell name: %s", cellName)
				}
			}
			requests = append(requests, &createAttributeRequest)
		}
	}
	return requests, nil
}

// iSendARequestToCreateAnAttributeWithGeneratedValues creates an attribute with valueCount
// programmatically-generated values (v0000, v0001, ...), too many to list inline. It records the
// created attribute under referenceID so a subject mapping can later be added for each value,
// reproducing the many-values shape of opentdf/platform#3821.
func (s *AttributesStepDefinitions) iSendARequestToCreateAnAttributeWithGeneratedValues(ctx context.Context, referenceID, namespaceRef, name, rule string, valueCount int) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()

	nsID, ok := scenarioContext.GetObject(strings.TrimSpace(namespaceRef)).(string)
	if !ok {
		return ctx, fmt.Errorf("unable to get namespace id for %s", namespaceRef)
	}

	ruleType, err := parseAttributeRule(rule)
	if err != nil {
		return ctx, err
	}

	values := make([]string, 0, valueCount)
	for i := range valueCount {
		values = append(values, fmt.Sprintf("v%04d", i))
	}

	resp, err := scenarioContext.SDK.Attributes.CreateAttribute(ctx, &attributes.CreateAttributeRequest{
		NamespaceId: nsID,
		Name:        strings.TrimSpace(name),
		Rule:        ruleType,
		Values:      values,
	})
	if resp != nil {
		scenarioContext.RecordObject(strings.TrimSpace(referenceID), resp.GetAttribute())
	}
	scenarioContext.SetError(err)
	return ctx, nil
}

func (s *AttributesStepDefinitions) iSendARequestToCreateAnAttributeWithBatchedGeneratedValues(ctx context.Context, referenceID, namespaceRef, name, rule string, valueCount, batchSize int) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()
	if valueCount < 1 {
		return ctx, errors.New("generated value count must be positive")
	}
	if batchSize < 1 {
		return ctx, errors.New("generated value batch size must be positive")
	}

	namespaceID, ok := scenarioContext.GetObject(strings.TrimSpace(namespaceRef)).(string)
	if !ok {
		return ctx, fmt.Errorf("unable to get namespace id for %s", namespaceRef)
	}
	ruleType, err := parseAttributeRule(rule)
	if err != nil {
		return ctx, err
	}

	created, err := scenarioContext.SDK.Attributes.CreateAttribute(ctx, &attributes.CreateAttributeRequest{
		NamespaceId: namespaceID,
		Name:        strings.TrimSpace(name),
		Rule:        ruleType,
	})
	if err != nil {
		scenarioContext.SetError(err)
		return ctx, nil
	}
	if created.GetAttribute() == nil {
		return ctx, errors.New("create attribute returned no attribute")
	}

	started := time.Now()
	values := make([]*policy.Value, valueCount)
	for batchStart := 0; batchStart < valueCount; batchStart += batchSize {
		batchEnd := min(batchStart+batchSize, valueCount)
		batchCtx, cancel := context.WithCancel(ctx)
		errCh := make(chan error, batchEnd-batchStart)
		var wg sync.WaitGroup
		for i := batchStart; i < batchEnd; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				resp, createErr := scenarioContext.SDK.Attributes.CreateAttributeValue(batchCtx, &attributes.CreateAttributeValueRequest{
					AttributeId: created.GetAttribute().GetId(),
					Value:       fmt.Sprintf("v%04d", index),
				})
				if createErr != nil {
					errCh <- fmt.Errorf("create generated attribute value v%04d: %w", index, createErr)
					cancel()
					return
				}
				if resp.GetValue() == nil {
					errCh <- fmt.Errorf("create generated attribute value v%04d returned no value", index)
					cancel()
					return
				}
				values[index] = resp.GetValue()
			}(i)
		}
		wg.Wait()
		cancel()
		close(errCh)
		if batchErr, hasBatchErr := <-errCh; hasBatchErr {
			scenarioContext.SetError(batchErr)
			return ctx, nil
		}
	}

	created.GetAttribute().Values = values
	scenarioContext.RecordObject(strings.TrimSpace(referenceID), created.GetAttribute())
	scenarioContext.TestSuiteContext.Logger.Info(
		"created generated attribute values in batches",
		slog.Int("value_count", valueCount),
		slog.Int("batch_size", batchSize),
		slog.Duration("duration", time.Since(started)),
	)
	return ctx, nil
}

func RegisterAttributeStepDefinitions(ctx *godog.ScenarioContext, x *PlatformTestSuiteContext) {
	stepDefinitions := AttributesStepDefinitions{
		PlatformCukesContext: x,
	}
	ctx.Step(`^a (anyOf|allOf|hierarchy) attribute definition with values: "([^"]*)"$`, stepDefinitions.aAttributeDef)
	ctx.Step(`^I send a request to create an attribute with:$`, stepDefinitions.iSendARequestToCreateAnAttributeWith)
	ctx.Step(`^I send a request to create an attribute referenced as "([^"]*)" in namespace "([^"]*)" named "([^"]*)" with rule "([^"]*)" and (\d+) generated values$`, stepDefinitions.iSendARequestToCreateAnAttributeWithGeneratedValues)
	ctx.Step(`^I send a request to create an attribute referenced as "([^"]*)" in namespace "([^"]*)" named "([^"]*)" with rule "([^"]*)" and (\d+) generated values in batches of (\d+)$`, stepDefinitions.iSendARequestToCreateAnAttributeWithBatchedGeneratedValues)
}
