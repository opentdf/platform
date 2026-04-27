package cukes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/cucumber/godog"
)

type EnumShorthandStepDefinitions struct{}

// getAccessToken fetches a bearer token from the Keycloak token endpoint using
// the same client credentials the BDD test SDK uses.
func getAccessToken(ctx context.Context, tokenEndpoint string) (string, error) {
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"opentdf"},
		"client_secret": {"secret"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("token request creation failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request returned %d: %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}
	return tokenResp.AccessToken, nil
}

// postConnectRPC sends a raw JSON body to a ConnectRPC endpoint and returns the
// HTTP status code and response body.
func postConnectRPC(ctx context.Context, endpoint, rpcPath, token, jsonBody string) (int, string, error) {
	client := &http.Client{}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+rpcPath, strings.NewReader(jsonBody))
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(body), nil
}

// prepareAuthenticatedRequest extracts the platform endpoint and fetches a
// bearer token for raw HTTP requests. This is the common setup shared by all
// shorthand enum e2e step definitions.
func prepareAuthenticatedRequest(ctx context.Context) (*PlatformScenarioContext, string, string, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()

	endpoint := scenarioContext.ScenarioOptions.PlatformEndpoint
	tokenEndpoint, err := scenarioContext.SDK.PlatformConfiguration.TokenEndpoint()
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to get token endpoint: %w", err)
	}

	token, err := getAccessToken(ctx, tokenEndpoint)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to get access token: %w", err)
	}

	return scenarioContext, endpoint, token, nil
}

// iCreateASubjectConditionSetViaHTTPWithShorthandEnums sends a raw HTTP POST with
// shorthand enum strings and verifies the platform accepts it.
func (s *EnumShorthandStepDefinitions) iCreateASubjectConditionSetViaHTTPWithShorthandEnums(ctx context.Context) (context.Context, error) {
	scenarioContext, endpoint, token, err := prepareAuthenticatedRequest(ctx)
	if err != nil {
		return ctx, err
	}

	// Raw JSON with shorthand enum values — this is what the middleware normalizes.
	body := `{
		"subjectConditionSet": {
			"subjectSets": [{
				"conditionGroups": [{
					"booleanOperator": "AND",
					"conditions": [{
						"subjectExternalSelectorValue": ".email",
						"operator": "IN_CONTAINS",
						"subjectExternalValues": ["@example.com"]
					}]
				}]
			}]
		}
	}`

	rpcPath := "/policy.subjectmapping.SubjectMappingService/CreateSubjectConditionSet"
	statusCode, respBody, err := postConnectRPC(ctx, endpoint, rpcPath, token, body)
	if err != nil {
		return ctx, fmt.Errorf("HTTP request failed: %w", err)
	}

	slog.Debug("shorthand enum e2e response",
		slog.Int("status", statusCode),
		slog.String("body", respBody))

	if statusCode != http.StatusOK {
		return ctx, fmt.Errorf("expected HTTP 200, got %d: %s", statusCode, respBody)
	}

	// Verify the response contains a valid subject condition set ID
	var result map[string]any
	if err := json.Unmarshal([]byte(respBody), &result); err != nil {
		return ctx, fmt.Errorf("failed to parse response: %w", err)
	}
	scs, ok := result["subjectConditionSet"].(map[string]any)
	if !ok || scs["id"] == nil {
		return ctx, fmt.Errorf("response missing subjectConditionSet.id: %s", respBody)
	}

	scsID, ok := scs["id"].(string)
	if !ok {
		return ctx, fmt.Errorf("subjectConditionSet.id is not a string: %s", respBody)
	}
	scenarioContext.RecordObject("shorthand_scs_id", scsID)
	return ctx, nil
}

// iCreateAnAttributeViaHTTPWithShorthandRule sends a raw HTTP POST to create an
// attribute using a shorthand rule type enum.
func (s *EnumShorthandStepDefinitions) iCreateAnAttributeViaHTTPWithShorthandRule(ctx context.Context) (context.Context, error) {
	scenarioContext, endpoint, token, err := prepareAuthenticatedRequest(ctx)
	if err != nil {
		return ctx, err
	}

	// Get the namespace ID that was created by the scenario setup
	nsID, ok := scenarioContext.GetObject("ns1").(string)
	if !ok {
		return ctx, errors.New("namespace ns1 not found in scenario context")
	}

	// Raw JSON with shorthand rule type
	body := fmt.Sprintf(`{
		"attribute": {
			"namespaceId": "%s",
			"name": "shorthand_test_attr",
			"rule": "ANY_OF",
			"values": ["val1", "val2"]
		}
	}`, nsID)

	rpcPath := "/policy.attributes.AttributesService/CreateAttribute"
	statusCode, respBody, err := postConnectRPC(ctx, endpoint, rpcPath, token, body)
	if err != nil {
		return ctx, fmt.Errorf("HTTP request failed: %w", err)
	}

	slog.Debug("shorthand rule e2e response",
		slog.Int("status", statusCode),
		slog.String("body", respBody))

	if statusCode != http.StatusOK {
		return ctx, fmt.Errorf("expected HTTP 200, got %d: %s", statusCode, respBody)
	}

	// Verify the response contains a valid attribute with the correct rule
	var result map[string]any
	if err := json.Unmarshal([]byte(respBody), &result); err != nil {
		return ctx, fmt.Errorf("failed to parse response: %w", err)
	}
	attr, ok := result["attribute"].(map[string]any)
	if !ok || attr["id"] == nil {
		return ctx, fmt.Errorf("response missing attribute.id: %s", respBody)
	}

	// Verify the rule was accepted and stored as the canonical name
	rule, _ := attr["rule"].(string)
	if rule != "ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF" {
		return ctx, fmt.Errorf("expected rule ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF, got %s", rule)
	}

	return ctx, nil
}

// iCreateASubjectConditionSetViaHTTPWithMixedEnumFormats verifies that a request
// mixing shorthand and canonical enum names works correctly.
func (s *EnumShorthandStepDefinitions) iCreateASubjectConditionSetViaHTTPWithMixedEnumFormats(ctx context.Context) (context.Context, error) {
	_, endpoint, token, err := prepareAuthenticatedRequest(ctx)
	if err != nil {
		return ctx, err
	}

	// Mix shorthand and canonical names in the same request
	body := `{
		"subjectConditionSet": {
			"subjectSets": [{
				"conditionGroups": [{
					"booleanOperator": "CONDITION_BOOLEAN_TYPE_ENUM_AND",
					"conditions": [
						{
							"subjectExternalSelectorValue": ".email",
							"operator": "IN",
							"subjectExternalValues": ["@test.com"]
						},
						{
							"subjectExternalSelectorValue": ".role",
							"operator": "SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN",
							"subjectExternalValues": ["guest"]
						}
					]
				}]
			}]
		}
	}`

	rpcPath := "/policy.subjectmapping.SubjectMappingService/CreateSubjectConditionSet"
	statusCode, respBody, err := postConnectRPC(ctx, endpoint, rpcPath, token, body)
	if err != nil {
		return ctx, fmt.Errorf("HTTP request failed: %w", err)
	}

	if statusCode != http.StatusOK {
		return ctx, fmt.Errorf("expected HTTP 200, got %d: %s", statusCode, respBody)
	}

	var result map[string]any
	if err := json.Unmarshal([]byte(respBody), &result); err != nil {
		return ctx, fmt.Errorf("failed to parse response: %w", err)
	}
	scs, ok := result["subjectConditionSet"].(map[string]any)
	if !ok || scs["id"] == nil {
		return ctx, fmt.Errorf("response missing subjectConditionSet.id: %s", respBody)
	}

	return ctx, nil
}

func RegisterEnumShorthandStepDefinitions(ctx *godog.ScenarioContext) {
	steps := &EnumShorthandStepDefinitions{}
	ctx.Step(`^I create a subject condition set via HTTP with shorthand enums$`, steps.iCreateASubjectConditionSetViaHTTPWithShorthandEnums)
	ctx.Step(`^I create an attribute via HTTP with shorthand rule type$`, steps.iCreateAnAttributeViaHTTPWithShorthandRule)
	ctx.Step(`^I create a subject condition set via HTTP with mixed enum formats$`, steps.iCreateASubjectConditionSetViaHTTPWithMixedEnumFormats)
}
