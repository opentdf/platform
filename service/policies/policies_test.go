package policies

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/open-policy-agent/opa/rego"
	"github.com/opentdf/platform/internal/idpplugin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegoEntitlementsEmpty(t *testing.T) {
	expected := []interface{}{}
	inputJSON := `{}`
	var input interface{}
	err := json.Unmarshal([]byte(inputJSON), &input)
	require.NoError(t, err)
	EvaluateRegoEntitlements(t, input, expected)
}

func TestRegoEntitlementsSimple(t *testing.T) {
	expected := []interface{}{"https://brightonhealthclinic.org/attr/healthrecordtype/value/basicpatientinfo"}
	inputJSON := `{
  "attribute_mappings": {
    "https://brightonhealthclinic.org/attr/healthrecordtype/value/basicpatientinfo": {
      "attribute": {
        "id": "46fd500e-6839-4cc0-8b29-75665bf98e3a",
        "namespace": {
          "id": "f1f12166-8b22-47d6-829a-66e68b533eb2",
          "name": "brightonhealthclinic.org"
        },
        "name": "healthrecordtype",
        "rule": 2,
        "values": [
          {
            "id": "356b7dd3-6abb-453c-8354-6915705fabcb",
            "value": "basicpatientinfo",
            "fqn": "https://brightonhealthclinic.org/attr/healthrecordtype/value/basicpatientinfo",
            "active": {
              "value": true
            }
          }
        ],
        "active": {
          "value": true
        },
        "metadata": {}
      },
      "value": {
        "id": "356b7dd3-6abb-453c-8354-6915705fabcb",
        "value": "basicpatientinfo",
        "fqn": "https://brightonhealthclinic.org/attr/healthrecordtype/value/basicpatientinfo",
        "active": {
          "value": true
        },
        "subject_mappings": [
          {
            "id": "5fb9f643-b7ea-4d53-8b23-f2b61a7ca38a",
            "subject_condition_set": {
              "id": "eb688795-fa0a-4014-8f4e-0f770c7bdab6",
              "subject_sets": [
                {
                  "condition_groups": [
                    {
                      "conditions": [
                        {
                          "subject_external_field": "groups",
                          "operator": 1,
                          "subject_external_values": [
                            "/medical"
                          ]
                        },
                        {
                          "subject_external_field": "roles",
                          "operator": 1,
                          "subject_external_values": [
                            "nurse",
                            "doctor"
                          ]
                        }
                      ],
                      "boolean_operator": 1
                    }
                  ]
                }
              ],
              "metadata": {}
            },
            "actions": [
              {
                "Value": {
                  "Standard": 1
                }
              }
            ],
            "metadata": {}
          }
        ]
      }
    }
  },
  "entity": {
    "jwt": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3bEN5Vlo4Zm9jaTBOSk1JclZGZ01jZFc1cGlRQVUwVV9KZ1BNZ2V1RFI0In0.eyJleHAiOjE3MTE1MTI2MjEsImlhdCI6MTcxMTQ3NjYyMSwiYXV0aF90aW1lIjoxNzExNDc2NjIxLCJqdGkiOiI2YzJlMjk0Mi1iNmE4LTQ2MTYtOTYwZi0xN2I2NzA3MDFiMzgiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0Ojg4ODgvYXV0aC9yZWFsbXMvYnJpZ2h0b25oZWFsdGhjbGluaWMiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiNWJkOTllODgtMDkyMS00MzVjLTkxOTktYjZmZTZmYjU3MGY4IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiYWNjb3VudC1jb25zb2xlIiwibm9uY2UiOiJlYTMwMjk1OC1jMzgyLTQ0NGItYjNlNy0zODFhMjAzODE4YTciLCJzZXNzaW9uX3N0YXRlIjoiODQ0NjMxMjgtYjg0NS00ZDM1LTljM2MtNmJhNjFiZWEwZTYyIiwiYWNyIjoiMSIsInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwic2lkIjoiODQ0NjMxMjgtYjg0NS00ZDM1LTljM2MtNmJhNjFiZWEwZTYyIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJyb2xlcyI6Im51cnNlIiwibmFtZSI6Ik9saXZpYSBHcmVlbiIsImdyb3VwcyI6WyIvbWVkaWNhbCJdLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJvZ3JlZW4iLCJnaXZlbl9uYW1lIjoiT2xpdmlhIiwiZmFtaWx5X25hbWUiOiJHcmVlbiIsImVtYWlsIjoib2dyZWVuQGJyaWdodG9uaGVhbHRoY2xpbmljLm9yZyJ9.2MWhwiCdUChYPCvP-Q08Z1RvwO2a0Q3axR0agWAA-KToirV7bRdcMGJUDxEYzxCKmZYTcR3nNjeTF-WzK1ZsiasimsOVeqoCv8Q2YbA19KqxusaTrRtHcSLCVM8BWYGMBbrEzgn06MDYXjHVhAjAYytl20dImRjUPukFhG6XI8LIoX8sCRwb4gKb0fweIUaX6lj3TCvRw9NakIyN1Jotd3CBBZMFJ7fid1_HX8rWJ7HWZNdvILLMxv3euLO2IFFnnCaq6_etMCNeSzEqg3jei5gwOIcbPzERt2fpmrTX4OhFbUOJvI3MU-4uMJ68muKNCW0nlMEjUbYfCcjbSRUDjA",
    "id": ""
  },
  "idp": null
}`
	var input interface{}
	err := json.Unmarshal([]byte(inputJSON), &input)
	require.NoError(t, err)
	EvaluateRegoEntitlements(t, input, expected)
}

func EvaluateRegoEntitlements(t *testing.T, input interface{}, expected []interface{}) {
	ctx := context.Background()
	policy, err := os.ReadFile("entitlements/entitlements.rego")
	require.NoError(t, err)
	regoObj := rego.New(
		rego.Query("data.opentdf.entitlements.attributes"),
		rego.Module("entitlements.rego", string(policy)),
		rego.Dump(os.Stderr),
		rego.EnablePrintStatements(true),
	)
	evalQuery, err := regoObj.PrepareForEval(ctx)
	require.NoError(t, err)
	resultSet, err := evalQuery.Eval(ctx, rego.EvalInput(input))
	require.NoError(t, err)
	for _, result := range resultSet {
		for _, expression := range result.Expressions {
			assert.Equal(t, expected, expression.Value)
		}
	}
}

// TestRegoEntitlementsKeycloakEmpty tests builtin instantiation only
func TestRegoEntitlementsKeycloakEmpty(t *testing.T) {
	expected := []interface{}{}
	inputJSON := `{}`
	var input interface{}
	err := json.Unmarshal([]byte(inputJSON), &input)
	require.NoError(t, err)
	EvaluateRegoEntitlementsKeycloak(t, input, expected)
}

// EvaluateRegoEntitlementsKeycloak tests the keycloak builtin - better in an integration test
func EvaluateRegoEntitlementsKeycloak(t *testing.T, input interface{}, expected []interface{}) {
	// instantiate built-ins
	idpplugin.KeycloakBuiltins()
	ctx := context.Background()
	policy, err := os.ReadFile("entitlements/entitlements-keycloak.rego")
	require.NoError(t, err)
	regoObj := rego.New(
		rego.Query("data.opentdf.entitlements.attributes"),
		rego.Module("entitlements-keycloak.rego", string(policy)),
		rego.Dump(os.Stderr),
		rego.EnablePrintStatements(true),
	)
	evalQuery, err := regoObj.PrepareForEval(ctx)
	require.NoError(t, err)
	resultSet, err := evalQuery.Eval(ctx, rego.EvalInput(input))
	require.NoError(t, err)
	for _, result := range resultSet {
		for _, expression := range result.Expressions {
			assert.Equal(t, expected, expression.Value)
		}
	}
}

func TestRegoConditionEmpty(t *testing.T) {
	expected := false
	inputJSON := `{}`
	var input interface{}
	_ = json.Unmarshal([]byte(inputJSON), &input)
	EvaluateRegoConditions(t, input, expected)
}

func TestRegoConditionSimple(t *testing.T) {
	expected := true
	inputJSON := `{
  "payload": {
	"groups": ["groupA"]
  },
  "condition": {
	"subject_external_field": "groups",
	"operator": 1,
	"subject_external_values": [
	  "groupA"
	]
  }
}`
	var input interface{}
	err := json.Unmarshal([]byte(inputJSON), &input)
	require.NoError(t, err)
	EvaluateRegoConditions(t, input, expected)
}

// EvaluateRegoConditions uses a conditions test file to do function level testing
func EvaluateRegoConditions(t *testing.T, input interface{}, expected bool) {
	ctx := context.Background()
	policy, err := os.ReadFile("entitlements/entitlements.rego")
	require.NoError(t, err)
	policyTest, err := os.ReadFile("entitlements/conditions-test.rego")
	require.NoError(t, err)
	regoObj := rego.New(
		rego.Query("data.opentdf.entitlements_test.condition_result"),
		rego.Module("entitlements.rego", string(policy)),
		rego.Module("conditions-test.rego", string(policyTest)),
		rego.Dump(os.Stderr),
		rego.EnablePrintStatements(true),
	)
	evalQuery, err := regoObj.PrepareForEval(ctx)
	require.NoError(t, err)
	resultSet, err := evalQuery.Eval(ctx, rego.EvalInput(input))
	require.NoError(t, err)
	for _, result := range resultSet {
		for _, expression := range result.Expressions {
			assert.Equal(t, expected, expression.Value)
		}
	}
}
