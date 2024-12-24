package sdk

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTDFWithAssertion(t *testing.T) {
	assertionConfig := AssertionConfig{
		ID:             "424ff3a3-50ca-4f01-a2ae-ef851cd3cac0",
		Type:           "handling",
		Scope:          "tdo",
		AppliesToState: "encrypted",
		Statement: Statement{
			Format: "json+stanag5636",
			Schema: "urn:nato:stanag:5636:A:1:elements:json",
			Value: FlexibleValue{
				AsString: func() *string {
					val := "{\"ocl\":{\"pol\":\"62c76c68-d73d-4628-8ccc-4c1e18118c22\",\"cls\":\"SECRET\",\"catl\":[{\"type\":\"P\",\"name\":\"Releasable To\",\"vals\":[\"usa\"]}],\"dcr\":\"2024-10-21T20:47:36Z\"},\"context\":{\"@base\":\"urn:nato:stanag:5636:A:1:elements:json\"}}"
					return &val
				}(),
			},
		},
	}

	assertion := Assertion{}

	assertion.ID = assertionConfig.ID
	assertion.Type = assertionConfig.Type
	assertion.Scope = assertionConfig.Scope
	assertion.Statement = assertionConfig.Statement
	assertion.AppliesToState = assertionConfig.AppliesToState

	hashOfAssertion, err := assertion.GetHash()
	require.NoError(t, err)

	assert.Equal(t, "4a447a13c5a32730d20bdf7feecb9ffe16649bc731914b574d80035a3927f860", string(hashOfAssertion))
}

func TestTDFWithAssertionJsonObject(t *testing.T) {
	// Define the assertion config with a JSON object in the statement value
	assertionConfig := AssertionConfig{
		ID:             "ab43266781e64b51a4c52ffc44d6152c",
		Type:           "handling",
		Scope:          "payload",
		AppliesToState: "", // Use "" or a pointer to a string if necessary
		Statement: Statement{
			Format: "json-structured",
			Value: FlexibleValue{
				AsObject: map[string]interface{}{ // Correct usage of FlexibleValue
					"ocl": map[string]interface{}{
						"pol": "2ccf11cb-6c9a-4e49-9746-a7f0a295945d",
						"cls": "SECRET",
						"catl": []map[string]interface{}{
							{
								"type": "P",
								"name": "Releasable To",
								"vals": []string{"usa"},
							},
						},
						"dcr": "2024-12-17T13:00:52Z",
					},
					"context": map[string]interface{}{
						"@base": "urn:nato:stanag:5636:A:1:elements:json",
					},
				},
			},
		},
	}

	// Set up the assertion
	assertion := Assertion{
		ID:             assertionConfig.ID,
		Type:           assertionConfig.Type,
		Scope:          assertionConfig.Scope,
		AppliesToState: assertionConfig.AppliesToState,
		Statement:      assertionConfig.Statement,
	}

	// Serialize the JSON object in the statement value
	serializedStatementValue, err := json.Marshal(assertion.Statement.Value.AsObject)
	require.NoError(t, err)

	// Ensure the serialized value is valid JSON
	var deserialized map[string]interface{}
	err = json.Unmarshal(serializedStatementValue, &deserialized)
	require.NoError(t, err)

	// Set the serialized value back into the statement
	assertion.Statement.Value = FlexibleValue{
		AsString: func() *string {
			val := string(serializedStatementValue)
			return &val
		}(),
	}

	// Calculate the hash of the assertion
	hashOfAssertion, err := assertion.GetHash()
	require.NoError(t, err)

	// Assert the expected hash (example hash, replace with actual expected value)
	expectedHash := "c1733259597a7025d2fdbd000a68c5ee3652cf2cd61c0be8f92f941c521cee92"
	assert.Equal(t, expectedHash, string(hashOfAssertion))
}
