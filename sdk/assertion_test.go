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
			Value:  "{\"ocl\":{\"pol\":\"62c76c68-d73d-4628-8ccc-4c1e18118c22\",\"cls\":\"SECRET\",\"catl\":[{\"type\":\"P\",\"name\":\"Releasable To\",\"vals\":[\"usa\"]}],\"dcr\":\"2024-10-21T20:47:36Z\"},\"context\":{\"@base\":\"urn:nato:stanag:5636:A:1:elements:json\"}}",
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
	value := `{
		"ocl": {
			"pol": "2ccf11cb-6c9a-4e49-9746-a7f0a295945d",
			"cls": "SECRET",
			"catl": [
				{
					"type": "P",
					"name": "Releasable To",
					"vals": ["usa"]
				}
			],
			"dcr": "2024-12-17T13:00:52Z"
		},
		"context": {
			"@base": "urn:nato:stanag:5636:A:1:elements:json"
		}
	}`
	assertionConfig := AssertionConfig{
		ID:             "ab43266781e64b51a4c52ffc44d6152c",
		Type:           "handling",
		Scope:          "payload",
		AppliesToState: "", // Use "" or a pointer to a string if necessary
		Statement: Statement{
			Format: "json-structured",
			Value:  value,
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

	var obj map[string]interface{}
	err := json.Unmarshal([]byte(assertionConfig.Statement.Value), &obj)
	require.NoError(t, err, "Unmarshaling the Value into a map should succeed")

	ocl, ok := obj["ocl"].(map[string]interface{})
	require.True(t, ok, "Parsed Value should contain 'ocl' as an object")
	require.Equal(t, "SECRET", ocl["cls"], "'cls' field should match")
	require.Equal(t, "2ccf11cb-6c9a-4e49-9746-a7f0a295945d", ocl["pol"], "'pol' field should match")

	context, ok := obj["context"].(map[string]interface{})
	require.True(t, ok, "Parsed Value should contain 'context' as an object")
	require.Equal(t, "urn:nato:stanag:5636:A:1:elements:json", context["@base"], "'@base' field should match")

	// Calculate the hash of the assertion
	hashOfAssertion, err := assertion.GetHash()
	require.NoError(t, err)

	expectedHash := "722dd40a90a0f7ec718fb156207a647e64daa43c0ae1f033033473a172c72aee"
	assert.Equal(t, expectedHash, string(hashOfAssertion))
}
