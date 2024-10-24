package sdk

import (
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
