// Experimental: This package is EXPERIMENTAL and may change or be removed at any time

package tdf

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/gowebpki/jcs"
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

func TestDeserializingAssertionWithJSONInStatementValue(t *testing.T) {
	// the assertion has a JSON object in the statement value
	assertionVal := ` {
      "id": "bacbe31eab384df39d35a5fbe83778de",
      "type": "handling",
      "scope": "tdo",
      "appliesToState": null,
      "statement": {
        "format": "json-structured",
        "value": {
          "ocl": {
            "pol": "2ccf11cb-6c9a-4e49-9746-a7f0a295945d",
            "cls": "SECRET",
            "catl": [
              {
                "type": "P",
                "name": "Releasable To",
                "vals": [
                  "usa"
                ]
              }
            ],
            "dcr": "2024-12-17T13:00:52Z"
          },
          "context": {
            "@base": "urn:nato:stanag:5636:A:1:elements:json"
          }
        }
      },
      "binding": {
        "method": "jws",
        "signature": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJDb25maWRlbnRpYWxpdHlJbmZvcm1hdGlvbiI6InsgXCJvY2xcIjogeyBcInBvbFwiOiBcIjJjY2YxMWNiLTZjOWEtNGU0OS05NzQ2LWE3ZjBhMjk1OTQ1ZFwiLCBcImNsc1wiOiBcIlNFQ1JFVFwiLCBcImNhdGxcIjogWyB7IFwidHlwZVwiOiBcIlBcIiwgXCJuYW1lXCI6IFwiUmVsZWFzYWJsZSBUb1wiLCBcInZhbHNcIjogWyBcInVzYVwiIF0gfSBdLCBcImRjclwiOiBcIjIwMjQtMTItMTdUMTM6MDA6NTJaXCIgfSwgXCJjb250ZXh0XCI6IHsgXCJAYmFzZVwiOiBcInVybjpuYXRvOnN0YW5hZzo1NjM2OkE6MTplbGVtZW50czpqc29uXCIgfSB9In0.LlOzRLKKXMAqXDNsx9Ha5915CGcAkNLuBfI7jJmx6CnfQrLXhlRHWW3_aLv5DPsKQC6vh9gDQBH19o7q7EcukvK4IabA4l0oP8ePgHORaajyj7ONjoeudv_zQ9XN7xU447S3QznzOoasuWAFoN4682Fhf99Kjl6rhDCzmZhTwQw9drP7s41nNA5SwgEhoZj-X9KkNW5GbWjA95eb8uVRRWk8dOnVje6j8mlJuOtKdhMxQ8N5n0vBYYhiss9c4XervBjWAxwAMdbRaQN0iPZtMzIkxKLYxBZDvTnYSAqzpvfGPzkSI-Ze_hUZs2hp-ADNnYUJBf_LzFmKyqHjPSFQ7A"
      }
    }`

	var assertion Assertion
	err := json.Unmarshal([]byte(assertionVal), &assertion)
	require.NoError(t, err, "Error deserializing the assertion with a JSON object in the statement value")

	expectedAssertionValue, _ := jcs.Transform([]byte(`{
          "ocl": {
            "pol": "2ccf11cb-6c9a-4e49-9746-a7f0a295945d",
            "cls": "SECRET",
            "catl": [
              {
                "type": "P",
                "name": "Releasable To",
                "vals": [
                  "usa"
                ]
              }
            ],
            "dcr": "2024-12-17T13:00:52Z"
          },
          "context": {
            "@base": "urn:nato:stanag:5636:A:1:elements:json"
          }
        }`))
	actualAssertionValue, err := jcs.Transform([]byte(assertion.Statement.Value))
	require.NoError(t, err, "Error transforming the assertion statement value")
	assert.Equal(t, expectedAssertionValue, actualAssertionValue)
}

func TestDeserializingAssertionWithStringInStatementValue(t *testing.T) {
	// the assertion has a JSON object in the statement value
	assertionVal := ` {
      "id": "bacbe31eab384df39d35a5fbe83778de",
      "type": "handling",
      "scope": "tdo",
      "appliesToState": null,
      "statement": {
        "format": "json-structured",
        "value": "this is a value"
      },
      "binding": {
        "method": "jws",
        "signature": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJDb25maWRlbnRpYWxpdHlJbmZvcm1hdGlvbiI6InsgXCJvY2xcIjogeyBcInBvbFwiOiBcIjJjY2YxMWNiLTZjOWEtNGU0OS05NzQ2LWE3ZjBhMjk1OTQ1ZFwiLCBcImNsc1wiOiBcIlNFQ1JFVFwiLCBcImNhdGxcIjogWyB7IFwidHlwZVwiOiBcIlBcIiwgXCJuYW1lXCI6IFwiUmVsZWFzYWJsZSBUb1wiLCBcInZhbHNcIjogWyBcInVzYVwiIF0gfSBdLCBcImRjclwiOiBcIjIwMjQtMTItMTdUMTM6MDA6NTJaXCIgfSwgXCJjb250ZXh0XCI6IHsgXCJAYmFzZVwiOiBcInVybjpuYXRvOnN0YW5hZzo1NjM2OkE6MTplbGVtZW50czpqc29uXCIgfSB9In0.LlOzRLKKXMAqXDNsx9Ha5915CGcAkNLuBfI7jJmx6CnfQrLXhlRHWW3_aLv5DPsKQC6vh9gDQBH19o7q7EcukvK4IabA4l0oP8ePgHORaajyj7ONjoeudv_zQ9XN7xU447S3QznzOoasuWAFoN4682Fhf99Kjl6rhDCzmZhTwQw9drP7s41nNA5SwgEhoZj-X9KkNW5GbWjA95eb8uVRRWk8dOnVje6j8mlJuOtKdhMxQ8N5n0vBYYhiss9c4XervBjWAxwAMdbRaQN0iPZtMzIkxKLYxBZDvTnYSAqzpvfGPzkSI-Ze_hUZs2hp-ADNnYUJBf_LzFmKyqHjPSFQ7A"
      }
    }`

	var assertion Assertion
	err := json.Unmarshal([]byte(assertionVal), &assertion)
	require.NoError(t, err, "Error deserializing the assertion with a JSON object in the statement value")

	assert.Equal(t, "this is a value", assertion.Statement.Value)
}

func TestAssertionSignWithCryptoSigner(t *testing.T) {
	// Generate RSA key pair - *rsa.PrivateKey implements crypto.Signer
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	assertion := Assertion{
		ID:             "test-assertion",
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: "text",
			Schema: "test",
			Value:  "test value",
		},
	}

	// Sign using crypto.Signer (RSA private key implements crypto.Signer)
	signerKey := AssertionKey{
		Alg:    AssertionKeyAlgRS256,
		Signer: privateKey,
	}

	err = assertion.Sign("testhash", "testsig", signerKey)
	require.NoError(t, err)
	assert.NotEmpty(t, assertion.Binding.Signature)
	assert.Equal(t, "jws", assertion.Binding.Method)

	// Verify using the same key (will use Public() from signer)
	hash, sig, err := assertion.Verify(signerKey)
	require.NoError(t, err)
	assert.Equal(t, "testhash", hash)
	assert.Equal(t, "testsig", sig)
}

func TestAssertionSignWithCryptoSignerVerifyWithPublicKey(t *testing.T) {
	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	assertion := Assertion{
		ID:             "test-assertion",
		Type:           BaseAssertion,
		Scope:          PayloadScope,
		AppliesToState: Unencrypted,
		Statement: Statement{
			Format: "text",
			Schema: "test",
			Value:  "test value",
		},
	}

	// Sign using crypto.Signer
	signerKey := AssertionKey{
		Alg:    AssertionKeyAlgRS256,
		Signer: privateKey,
	}

	err = assertion.Sign("testhash", "testsig", signerKey)
	require.NoError(t, err)

	// Verify using public key directly (typical verification scenario)
	verifyKey := AssertionKey{
		Alg: AssertionKeyAlgRS256,
		Key: privateKey.PublicKey,
	}

	hash, sig, err := assertion.Verify(verifyKey)
	require.NoError(t, err)
	assert.Equal(t, "testhash", hash)
	assert.Equal(t, "testsig", sig)
}
