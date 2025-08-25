package sdk

import (
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
			Format: "json",
			Schema: "https://geojson.org/schema/GeoJSON.json",
			Value:  "{\"type\":\"Feature\",\"geometry\":{\"type\":\"Point\",\"coordinates\":[125.6,10.1]},\"properties\":{\"name\":\"Dinagat Islands\"}}",
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

	assert.Equal(t, "641981b75d68cedd246db01c3598383a2e7745dc18987c0113924e69d2c7adba", string(hashOfAssertion))
}

func TestTDFWithAssertionJsonObject(t *testing.T) {
	// Define the assertion config with a JSON object in the statement value
	value := `{
		"type": "Feature",
		"geometry": {
			"type": "Polygon",
			"coordinates": [
				[
					[100.1, 0.2],
					[101.3, 0.4],
					[101.5, 1.6],
					[100.7, 1.8],
					[100.1, 0.2]
				]
			]
		},
		"properties": {
			"name": "A Polygon"
		}
	}`
	assertionConfig := AssertionConfig{
		ID:             "ab43266781e64b51a4c52ffc44d6152c",
		Type:           "handling",
		Scope:          "payload",
		AppliesToState: "", // Use "" or a pointer to a string if necessary
		Statement: Statement{
			Format: "json",
			Schema: "https://geojson.org/schema/GeoJSON.json",
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

	assert.Equal(t, "Feature", obj["type"], "'type' field should be Feature")

	properties, ok := obj["properties"].(map[string]interface{})
	require.True(t, ok, "Parsed Value should contain 'properties' as an object")
	assert.Equal(t, "A Polygon", properties["name"], "'name' property should match")

	geometry, ok := obj["geometry"].(map[string]interface{})
	require.True(t, ok, "Parsed Value should contain 'geometry' as an object")
	assert.Equal(t, "Polygon", geometry["type"], "'type' of geometry should be Polygon")

	// Calculate the hash of the assertion
	hashOfAssertion, err := assertion.GetHash()
	require.NoError(t, err)

	expectedHash := "b140675260ffd395e3a935e4102a123dcdcd70e7cfa6ec91e8d309b655497741"
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
        "format": "json",
        "schema": "https://geojson.org/schema/GeoJSON.json",
        "value": {
          "type": "FeatureCollection",
          "features": [
            {
              "type": "Feature",
              "geometry": {
                "type": "Point",
                "coordinates": [
                  -80.837753,
                  35.227222
                ]
              },
              "properties": {
                "name": "Charlotte"
              }
            },
            {
              "type": "Feature",
              "geometry": {
                "type": "Polygon",
                "coordinates": [
                  [
                    [
                      -80.843,
                      35.228
                    ],
                    [
                      -80.843,
                      35.226
                    ],
                    [
                      -80.841,
                      35.226
                    ],
                    [
                      -80.841,
                      35.228
                    ],
                    [
                      -80.843,
                      35.228
                    ]
                  ]
                ]
              },
              "properties": {
                "name": "Uptown"
              }
            }
          ]
        }
      }
    }`

	var assertion Assertion
	err := json.Unmarshal([]byte(assertionVal), &assertion)
	require.NoError(t, err, "Error deserializing the assertion with a JSON object in the statement value")

	expectedAssertionValue, _ := jcs.Transform([]byte(`{
          "type": "FeatureCollection",
          "features": [
            {
              "type": "Feature",
              "geometry": {
                "type": "Point",
                "coordinates": [
                  -80.837753,
                  35.227222
                ]
              },
              "properties": {
                "name": "Charlotte"
              }
            },
            {
              "type": "Feature",
              "geometry": {
                "type": "Polygon",
                "coordinates": [
                  [
                    [
                      -80.843,
                      35.228
                    ],
                    [
                      -80.843,
                      35.226
                    ],
                    [
                      -80.841,
                      35.226
                    ],
                    [
                      -80.841,
                      35.228
                    ],
                    [
                      -80.843,
                      35.228
                    ]
                  ]
                ]
              },
              "properties": {
                "name": "Uptown"
              }
            }
          ]
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
        "format": "json",
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
