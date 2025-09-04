package sdk

import (
	"encoding/json"
	"fmt"
	"runtime"
	"time"

	"github.com/opentdf/platform/sdk/tdf"
)

// GetSystemMetadataAssertionConfig returns a default assertion configuration with predefined values.
func GetSystemMetadataAssertionConfig() (tdf.AssertionConfig, error) {
	// Define the JSON structure
	type Metadata struct {
		TDFSpecVersion string `json:"tdf_spec_version,omitempty"`
		CreationDate   string `json:"creation_date,omitempty"`
		OS             string `json:"operating_system,omitempty"`
		SDKVersion     string `json:"sdk_version,omitempty"`
		GoVersion      string `json:"go_version,omitempty"`
		Architecture   string `json:"architecture,omitempty"`
	}

	// Populate the metadata
	metadata := Metadata{
		TDFSpecVersion: TDFSpecVersion,
		CreationDate:   time.Now().Format(time.RFC3339),
		OS:             runtime.GOOS,
		SDKVersion:     "Go-" + Version,
		GoVersion:      runtime.Version(),
		Architecture:   runtime.GOARCH,
	}

	// Marshal the metadata to JSON
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return tdf.AssertionConfig{}, fmt.Errorf("failed to marshal system metadata: %w", err)
	}

	return tdf.AssertionConfig{
		ID:             SystemMetadataAssertionID,
		Type:           tdf.BaseAssertion,
		Scope:          tdf.PayloadScope,
		AppliesToState: tdf.Unencrypted,
		Statement: Statement{
			Format: "json",
			Schema: SystemMetadataSchemaV1,
			Value:  string(metadataJSON),
		},
	}, nil
}
