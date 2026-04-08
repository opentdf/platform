package metadata

import (
	"time"

	"github.com/Masterminds/semver/v3"
)

const ArtifactName = "policy-migration"

type ArtifactMetadata struct {
	SchemaValue    string    `json:"schema"`
	NameValue      string    `json:"name"`
	RunIDValue     string    `json:"run_id"`
	CreatedAtValue time.Time `json:"created_at"`
}

func New(schema, runID string, createdAt time.Time) ArtifactMetadata {
	return ArtifactMetadata{
		SchemaValue:    schema,
		NameValue:      ArtifactName,
		RunIDValue:     runID,
		CreatedAtValue: createdAt,
	}
}

func (m ArtifactMetadata) Schema() *semver.Version {
	if m.SchemaValue == "" {
		return nil
	}

	version, err := semver.NewVersion(m.SchemaValue)
	if err != nil {
		return nil
	}

	return version
}

func (m ArtifactMetadata) Name() string {
	return m.NameValue
}

func (m ArtifactMetadata) RunID() string {
	return m.RunIDValue
}

func (m ArtifactMetadata) CreatedAt() time.Time {
	return m.CreatedAtValue
}
