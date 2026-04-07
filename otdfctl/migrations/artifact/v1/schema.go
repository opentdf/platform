package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	artifactmetadata "github.com/opentdf/platform/otdfctl/migrations/artifact/metadata"
)

const SchemaVersion = "v1.0.0"

var (
	ErrNotImplemented  = errors.New("not implemented")
	ErrNilWriter       = errors.New("nil writer")
	ErrWriteArtifact   = errors.New("write artifact")
	ErrSummaryArtifact = errors.New("summary artifact")
)

type artifact struct {
	MetadataData         artifactmetadata.ArtifactMetadata `json:"metadata"`
	SummaryData          Summary                           `json:"summary"`
	Skipped              []skippedEntry                    `json:"skipped"`
	Namespaces           []namespaceIndexEntry             `json:"namespaces"`
	Actions              []actionRecord                    `json:"actions"`
	SubjectConditionSets []subjectConditionSetRecord       `json:"subject_condition_sets"`
	SubjectMappings      []subjectMappingRecord            `json:"subject_mappings"`
	RegisteredResources  []registeredResourceRecord        `json:"registered_resources"`
	ObligationTriggers   []obligationTriggerRecord         `json:"obligation_triggers"`
	writer               io.Writer                         `json:"-"`
}

type Summary struct {
	Counts SummaryCounts `json:"counts"`
}

type SummaryCounts struct {
	Namespaces           int `json:"namespaces"`
	Actions              int `json:"actions"`
	SubjectConditionSets int `json:"subject_condition_sets"`
	SubjectMappings      int `json:"subject_mappings"`
	RegisteredResources  int `json:"registered_resources"`
	ObligationTriggers   int `json:"obligation_triggers"`
	Skipped              int `json:"skipped"`
}

type skippedEntry struct {
	Type              string         `json:"type"`
	SkippedReasonCode string         `json:"skipped_reason_code"`
	SkippedReason     string         `json:"skipped_reason"`
	Source            skippedSource  `json:"source"`
	Context           skippedContext `json:"context"`
}

type skippedSource struct {
	RegisteredResourceID      string `json:"registered_resource_id,omitempty"`
	RegisteredResourceValueID string `json:"registered_resource_value_id,omitempty"`
	ActionID                  string `json:"action_id,omitempty"`
	AttributeValueID          string `json:"attribute_value_id,omitempty"`
}

type skippedContext struct {
	TargetNamespaceID  string `json:"target_namespace_id,omitempty"`
	TargetNamespaceFQN string `json:"target_namespace_fqn,omitempty"`
}

type namespaceIndexEntry struct {
	FQN                  string   `json:"fqn"`
	ID                   string   `json:"id"`
	Actions              []string `json:"actions"`
	SubjectConditionSets []string `json:"subject_condition_sets"`
	SubjectMappings      []string `json:"subject_mappings"`
	RegisteredResources  []string `json:"registered_resources"`
	ObligationTriggers   []string `json:"obligation_triggers"`
}

type actionRecord struct {
	Source  actionSource   `json:"source"`
	Targets []actionTarget `json:"targets"`
}

type actionSource struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	NamespaceID *string `json:"namespace_id"`
	IsStandard  bool    `json:"is_standard"`
}

type actionTarget struct {
	NamespaceID  string `json:"namespace_id"`
	NamespaceFQN string `json:"namespace_fqn"`
	ID           string `json:"id"`
}

type subjectConditionSetRecord struct {
	Source  subjectConditionSetSource   `json:"source"`
	Targets []subjectConditionSetTarget `json:"targets"`
}

type subjectConditionSetSource struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	NamespaceID *string `json:"namespace_id"`
}

type subjectConditionSetTarget struct {
	NamespaceID  string `json:"namespace_id"`
	NamespaceFQN string `json:"namespace_fqn"`
	ID           string `json:"id"`
}

type subjectMappingRecord struct {
	Source  subjectMappingSource   `json:"source"`
	Targets []subjectMappingTarget `json:"targets"`
}

type subjectMappingSource struct {
	ID                    string   `json:"id"`
	ActionIDs             []string `json:"action_ids"`
	SubjectConditionSetID string   `json:"subject_condition_set_id"`
	NamespaceID           *string  `json:"namespace_id"`
	AttributeValueID      string   `json:"attribute_value_id"`
}

type subjectMappingTarget struct {
	NamespaceID           string   `json:"namespace_id"`
	NamespaceFQN          string   `json:"namespace_fqn"`
	ID                    string   `json:"id"`
	ActionIDs             []string `json:"action_ids"`
	SubjectConditionSetID string   `json:"subject_condition_set_id"`
	AttributeValueID      string   `json:"attribute_value_id"`
}

type registeredResourceRecord struct {
	Source  registeredResourceSource   `json:"source"`
	Targets []registeredResourceTarget `json:"targets"`
}

type registeredResourceSource struct {
	ID          string                    `json:"id"`
	Name        string                    `json:"name"`
	NamespaceID *string                   `json:"namespace_id"`
	Values      []registeredResourceValue `json:"values"`
}

type registeredResourceTarget struct {
	NamespaceID  string                    `json:"namespace_id"`
	NamespaceFQN string                    `json:"namespace_fqn"`
	ID           string                    `json:"id"`
	Values       []registeredResourceValue `json:"values"`
}

type registeredResourceValue struct {
	ID                    string                 `json:"id"`
	Value                 string                 `json:"value"`
	ActionAttributeValues []actionAttributeValue `json:"action_attribute_values"`
}

type actionAttributeValue struct {
	ActionID         string `json:"action_id"`
	AttributeValueID string `json:"attribute_value_id"`
}

type obligationTriggerRecord struct {
	Source  obligationTriggerSource   `json:"source"`
	Targets []obligationTriggerTarget `json:"targets"`
}

type obligationTriggerSource struct {
	ID                string `json:"id"`
	NamespaceID       string `json:"namespace_id"`
	NamespaceFQN      string `json:"namespace_fqn"`
	ActionID          string `json:"action_id"`
	ObligationValueID string `json:"obligation_value_id"`
	AttributeValueID  string `json:"attribute_value_id"`
	ClientID          string `json:"client_id"`
}

type obligationTriggerTarget struct {
	NamespaceID       string `json:"namespace_id"`
	NamespaceFQN      string `json:"namespace_fqn"`
	ActionID          string `json:"action_id"`
	ObligationValueID string `json:"obligation_value_id"`
	AttributeValueID  string `json:"attribute_value_id"`
	ClientID          string `json:"client_id"`
	ID                string `json:"id"`
}

func New(writer io.Writer) (*artifact, error) {
	if writer == nil {
		return nil, ErrNilWriter
	}

	return &artifact{
		MetadataData:         artifactmetadata.New(SchemaVersion, uuid.NewString(), time.Now().UTC()),
		Skipped:              []skippedEntry{},
		Namespaces:           []namespaceIndexEntry{},
		Actions:              []actionRecord{},
		SubjectConditionSets: []subjectConditionSetRecord{},
		SubjectMappings:      []subjectMappingRecord{},
		RegisteredResources:  []registeredResourceRecord{},
		ObligationTriggers:   []obligationTriggerRecord{},
		writer:               writer,
	}, nil
}

func (a *artifact) Build() error {
	return fmt.Errorf("%w: artifact build for schema %s", ErrNotImplemented, SchemaVersion)
}

func (a *artifact) Commit() error {
	return fmt.Errorf("%w: artifact commit for schema %s", ErrNotImplemented, SchemaVersion)
}

func (a *artifact) Metadata() artifactmetadata.ArtifactMetadata {
	return a.MetadataData
}

func (a *artifact) Summary() ([]byte, error) {
	summary := Summary{
		Counts: SummaryCounts{
			Namespaces:           len(a.Namespaces),
			Actions:              len(a.Actions),
			SubjectConditionSets: len(a.SubjectConditionSets),
			SubjectMappings:      len(a.SubjectMappings),
			RegisteredResources:  len(a.RegisteredResources),
			ObligationTriggers:   len(a.ObligationTriggers),
			Skipped:              len(a.Skipped),
		},
	}

	encoded, err := json.Marshal(summary)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSummaryArtifact, err)
	}

	return encoded, nil
}

func (a *artifact) Write() error {
	a.updateSummary()

	encoder := json.NewEncoder(a.writer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(a); err != nil {
		return fmt.Errorf("%w: %w", ErrWriteArtifact, err)
	}

	return nil
}

func (a *artifact) updateSummary() {
	a.SummaryData = Summary{
		Counts: SummaryCounts{
			Namespaces:           len(a.Namespaces),
			Actions:              len(a.Actions),
			SubjectConditionSets: len(a.SubjectConditionSets),
			SubjectMappings:      len(a.SubjectMappings),
			RegisteredResources:  len(a.RegisteredResources),
			ObligationTriggers:   len(a.ObligationTriggers),
			Skipped:              len(a.Skipped),
		},
	}
}
