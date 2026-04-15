package namespacedpolicy

import (
	"context"
	"errors"
	"fmt"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
)

var (
	errMissingMockActionResult              = errors.New("missing mock action result")
	errMissingMockSubjectConditionSetResult = errors.New("missing mock subject condition set result")
	errMissingMockSubjectMappingResult      = errors.New("missing mock subject mapping result")
	errMissingMockObligationTriggerResult   = errors.New("missing mock obligation trigger result")
)

type expectedError struct {
	is      error
	message string
}

func wantError(is error, format string, args ...any) *expectedError {
	return &expectedError{
		is:      is,
		message: fmt.Sprintf("%s: %s", is, fmt.Sprintf(format, args...)),
	}
}

type mockExecutorHandler struct {
	created                   map[string]map[string]*createdActionCall
	results                   map[string]map[string]*policy.Action // ! Should be renamed to actionResults
	errs                      map[string]map[string]error
	createdSubjectConditions  map[string]map[string]*createdSubjectConditionSetCall
	subjectConditionSetResult map[string]map[string]*policy.SubjectConditionSet
	subjectConditionSetErrs   map[string]map[string]error
	createdSubjectMappings    map[string]map[string]*createdSubjectMappingCall
	subjectMappingResults     map[string]map[string]*policy.SubjectMapping
	subjectMappingErrs        map[string]map[string]error
	createdObligationTriggers map[string]map[string]*createdObligationTriggerCall
	obligationTriggerResult   map[string]map[string]*policy.ObligationTrigger
	obligationTriggerErrs     map[string]map[string]error
}

type createdActionCall struct {
	Name      string
	Namespace string
	Metadata  *common.MetadataMutable
}

type createdSubjectConditionSetCall struct {
	SubjectSets []*policy.SubjectSet
	Namespace   string
	Metadata    *common.MetadataMutable
}

type createdSubjectMappingCall struct {
	AttributeValueID            string
	Actions                     []*policy.Action
	ExistingSubjectConditionSet string
	NewSubjectConditionSet      *subjectmapping.SubjectConditionSetCreate
	Namespace                   string
	Metadata                    *common.MetadataMutable
}
type createdObligationTriggerCall struct {
	AttributeValue  string
	Action          string
	ObligationValue string
	ClientID        string
	Metadata        *common.MetadataMutable
}

func (m *mockExecutorHandler) CreateAction(_ context.Context, name string, namespace string, metadata *common.MetadataMutable) (*policy.Action, error) {
	if m.created == nil {
		m.created = make(map[string]map[string]*createdActionCall)
	}
	if m.created[name] == nil {
		m.created[name] = make(map[string]*createdActionCall)
	}

	m.created[name][namespace] = &createdActionCall{
		Name:      name,
		Namespace: namespace,
		Metadata:  metadata,
	}

	if m.errs != nil && m.errs[name] != nil {
		if err := m.errs[name][namespace]; err != nil {
			return nil, err
		}
	}
	if m.results != nil && m.results[name] != nil {
		if result := m.results[name][namespace]; result != nil {
			return result, nil
		}
	}

	return nil, errMissingMockActionResult
}

func (m *mockExecutorHandler) CreateSubjectConditionSet(_ context.Context, ss []*policy.SubjectSet, metadata *common.MetadataMutable, namespace string) (*policy.SubjectConditionSet, error) {
	sourceID := metadata.GetLabels()[migrationLabelMigratedFrom]

	if m.createdSubjectConditions == nil {
		m.createdSubjectConditions = make(map[string]map[string]*createdSubjectConditionSetCall)
	}
	if m.createdSubjectConditions[sourceID] == nil {
		m.createdSubjectConditions[sourceID] = make(map[string]*createdSubjectConditionSetCall)
	}

	m.createdSubjectConditions[sourceID][namespace] = &createdSubjectConditionSetCall{
		SubjectSets: ss,
		Namespace:   namespace,
		Metadata:    metadata,
	}

	if m.subjectConditionSetErrs != nil && m.subjectConditionSetErrs[sourceID] != nil {
		if err := m.subjectConditionSetErrs[sourceID][namespace]; err != nil {
			return nil, err
		}
	}
	if m.subjectConditionSetResult != nil && m.subjectConditionSetResult[sourceID] != nil {
		if result := m.subjectConditionSetResult[sourceID][namespace]; result != nil {
			return result, nil
		}
	}

	return nil, errMissingMockSubjectConditionSetResult
}

func (m *mockExecutorHandler) CreateNewSubjectMapping(_ context.Context, attrValID string, actions []*policy.Action, existingSCSId string, newScs *subjectmapping.SubjectConditionSetCreate, metadata *common.MetadataMutable, namespace string) (*policy.SubjectMapping, error) {
	sourceID := metadata.GetLabels()[migrationLabelMigratedFrom]

	if m.createdSubjectMappings == nil {
		m.createdSubjectMappings = make(map[string]map[string]*createdSubjectMappingCall)
	}
	if m.createdSubjectMappings[sourceID] == nil {
		m.createdSubjectMappings[sourceID] = make(map[string]*createdSubjectMappingCall)
	}

	m.createdSubjectMappings[sourceID][namespace] = &createdSubjectMappingCall{
		AttributeValueID:            attrValID,
		Actions:                     actions,
		ExistingSubjectConditionSet: existingSCSId,
		NewSubjectConditionSet:      newScs,
		Namespace:                   namespace,
		Metadata:                    metadata,
	}

	if m.subjectMappingErrs != nil && m.subjectMappingErrs[sourceID] != nil {
		if err := m.subjectMappingErrs[sourceID][namespace]; err != nil {
			return nil, err
		}
	}
	if m.subjectMappingResults != nil && m.subjectMappingResults[sourceID] != nil {
		if result := m.subjectMappingResults[sourceID][namespace]; result != nil {
			return result, nil
		}
	}

	return nil, errMissingMockSubjectMappingResult
}

func (m *mockExecutorHandler) CreateObligationTrigger(_ context.Context, attributeValue, action, obligationValue, clientID string, metadata *common.MetadataMutable) (*policy.ObligationTrigger, error) {
	sourceID := metadata.GetLabels()[migrationLabelMigratedFrom]

	if m.createdObligationTriggers == nil {
		m.createdObligationTriggers = make(map[string]map[string]*createdObligationTriggerCall)
	}
	if m.createdObligationTriggers[sourceID] == nil {
		m.createdObligationTriggers[sourceID] = make(map[string]*createdObligationTriggerCall)
	}

	m.createdObligationTriggers[sourceID][action] = &createdObligationTriggerCall{
		AttributeValue:  attributeValue,
		Action:          action,
		ObligationValue: obligationValue,
		ClientID:        clientID,
		Metadata:        metadata,
	}

	if m.obligationTriggerErrs != nil && m.obligationTriggerErrs[sourceID] != nil {
		if err := m.obligationTriggerErrs[sourceID][action]; err != nil {
			return nil, err
		}
	}
	if m.obligationTriggerResult != nil && m.obligationTriggerResult[sourceID] != nil {
		if result := m.obligationTriggerResult[sourceID][action]; result != nil {
			return result, nil
		}
	}

	return nil, errMissingMockObligationTriggerResult
}
