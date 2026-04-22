package namespacedpolicy

import (
	"context"
	"errors"
	"fmt"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
)

var (
	errMissingMockActionResult              = errors.New("missing mock action result")
	errMissingMockSubjectConditionSetResult = errors.New("missing mock subject condition set result")
	errMissingMockSubjectMappingResult      = errors.New("missing mock subject mapping result")
	errMissingMockObligationTriggerResult   = errors.New("missing mock obligation trigger result")
	errMissingMockRegisteredResourceResult  = errors.New("missing mock registered resource result")
	errMissingMockRegisteredResourceValue   = errors.New("missing mock registered resource value result")
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
	created                         map[string]map[string]*createdActionCall
	results                         map[string]map[string]*policy.Action // ! Should be renamed to actionResults
	errs                            map[string]map[string]error
	createdSubjectConditions        map[string]map[string]*createdSubjectConditionSetCall
	subjectConditionSetResult       map[string]map[string]*policy.SubjectConditionSet
	subjectConditionSetErrs         map[string]map[string]error
	createdSubjectMappings          map[string]map[string]*createdSubjectMappingCall
	subjectMappingResults           map[string]map[string]*policy.SubjectMapping
	subjectMappingErrs              map[string]map[string]error
	createdObligationTriggers       map[string]map[string]*createdObligationTriggerCall
	obligationTriggerResult         map[string]map[string]*policy.ObligationTrigger
	obligationTriggerErrs           map[string]map[string]error
	createdRegisteredResources      map[string]map[string]*createdRegisteredResourceCall
	registeredResourceResult        map[string]map[string]*policy.RegisteredResource
	registeredResourcesByID         map[string]*policy.RegisteredResource
	registeredResourceErrs          map[string]map[string]error
	createdRegisteredResourceValues map[string]map[string]*createdRegisteredResourceValueCall
	registeredResourceValueResult   map[string]map[string]*policy.RegisteredResourceValue
	registeredResourceValueErrs     map[string]map[string]error
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

type createdRegisteredResourceCall struct {
	Name      string
	Namespace string
	Values    []string
	Metadata  *common.MetadataMutable
}

type createdRegisteredResourceValueCall struct {
	ResourceID            string
	Value                 string
	ActionAttributeValues []*registeredresources.ActionAttributeValue
	Metadata              *common.MetadataMutable
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

func (m *mockExecutorHandler) CreateRegisteredResource(_ context.Context, namespace string, name string, values []string, metadata *common.MetadataMutable) (*policy.RegisteredResource, error) {
	sourceID := metadata.GetLabels()[migrationLabelMigratedFrom]

	if m.createdRegisteredResources == nil {
		m.createdRegisteredResources = make(map[string]map[string]*createdRegisteredResourceCall)
	}
	if m.createdRegisteredResources[sourceID] == nil {
		m.createdRegisteredResources[sourceID] = make(map[string]*createdRegisteredResourceCall)
	}

	m.createdRegisteredResources[sourceID][namespace] = &createdRegisteredResourceCall{
		Name:      name,
		Namespace: namespace,
		Values:    values,
		Metadata:  metadata,
	}

	if m.registeredResourceErrs != nil && m.registeredResourceErrs[sourceID] != nil {
		if err := m.registeredResourceErrs[sourceID][namespace]; err != nil {
			return nil, err
		}
	}
	if m.registeredResourceResult != nil && m.registeredResourceResult[sourceID] != nil {
		if result := m.registeredResourceResult[sourceID][namespace]; result != nil {
			if m.registeredResourcesByID == nil {
				m.registeredResourcesByID = make(map[string]*policy.RegisteredResource)
			}
			m.registeredResourcesByID[result.GetId()] = result
			return result, nil
		}
	}

	return nil, errMissingMockRegisteredResourceResult
}

func (m *mockExecutorHandler) GetRegisteredResource(_ context.Context, id, _, _ string) (*policy.RegisteredResource, error) {
	if id == "" {
		return nil, errMissingMockRegisteredResourceResult
	}
	if m.registeredResourcesByID != nil {
		if result := m.registeredResourcesByID[id]; result != nil {
			return result, nil
		}
	}
	return nil, errMissingMockRegisteredResourceResult
}

func (m *mockExecutorHandler) CreateRegisteredResourceValue(_ context.Context, resourceID string, value string, actionAttributeValues []*registeredresources.ActionAttributeValue, metadata *common.MetadataMutable) (*policy.RegisteredResourceValue, error) {
	sourceID := metadata.GetLabels()[migrationLabelMigratedFrom]

	if m.createdRegisteredResourceValues == nil {
		m.createdRegisteredResourceValues = make(map[string]map[string]*createdRegisteredResourceValueCall)
	}
	if m.createdRegisteredResourceValues[sourceID] == nil {
		m.createdRegisteredResourceValues[sourceID] = make(map[string]*createdRegisteredResourceValueCall)
	}

	m.createdRegisteredResourceValues[sourceID][resourceID] = &createdRegisteredResourceValueCall{
		ResourceID:            resourceID,
		Value:                 value,
		ActionAttributeValues: actionAttributeValues,
		Metadata:              metadata,
	}

	if m.registeredResourceValueErrs != nil && m.registeredResourceValueErrs[sourceID] != nil {
		if err := m.registeredResourceValueErrs[sourceID][resourceID]; err != nil {
			return nil, err
		}
	}
	if m.registeredResourceValueResult != nil && m.registeredResourceValueResult[sourceID] != nil {
		if result := m.registeredResourceValueResult[sourceID][resourceID]; result != nil {
			return result, nil
		}
	}

	return nil, errMissingMockRegisteredResourceValue
}
