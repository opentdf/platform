package namespacedpolicy

import (
	"context"
	"errors"
	"fmt"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
)

var (
	errMissingMockActionResult              = errors.New("missing mock action result")
	errMissingMockSubjectConditionSetResult = errors.New("missing mock subject condition set result")
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
	results                   map[string]map[string]*policy.Action
	errs                      map[string]map[string]error
	createdSubjectConditions  map[string]map[string]*createdSubjectConditionSetCall
	subjectConditionSetResult map[string]map[string]*policy.SubjectConditionSet
	subjectConditionSetErrs   map[string]map[string]error
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
