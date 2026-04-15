package namespacedpolicy

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
)

var (
	ErrNilExecutorHandler               = errors.New("executor handler is required")
	ErrNilExecutionPlan                 = errors.New("execution plan is required")
	ErrPlanNotExecutable                = errors.New("plan is not executable")
	ErrExecutionPhaseNotImplemented     = errors.New("execution phase is not implemented")
	ErrMissingExistingTarget            = errors.New("missing existing target")
	ErrMissingMigratedTarget            = errors.New("missing migrated target")
	ErrMissingActionTarget              = errors.New("missing action target")
	ErrMissingSubjectConditionSetTarget = errors.New("missing subject condition set target")
	ErrTargetNamespaceRequired          = errors.New("target namespace is required")
	ErrMissingCreatedTargetID           = errors.New("missing created target id")
	ErrUnsupportedStatus                = errors.New("unsupported status")
)

const (
	migrationLabelMigratedFrom = "migrated_from"
	migrationLabelRun          = "migration_run"
)

type ExecutorHandler interface {
	CreateAction(ctx context.Context, name string, namespace string, metadata *common.MetadataMutable) (*policy.Action, error)
	CreateSubjectConditionSet(ctx context.Context, ss []*policy.SubjectSet, metadata *common.MetadataMutable, namespace string) (*policy.SubjectConditionSet, error)
	CreateNewSubjectMapping(ctx context.Context, attrValID string, actions []*policy.Action, existingSCSId string, newScs *subjectmapping.SubjectConditionSetCreate, metadata *common.MetadataMutable, namespace string) (*policy.SubjectMapping, error)
}

type Executor struct {
	handler              ExecutorHandler
	runID                string
	actionTargets        map[string]map[string]*ActionTargetPlan
	subjectConditionSets map[string]map[string]*SubjectConditionSetTargetPlan
}

func NewExecutor(handler ExecutorHandler) (*Executor, error) {
	if handler == nil {
		return nil, ErrNilExecutorHandler
	}

	return &Executor{
		handler:              handler,
		runID:                uuid.NewString(),
		actionTargets:        make(map[string]map[string]*ActionTargetPlan),
		subjectConditionSets: make(map[string]map[string]*SubjectConditionSetTargetPlan),
	}, nil
}

func (e *Executor) Execute(ctx context.Context, plan *Plan) error {
	if err := e.validatePlan(plan); err != nil {
		return err
	}

	if err := e.executeActions(ctx, plan.Actions); err != nil {
		return err
	}
	if err := e.executeSubjectConditionSets(ctx, plan.SubjectConditionSets); err != nil {
		return err
	}
	if err := e.executeSubjectMappings(ctx, plan.SubjectMappings); err != nil {
		return err
	}
	if err := e.executeRegisteredResources(ctx, plan.RegisteredResources); err != nil {
		return err
	}
	if err := e.executeObligationTriggers(ctx, plan.ObligationTriggers); err != nil {
		return err
	}

	return nil
}

func (e *Executor) validatePlan(plan *Plan) error {
	if e == nil || e.handler == nil {
		return ErrNilExecutorHandler
	}
	if plan == nil {
		return ErrNilExecutionPlan
	}
	if plan.Unresolved != nil && hasUnresolved(*plan.Unresolved) {
		return fmt.Errorf("%w: finalized plan contains unresolved entries", ErrPlanNotExecutable)
	}

	return nil
}

func metadataForCreate(sourceID string, sourceLabels map[string]string, runID string) *common.MetadataMutable {
	labels := map[string]string{}
	for key, value := range sourceLabels {
		labels[key] = value
	}

	labels[migrationLabelMigratedFrom] = sourceID
	labels[migrationLabelRun] = runID

	return &common.MetadataMutable{
		Labels: labels,
	}
}

func metadataLabels(metadata *common.Metadata) map[string]string {
	if metadata == nil {
		return nil
	}

	return metadata.GetLabels()
}

func namespaceIdentifier(namespace *policy.Namespace) string {
	if namespace == nil {
		return ""
	}
	if id := strings.TrimSpace(namespace.GetId()); id != "" {
		return id
	}
	return strings.TrimSpace(namespace.GetFqn())
}

func namespaceLabel(namespace *policy.Namespace) string {
	if namespace == nil {
		return "<unknown>"
	}
	if fqn := strings.TrimSpace(namespace.GetFqn()); fqn != "" {
		return fqn
	}
	if id := strings.TrimSpace(namespace.GetId()); id != "" {
		return id
	}
	return "<unknown>"
}
