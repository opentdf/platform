package cukes

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
)

type SubjectMappingsStepDefinitions struct{}

const policyDatabaseSchema = "otdf"

func (s *SubjectMappingsStepDefinitions) iSendARequestToCreateSubjectMapping(ctx context.Context, tbl *godog.Table) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()
	cellIndexMap := make(map[int]string)
	subjectMappingRequests := []*subjectmapping.CreateSubjectMappingRequest{}
	referenceIDs := []string{}
	for ri, r := range tbl.Rows {
		subjectMappingRequest := subjectmapping.CreateSubjectMappingRequest{}
		subjectMappingRequest.Actions = []*policy.Action{}
		var standardActions *string
		var customActions *string
		for ci, c := range r.Cells {
			if ri == 0 {
				cellIndexMap[ci] = c.Value
			} else {
				switch cellIndexMap[ci] {
				case namespaceIDKey:
					nsID, ok := scenarioContext.GetObject(strings.TrimSpace(c.Value)).(string)
					if !ok {
						return ctx, fmt.Errorf("unable to get namespace id for %s", c.Value)
					}
					subjectMappingRequest.NamespaceId = nsID
				case "namespace_fqn":
					subjectMappingRequest.NamespaceFqn = strings.TrimSpace(c.Value)
				case "attribute_value":
					av, err := scenarioContext.GetAttributeValue(ctx, strings.TrimSpace(c.Value))
					if err != nil {
						return ctx, err
					}
					subjectMappingRequest.AttributeValueId = av.GetId()
				case "condition_set_name":
					scs, ok := scenarioContext.GetObject(strings.TrimSpace(c.Value)).(*policy.SubjectConditionSet)
					if !ok {
						return ctx, fmt.Errorf("unable to get condition set for %s", c.Value)
					}

					subjectMappingRequest.ExistingSubjectConditionSetId = scs.GetId()
				case "standard actions":
					standardActions = &c.Value
				case "custom actions":
					customActions = &c.Value
				case "reference_id":
					referenceIDs = append(referenceIDs, strings.TrimSpace(c.Value))
				default:
					return ctx, fmt.Errorf("invalid condition value: %s", c.Value)
				}
			}
		}
		if ri > 0 {
			subjectMappingRequest.Actions = GetActionsFromValues(standardActions, customActions)
			subjectMappingRequests = append(subjectMappingRequests, &subjectMappingRequest)
		}
	}
	for i, subjectMappingRequest := range subjectMappingRequests {
		resp, err := scenarioContext.SDK.SubjectMapping.CreateSubjectMapping(ctx, subjectMappingRequest)
		if err != nil {
			return ctx, err
		}
		if resp != nil {
			scenarioContext.RecordObject(referenceIDs[i], resp.GetSubjectMapping())
		}
	}

	return ctx, nil
}

func (s *SubjectMappingsStepDefinitions) iSendARequestToCreateSubjectConditionSet(ctx context.Context, referenceID string, subjectSetIDs string) (context.Context, error) {
	return s.createSubjectConditionSet(ctx, referenceID, subjectSetIDs, "")
}

func (s *SubjectMappingsStepDefinitions) iSendARequestToCreateSubjectConditionSetInNamespace(ctx context.Context, referenceID string, namespaceRef string, subjectSetIDs string) (context.Context, error) {
	return s.createSubjectConditionSet(ctx, referenceID, subjectSetIDs, namespaceRef)
}

func (s *SubjectMappingsStepDefinitions) createSubjectConditionSet(ctx context.Context, referenceID string, subjectSetIDs string, namespaceRef string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()
	subjectSets := []*policy.SubjectSet{}
	for _, subjectSetID := range strings.Split(subjectSetIDs, ",") {
		ss, ok := scenarioContext.GetObject(strings.TrimSpace(subjectSetID)).(*policy.SubjectSet)
		if !ok {
			return ctx, fmt.Errorf("invalid subject set id: %s", subjectSetID)
		}
		subjectSets = append(subjectSets, ss)
	}
	req := &subjectmapping.CreateSubjectConditionSetRequest{
		SubjectConditionSet: &subjectmapping.SubjectConditionSetCreate{
			SubjectSets: subjectSets,
		},
	}

	if namespaceRef != "" {
		nsID, ok := scenarioContext.GetObject(strings.TrimSpace(namespaceRef)).(string)
		if !ok {
			return ctx, fmt.Errorf("unable to get namespace id for %s", namespaceRef)
		}
		req.NamespaceId = nsID
	}

	resp, respErr := scenarioContext.SDK.SubjectMapping.CreateSubjectConditionSet(ctx, req)
	if resp != nil {
		scenarioContext.RecordObject(referenceID, resp.GetSubjectConditionSet())
	}
	scenarioContext.SetError(respErr)
	return ctx, nil
}

func (s *SubjectMappingsStepDefinitions) aSubjectSet(ctx context.Context, referenceID string, conditionGroupIDs string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	conditionGroups := []*policy.ConditionGroup{}
	for _, id := range strings.Split(conditionGroupIDs, ",") {
		id = strings.TrimSpace(id)
		cg, ok := scenarioContext.GetObject(id).(*policy.ConditionGroup)
		if !ok {
			return ctx, fmt.Errorf("invalid condition group id: %s", id)
		}
		conditionGroups = append(conditionGroups, cg)
	}
	subjectSet := &policy.SubjectSet{
		ConditionGroups: conditionGroups,
	}
	scenarioContext.RecordObject(referenceID, subjectSet)
	return ctx, nil
}

func (s *SubjectMappingsStepDefinitions) aConditionGroup(ctx context.Context, referenceID string, operator string, tbl *godog.Table) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	cellIndexMap := make(map[int]string)
	conditions := []*policy.Condition{}
	for ri, r := range tbl.Rows {
		condition := policy.Condition{}
		for ci, c := range r.Cells {
			if ri == 0 {
				cellIndexMap[ci] = c.Value
			} else {
				switch cellIndexMap[ci] {
				case "selector_value":
					condition.SubjectExternalSelectorValue = c.Value
				case "operator":
					condition.Operator = policy.SubjectMappingOperatorEnum(policy.SubjectMappingOperatorEnum_value["SUBJECT_MAPPING_OPERATOR_ENUM_"+strings.ToUpper(strings.TrimSpace(c.Value))])
				case "values":
					values := strings.Split(c.Value, ",")
					valueList := []string{}
					for _, value := range values {
						valueList = append(valueList, strings.TrimSpace(value))
					}
					condition.SubjectExternalValues = valueList
				}
			}
		}
		if ri > 0 {
			conditions = append(conditions, &condition)
		}
	}
	var boper policy.ConditionBooleanTypeEnum
	switch operator {
	case "or":
		boper = policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_OR
	case "and":
		boper = policy.ConditionBooleanTypeEnum_CONDITION_BOOLEAN_TYPE_ENUM_AND
	default:
		return ctx, errors.New("unsupported boolean operator: " + operator)
	}
	conditionGroup := &policy.ConditionGroup{
		BooleanOperator: boper,
		Conditions:      conditions,
	}
	scenarioContext.RecordObject(referenceID, conditionGroup)
	return ctx, nil
}

// iSendARequestToCreateSubjectMappingForEveryAttributeValue maps every value of a previously
// created attribute to a single condition set. Attributes carrying a value count in the thousands,
// each with its own subject mapping, are the shape that exhausted the v1 GetDecisions message limit
// (opentdf/platform#3821); they are impractical to enumerate in a table.
func (s *SubjectMappingsStepDefinitions) iSendARequestToCreateSubjectMappingForEveryAttributeValue(ctx context.Context, attributeRef, conditionSetRef, actions string) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()

	attr, ok := scenarioContext.GetObject(strings.TrimSpace(attributeRef)).(*policy.Attribute)
	if !ok {
		return ctx, fmt.Errorf("unable to get attribute for %s", attributeRef)
	}
	scs, ok := scenarioContext.GetObject(strings.TrimSpace(conditionSetRef)).(*policy.SubjectConditionSet)
	if !ok {
		return ctx, fmt.Errorf("unable to get condition set for %s", conditionSetRef)
	}
	if len(attr.GetValues()) == 0 {
		return ctx, fmt.Errorf("attribute %s has no values to map", attributeRef)
	}

	mappingActions := GetActionsFromValues(&actions, nil)
	for _, v := range attr.GetValues() {
		_, err := scenarioContext.SDK.SubjectMapping.CreateSubjectMapping(ctx, &subjectmapping.CreateSubjectMappingRequest{
			AttributeValueId:              v.GetId(),
			ExistingSubjectConditionSetId: scs.GetId(),
			Actions:                       mappingActions,
		})
		if err != nil {
			scenarioContext.SetError(err)
			return ctx, fmt.Errorf("create subject mapping for value %s: %w", v.GetFqn(), err)
		}
	}

	return ctx, nil
}

// seedSubjectAndResourceMappingsAtScale uses the scenario database for fixture setup so the
// end-to-end test spends its measured time in authorization, not in thousands of setup requests.
// The decision itself still goes through the public v2 API and the running platform container.
func (s *SubjectMappingsStepDefinitions) seedSubjectAndResourceMappingsAtScale(ctx context.Context, expectedSubjectMappings int, attributeRef, conditionSetRef, namespaceRef, action string, resourceMappingCount int) (context.Context, error) {
	scenarioContext := GetPlatformScenarioContext(ctx)
	scenarioContext.ClearError()

	attr, ok := scenarioContext.GetObject(strings.TrimSpace(attributeRef)).(*policy.Attribute)
	if !ok {
		return ctx, fmt.Errorf("unable to get attribute for %s", attributeRef)
	}
	if len(attr.GetValues()) != expectedSubjectMappings {
		return ctx, fmt.Errorf("attribute %s has %d values, expected %d", attributeRef, len(attr.GetValues()), expectedSubjectMappings)
	}
	if resourceMappingCount < 0 || resourceMappingCount > len(attr.GetValues()) {
		return ctx, fmt.Errorf("resource mapping count %d must be between 0 and %d", resourceMappingCount, len(attr.GetValues()))
	}
	scs, ok := scenarioContext.GetObject(strings.TrimSpace(conditionSetRef)).(*policy.SubjectConditionSet)
	if !ok {
		return ctx, fmt.Errorf("unable to get condition set for %s", conditionSetRef)
	}
	namespaceID, ok := scenarioContext.GetObject(strings.TrimSpace(namespaceRef)).(string)
	if !ok {
		return ctx, fmt.Errorf("unable to get namespace id for %s", namespaceRef)
	}
	localPlatformGlue, ok := (*scenarioContext.TestSuiteContext.PlatformGlue).(*LocalDevPlatformGlue)
	if !ok {
		return ctx, errors.New("failed to load local platform glue")
	}

	pgConfig, err := pgxpool.ParseConfig(fmt.Sprintf(
		"postgres://postgres:changeme@localhost:%d/%s?sslmode=prefer",
		localPlatformGlue.Options.postgresPort,
		scenarioContext.ScenarioOptions.DatabaseName,
	))
	if err != nil {
		return ctx, fmt.Errorf("parse scenario database config: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		return ctx, fmt.Errorf("connect to scenario database: %w", err)
	}
	defer pool.Close()

	tx, err := pool.Begin(ctx)
	if err != nil {
		return ctx, fmt.Errorf("begin scale fixture transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var actionID string
	err = tx.QueryRow(ctx, `
		SELECT id
		FROM otdf.actions
		WHERE name = $1 AND (namespace_id = $2 OR namespace_id IS NULL)
		ORDER BY (namespace_id = $2) DESC
		LIMIT 1
	`, strings.ToLower(strings.TrimSpace(action)), namespaceID).Scan(&actionID)
	if err != nil {
		return ctx, fmt.Errorf("resolve action %q: %w", action, err)
	}

	subjectMappingRows := make([][]any, 0, expectedSubjectMappings)
	actionRows := make([][]any, 0, expectedSubjectMappings)
	resourceMappingRows := make([][]any, 0, resourceMappingCount)
	for i, value := range attr.GetValues() {
		mappingID := uuid.NewString()
		subjectMappingRows = append(subjectMappingRows, []any{mappingID, value.GetId(), scs.GetId(), namespaceID})
		actionRows = append(actionRows, []any{mappingID, actionID})
		if i < resourceMappingCount {
			resourceMappingRows = append(resourceMappingRows, []any{
				uuid.NewString(),
				value.GetId(),
				[]string{fmt.Sprintf("resource-%04d", i)},
				namespaceID,
			})
		}
	}

	inserted, err := tx.CopyFrom(ctx, pgx.Identifier{policyDatabaseSchema, "subject_mappings"}, []string{"id", "attribute_value_id", "subject_condition_set_id", namespaceIDKey}, pgx.CopyFromRows(subjectMappingRows))
	if err != nil {
		return ctx, fmt.Errorf("seed subject mappings: %w", err)
	}
	if inserted != int64(expectedSubjectMappings) {
		return ctx, fmt.Errorf("seeded %d subject mappings, expected %d", inserted, expectedSubjectMappings)
	}
	inserted, err = tx.CopyFrom(ctx, pgx.Identifier{policyDatabaseSchema, "subject_mapping_actions"}, []string{"subject_mapping_id", "action_id"}, pgx.CopyFromRows(actionRows))
	if err != nil {
		return ctx, fmt.Errorf("seed subject mapping actions: %w", err)
	}
	if inserted != int64(expectedSubjectMappings) {
		return ctx, fmt.Errorf("seeded %d subject mapping actions, expected %d", inserted, expectedSubjectMappings)
	}
	inserted, err = tx.CopyFrom(ctx, pgx.Identifier{policyDatabaseSchema, "resource_mappings"}, []string{"id", "attribute_value_id", "terms", namespaceIDKey}, pgx.CopyFromRows(resourceMappingRows))
	if err != nil {
		return ctx, fmt.Errorf("seed resource mappings: %w", err)
	}
	if inserted != int64(resourceMappingCount) {
		return ctx, fmt.Errorf("seeded %d resource mappings, expected %d", inserted, resourceMappingCount)
	}
	if err := tx.Commit(ctx); err != nil {
		return ctx, fmt.Errorf("commit scale fixtures: %w", err)
	}

	scenarioContext.TestSuiteContext.Logger.Info(
		"seeded authorization scale fixture",
		slog.Int("subject_mapping_count", expectedSubjectMappings),
		slog.Int("resource_mapping_count", resourceMappingCount),
	)
	return ctx, nil
}

func RegisterSubjectMappingsStepsDefinitions(ctx *godog.ScenarioContext) {
	subjectMappingStepDefinitions := &SubjectMappingsStepDefinitions{}
	ctx.Step(`a condition group referenced as "([^"]*)" with an "([^"]*)" operator with conditions:$`, subjectMappingStepDefinitions.aConditionGroup)
	ctx.Step(`^a subject set referenced as "([^"]*)" containing the condition groups "([^"]*)"$`, subjectMappingStepDefinitions.aSubjectSet)
	ctx.Step(`^I send a request to create a subject condition set referenced as "([^"]*)" containing subject sets "([^"]*)"$`, subjectMappingStepDefinitions.iSendARequestToCreateSubjectConditionSet)
	ctx.Step(`^I send a request to create a subject condition set referenced as "([^"]*)" in namespace "([^"]*)" containing subject sets "([^"]*)"$`, subjectMappingStepDefinitions.iSendARequestToCreateSubjectConditionSetInNamespace)
	ctx.Step(`^I send a request to create a subject mapping with:$`, subjectMappingStepDefinitions.iSendARequestToCreateSubjectMapping)
	ctx.Step(`^I send a request to create a subject mapping for every value of attribute "([^"]*)" using condition set "([^"]*)" with actions "([^"]*)"$`, subjectMappingStepDefinitions.iSendARequestToCreateSubjectMappingForEveryAttributeValue)
	ctx.Step(`^the policy database contains (\d+) subject mappings for attribute "([^"]*)" using condition set "([^"]*)" in namespace "([^"]*)" with action "([^"]*)" and (\d+) resource mappings$`, subjectMappingStepDefinitions.seedSubjectAndResourceMappingsAtScale)
}
