package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/evertras/bubble-table/table"
	"github.com/google/uuid"
	"github.com/opentdf/platform/otdfctl/cmd/common"
	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/handlers"
	"github.com/opentdf/platform/otdfctl/pkg/man"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/subjectmapping"
	"github.com/spf13/cobra"
)

// parseDynamicValueMappingActions converts each flag value into an Action referenced by id (when a
// UUID) or by name otherwise.
func parseDynamicValueMappingActions(values []string) []*policy.Action {
	actions := make([]*policy.Action, len(values))
	for i, a := range values {
		action := &policy.Action{}
		if _, err := uuid.Parse(a); err != nil {
			action.Name = a
		} else {
			action.Id = a
		}
		actions[i] = action
	}
	return actions
}

// parseDynamicValueMappingOperator validates the readable operator choice and returns its enum.
// Only IN and IN_CONTAINS are supported; NOT_IN, UNSPECIFIED, and unknown values are rejected.
func parseDynamicValueMappingOperator(operator string) policy.SubjectMappingOperatorEnum {
	op := handlers.GetSubjectMappingOperatorFromChoice(operator)
	if op != policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN &&
		op != policy.SubjectMappingOperatorEnum_SUBJECT_MAPPING_OPERATOR_ENUM_IN_CONTAINS {
		cli.ExitWithError(fmt.Sprintf("Invalid --operator %q; must be one of %s", operator, strings.Join(handlers.DynamicValueMappingOperatorEnumChoices, ", ")), nil)
	}
	return op
}

func dynamicValueMappingRows(m *policy.DynamicValueMapping) [][]string {
	actionsJSON, err := json.Marshal(m.GetActions())
	if err != nil {
		cli.ExitWithError("Error marshalling dynamic value mapping actions", err)
	}
	subjectSetsJSON, err := json.Marshal(m.GetSubjectConditionSet().GetSubjectSets())
	if err != nil {
		cli.ExitWithError("Error marshalling subject condition set", err)
	}
	return [][]string{
		{"Id", m.GetId()},
		{"Namespace", m.GetNamespace().GetFqn()},
		{"Attribute Definition: Id", m.GetAttributeDefinition().GetId()},
		{"Attribute Definition: FQN", m.GetAttributeDefinition().GetFqn()},
		{"Resolver: Selector", m.GetValueResolver().GetSubjectExternalSelectorValue()},
		{"Resolver: Operator", handlers.GetSubjectMappingOperatorChoiceFromEnum(m.GetValueResolver().GetOperator())},
		{"Actions", string(actionsJSON)},
		{"Subject Condition Set: Id", m.GetSubjectConditionSet().GetId()},
		{"Subject Condition Set", string(subjectSetsJSON)},
	}
}

func policyGetDynamicValueMapping(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")

	mapping, err := h.GetDynamicValueMapping(cmd.Context(), id)
	if err != nil {
		cli.ExitWithError(fmt.Sprintf("Failed to find dynamic value mapping (%s)", id), err)
	}

	rows := dynamicValueMappingRows(mapping)
	if mdRows := getMetadataRows(mapping.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, mapping.GetId(), t, mapping)
}

func policyListDynamicValueMappings(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	limit := c.Flags.GetRequiredInt32("limit")
	offset := c.Flags.GetRequiredInt32("offset")
	namespace := c.Flags.GetOptionalString("namespace")
	attrDefID := c.Flags.GetOptionalID("attribute-definition-id")
	sort := getSortOption(c)

	resp, err := h.ListDynamicValueMappings(cmd.Context(), limit, offset, namespace, attrDefID, sort)
	if err != nil {
		cli.ExitWithError("Failed to list dynamic value mappings", err)
	}

	t := cli.NewTable(
		cli.NewUUIDColumn(),
		table.NewFlexColumn("namespace", "Namespace", cli.FlexColumnWidthFour),
		table.NewFlexColumn("attr_definition_fqn", "Attribute Definition FQN", cli.FlexColumnWidthFour),
		table.NewFlexColumn("selector", "Resolver Selector", cli.FlexColumnWidthThree),
		table.NewFlexColumn("operator", "Resolver Operator", cli.FlexColumnWidthTwo),
		table.NewFlexColumn("actions", "Actions", cli.FlexColumnWidthTwo),
		table.NewFlexColumn("subject_condition_set_id", "Subject Condition Set: Id", cli.FlexColumnWidthFour),
	)
	rows := []table.Row{}
	for _, dvm := range resp.GetDynamicValueMappings() {
		actionsJSON, err := json.Marshal(dvm.GetActions())
		if err != nil {
			cli.ExitWithError("Error marshalling dynamic value mapping actions", err)
		}
		rows = append(rows, table.NewRow(table.RowData{
			"id":                       dvm.GetId(),
			"namespace":                dvm.GetNamespace().GetFqn(),
			"attr_definition_fqn":      dvm.GetAttributeDefinition().GetFqn(),
			"selector":                 dvm.GetValueResolver().GetSubjectExternalSelectorValue(),
			"operator":                 handlers.GetSubjectMappingOperatorChoiceFromEnum(dvm.GetValueResolver().GetOperator()),
			"actions":                  string(actionsJSON),
			"subject_condition_set_id": dvm.GetSubjectConditionSet().GetId(),
		}))
	}
	t = t.WithRows(rows)
	t = cli.WithListPaginationFooter(t, resp.GetPagination())
	common.HandleSuccess(cmd, "", t, resp)
}

func policyCreateDynamicValueMapping(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	attrDefID := c.Flags.GetOptionalID("attribute-definition-id")
	attrDefFQN := c.Flags.GetOptionalString("attribute-definition-fqn")
	selector := c.Flags.GetOptionalString("selector")
	operator := c.Flags.GetOptionalString("operator")
	actionFlagValues = c.Flags.GetStringSlice("action", actionFlagValues, cli.FlagsStringSliceOptions{Min: 0})
	existingSCSID := c.Flags.GetOptionalID("subject-condition-set-id")
	newScsJSON := c.Flags.GetOptionalString("subject-condition-set-new")
	namespace := c.Flags.GetOptionalString("namespace")
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	// validations
	if attrDefID == "" && attrDefFQN == "" {
		cli.ExitWithError("One of [--attribute-definition-id, --attribute-definition-fqn] is required", nil)
	}
	if attrDefID != "" && attrDefFQN != "" {
		cli.ExitWithError("Only one of [--attribute-definition-id, --attribute-definition-fqn] may be provided", nil)
	}
	if selector == "" {
		cli.ExitWithError("The resolver selector [--selector] is required", nil)
	}
	if operator == "" {
		cli.ExitWithError("The resolver operator [--operator] is required", nil)
	}
	if len(actionFlagValues) == 0 {
		cli.ExitWithError("At least one Action [--action] is required", nil)
	}

	resolver := &policy.DynamicValueResolver{
		SubjectExternalSelectorValue: selector,
		Operator:                     parseDynamicValueMappingOperator(operator),
	}
	actions := parseDynamicValueMappingActions(actionFlagValues)

	var scs *subjectmapping.SubjectConditionSetCreate
	if newScsJSON != "" {
		ss, err := unmarshalSubjectSetsProto([]byte(newScsJSON))
		if err != nil {
			cli.ExitWithError("Error unmarshalling subject sets", err)
		}
		scs = &subjectmapping.SubjectConditionSetCreate{
			SubjectSets: ss,
		}
	}

	mapping, err := h.CreateDynamicValueMapping(cmd.Context(), attrDefID, attrDefFQN, resolver, actions, existingSCSID, scs, namespace, getMetadataMutable(metadataLabels))
	if err != nil {
		cli.ExitWithError("Failed to create dynamic value mapping", err)
	}

	rows := dynamicValueMappingRows(mapping)
	if mdRows := getMetadataRows(mapping.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, mapping.GetId(), t, mapping)
}

func policyUpdateDynamicValueMapping(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")
	selector := c.Flags.GetOptionalString("selector")
	operator := c.Flags.GetOptionalString("operator")
	actionFlagValues = c.Flags.GetStringSlice("action", actionFlagValues, cli.FlagsStringSliceOptions{Min: 0})
	scsID := c.Flags.GetOptionalID("subject-condition-set-id")
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	// The resolver is replaced as a whole and both of its fields are required, so --selector and
	// --operator must be provided together (or both omitted to leave the resolver unchanged).
	if (selector == "") != (operator == "") {
		cli.ExitWithError("Both [--selector, --operator] must be provided together to replace the resolver", nil)
	}
	var resolver *policy.DynamicValueResolver
	if selector != "" {
		resolver = &policy.DynamicValueResolver{
			SubjectExternalSelectorValue: selector,
			Operator:                     parseDynamicValueMappingOperator(operator),
		}
	}

	var actions []*policy.Action
	if len(actionFlagValues) > 0 {
		actions = parseDynamicValueMappingActions(actionFlagValues)
	}

	updated, err := h.UpdateDynamicValueMapping(
		cmd.Context(),
		id,
		resolver,
		scsID,
		actions,
		getMetadataMutable(metadataLabels),
		getMetadataUpdateBehavior(),
	)
	if err != nil {
		cli.ExitWithError("Failed to update dynamic value mapping", err)
	}

	rows := [][]string{{"Id", id}}
	if mdRows := getMetadataRows(updated.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, id, t, updated)
}

func policyDeleteDynamicValueMapping(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")
	force := c.Flags.GetOptionalBool("force")

	dvm, err := h.GetDynamicValueMapping(cmd.Context(), id)
	if err != nil {
		cli.ExitWithError(fmt.Sprintf("Failed to find dynamic value mapping (%s)", id), err)
	}

	cli.ConfirmAction(cli.ActionDelete, "dynamic value mapping", dvm.GetId(), force)

	deleted, err := h.DeleteDynamicValueMapping(cmd.Context(), id)
	if err != nil {
		cli.ExitWithError(fmt.Sprintf("Failed to delete dynamic value mapping (%s)", id), err)
	}

	rows := [][]string{{"Id", dvm.GetId()}}
	if mdRows := getMetadataRows(deleted.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, id, t, deleted)
}

func initDynamicValueMappingsCommands() {
	getDoc := man.Docs.GetCommand(
		"policy/dynamic-value-mappings/get",
		man.WithRun(policyGetDynamicValueMapping),
	)
	getDoc.Flags().StringP(
		getDoc.GetDocFlag("id").Name,
		getDoc.GetDocFlag("id").Shorthand,
		getDoc.GetDocFlag("id").Default,
		getDoc.GetDocFlag("id").Description,
	)

	listDoc := man.Docs.GetCommand(
		"policy/dynamic-value-mappings/list",
		man.WithRun(policyListDynamicValueMappings),
	)
	injectListPaginationFlags(listDoc)
	injectListSortFlags(listDoc)
	listDoc.Flags().StringP(
		listDoc.GetDocFlag("namespace").Name,
		listDoc.GetDocFlag("namespace").Shorthand,
		listDoc.GetDocFlag("namespace").Default,
		listDoc.GetDocFlag("namespace").Description,
	)
	listDoc.Flags().String(
		listDoc.GetDocFlag("attribute-definition-id").Name,
		listDoc.GetDocFlag("attribute-definition-id").Default,
		listDoc.GetDocFlag("attribute-definition-id").Description,
	)

	createDoc := man.Docs.GetCommand(
		"policy/dynamic-value-mappings/create",
		man.WithRun(policyCreateDynamicValueMapping),
	)
	createDoc.Flags().StringP(
		createDoc.GetDocFlag("attribute-definition-id").Name,
		createDoc.GetDocFlag("attribute-definition-id").Shorthand,
		createDoc.GetDocFlag("attribute-definition-id").Default,
		createDoc.GetDocFlag("attribute-definition-id").Description,
	)
	createDoc.Flags().String(
		createDoc.GetDocFlag("attribute-definition-fqn").Name,
		createDoc.GetDocFlag("attribute-definition-fqn").Default,
		createDoc.GetDocFlag("attribute-definition-fqn").Description,
	)
	createDoc.Flags().StringP(
		createDoc.GetDocFlag("selector").Name,
		createDoc.GetDocFlag("selector").Shorthand,
		createDoc.GetDocFlag("selector").Default,
		createDoc.GetDocFlag("selector").Description,
	)
	createDoc.Flags().StringP(
		createDoc.GetDocFlag("operator").Name,
		createDoc.GetDocFlag("operator").Shorthand,
		createDoc.GetDocFlag("operator").Default,
		createDoc.GetDocFlag("operator").Description,
	)
	createDoc.Flags().StringSliceVarP(
		&actionFlagValues,
		createDoc.GetDocFlag("action").Name,
		createDoc.GetDocFlag("action").Shorthand,
		[]string{},
		createDoc.GetDocFlag("action").Description,
	)
	createDoc.Flags().String(
		createDoc.GetDocFlag("subject-condition-set-id").Name,
		createDoc.GetDocFlag("subject-condition-set-id").Default,
		createDoc.GetDocFlag("subject-condition-set-id").Description,
	)
	createDoc.Flags().String(
		createDoc.GetDocFlag("subject-condition-set-new").Name,
		createDoc.GetDocFlag("subject-condition-set-new").Default,
		createDoc.GetDocFlag("subject-condition-set-new").Description,
	)
	createDoc.Flags().StringP(
		createDoc.GetDocFlag("namespace").Name,
		createDoc.GetDocFlag("namespace").Shorthand,
		createDoc.GetDocFlag("namespace").Default,
		createDoc.GetDocFlag("namespace").Description,
	)
	injectLabelFlags(&createDoc.Command, false)

	updateDoc := man.Docs.GetCommand(
		"policy/dynamic-value-mappings/update",
		man.WithRun(policyUpdateDynamicValueMapping),
	)
	updateDoc.Flags().StringP(
		updateDoc.GetDocFlag("id").Name,
		updateDoc.GetDocFlag("id").Shorthand,
		updateDoc.GetDocFlag("id").Default,
		updateDoc.GetDocFlag("id").Description,
	)
	updateDoc.Flags().StringP(
		updateDoc.GetDocFlag("selector").Name,
		updateDoc.GetDocFlag("selector").Shorthand,
		updateDoc.GetDocFlag("selector").Default,
		updateDoc.GetDocFlag("selector").Description,
	)
	updateDoc.Flags().StringP(
		updateDoc.GetDocFlag("operator").Name,
		updateDoc.GetDocFlag("operator").Shorthand,
		updateDoc.GetDocFlag("operator").Default,
		updateDoc.GetDocFlag("operator").Description,
	)
	updateDoc.Flags().StringSliceVarP(
		&actionFlagValues,
		updateDoc.GetDocFlag("action").Name,
		updateDoc.GetDocFlag("action").Shorthand,
		[]string{},
		updateDoc.GetDocFlag("action").Description,
	)
	updateDoc.Flags().String(
		updateDoc.GetDocFlag("subject-condition-set-id").Name,
		updateDoc.GetDocFlag("subject-condition-set-id").Default,
		updateDoc.GetDocFlag("subject-condition-set-id").Description,
	)
	injectLabelFlags(&updateDoc.Command, true)

	deleteDoc := man.Docs.GetCommand(
		"policy/dynamic-value-mappings/delete",
		man.WithRun(policyDeleteDynamicValueMapping),
	)
	deleteDoc.Flags().StringP(
		deleteDoc.GetDocFlag("id").Name,
		deleteDoc.GetDocFlag("id").Shorthand,
		deleteDoc.GetDocFlag("id").Default,
		deleteDoc.GetDocFlag("id").Description,
	)
	deleteDoc.Flags().Bool(
		deleteDoc.GetDocFlag("force").Name,
		false,
		deleteDoc.GetDocFlag("force").Description,
	)

	doc := man.Docs.GetCommand(
		"policy/dynamic-value-mappings",
		man.WithSubcommands(
			createDoc,
			getDoc,
			listDoc,
			updateDoc,
			deleteDoc,
		),
	)
	dynamicValueMappingCmd := &doc.Command
	Cmd.AddCommand(dynamicValueMappingCmd)
}
