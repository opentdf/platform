package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"strconv"

	"github.com/evertras/bubble-table/table"
	"github.com/opentdf/otdfctl/cmd/common"
	"github.com/opentdf/otdfctl/pkg/cli"
	"github.com/opentdf/otdfctl/pkg/handlers"
	"github.com/opentdf/otdfctl/pkg/man"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/obligations"
	"github.com/spf13/cobra"
)

//
// Obligations
//

var obligationValues []string

// TriggerRequest represents the JSON structure for a trigger
type TriggerRequest struct {
	Action         string                 `json:"action"`
	AttributeValue string                 `json:"attribute_value"`
	Context        *policy.RequestContext `json:"context,omitempty"`
}

func policyCreateObligation(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()
	name := c.Flags.GetRequiredString("name")
	obligationValues = c.Flags.GetStringSlice("value", obligationValues, cli.FlagsStringSliceOptions{})
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})
	namespace := c.Flags.GetRequiredString("namespace")
	obl, err := h.CreateObligation(cmd.Context(), namespace, name, obligationValues, getMetadataMutable(metadataLabels))
	if err != nil {
		cli.ExitWithError("Failed to create obligation", err)
	}

	simpleObligationValues := cli.GetSimpleObligationValues(obl.GetValues())

	rows := [][]string{
		{"Id", obl.GetId()},
		{"Name", obl.GetName()},
		{"Values", cli.CommaSeparated(simpleObligationValues)},
	}

	if mdRows := getMetadataRows(obl.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, obl.GetId(), t, obl)
}

func policyGetObligation(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetOptionalID("id")
	fqn := c.Flags.GetOptionalString("fqn")

	obl, err := h.GetObligation(cmd.Context(), id, fqn)
	if err != nil {
		identifier := fmt.Sprintf("id: %s", id)
		if id == "" {
			identifier = fmt.Sprintf("fqn: %s", fqn)
		}
		errMsg := fmt.Sprintf("Failed to find obligation (%s)", identifier)
		cli.ExitWithError(errMsg, err)
	}

	simpleObligationValues := cli.GetSimpleObligationValues(obl.GetValues())

	rows := [][]string{
		{"Id", obl.GetId()},
		{"Name", obl.GetName()},
		{"Values", cli.CommaSeparated(simpleObligationValues)},
	}
	if mdRows := getMetadataRows(obl.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, obl.GetId(), t, obl)
}

func policyListObligations(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	namespace := c.Flags.GetOptionalString("namespace")
	limit := c.Flags.GetRequiredInt32("limit")
	offset := c.Flags.GetRequiredInt32("offset")

	resp, err := h.ListObligations(cmd.Context(), limit, offset, namespace)
	if err != nil {
		cli.ExitWithError("Failed to list obligations", err)
	}

	t := cli.NewTable(
		cli.NewUUIDColumn(),
		table.NewFlexColumn("name", "Name", cli.FlexColumnWidthFour),
		table.NewFlexColumn("values", "Values", cli.FlexColumnWidthTwo),
	)
	rows := []table.Row{}
	for _, r := range resp.GetObligations() {
		simpleObligationValues := cli.GetSimpleObligationValues(r.GetValues())
		rows = append(rows, table.NewRow(table.RowData{
			"id":     r.GetId(),
			"name":   r.GetName(),
			"values": cli.CommaSeparated(simpleObligationValues),
		}))
	}
	t = t.WithRows(rows)
	t = cli.WithListPaginationFooter(t, resp.GetPagination())
	common.HandleSuccess(cmd, "", t, resp)
}

func policyUpdateObligation(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")
	name := c.Flags.GetOptionalString("name")
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	updated, err := h.UpdateObligation(
		cmd.Context(),
		id,
		name,
		getMetadataMutable(metadataLabels),
		getMetadataUpdateBehavior(),
	)
	if err != nil {
		cli.ExitWithError("Failed to update obligation", err)
	}

	rows := [][]string{
		{"Id", id},
		{"Name", updated.GetName()},
	}
	if mdRows := getMetadataRows(updated.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, id, t, updated)
}

func policyDeleteObligation(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetOptionalID("id")
	fqn := c.Flags.GetOptionalString("fqn")

	force := c.Flags.GetRequiredBool("force")
	ctx := cmd.Context()

	obl, err := h.GetObligation(ctx, id, fqn)
	identifier := id
	if id == "" {
		identifier = fqn
	}
	if err != nil {
		errMsg := fmt.Sprintf("Failed to find obligation (%s)", identifier)
		cli.ExitWithError(errMsg, err)
	}
	id = obl.GetId()
	cli.ConfirmAction(cli.ActionDelete, "obligation", identifier, force)

	err = h.DeleteObligation(ctx, id, fqn)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to delete obligation (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	rows := [][]string{
		{"Id", id},
		{"Name", obl.GetName()},
	}
	if mdRows := getMetadataRows(obl.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, id, t, obl)
}

//
// Obligation Values
//

func policyCreateObligationValue(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	ctx := cmd.Context()
	obligation := c.Flags.GetRequiredString("obligation")
	value := c.Flags.GetRequiredString("value")
	triggerJSON := c.Flags.GetOptionalString("triggers")
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	// Parse triggers if provided
	triggers, err := parseTriggers(triggerJSON)
	if err != nil {
		cli.ExitWithError("Invalid trigger configuration", err)
	}

	oblVal, err := h.CreateObligationValue(ctx, obligation, value, triggers, getMetadataMutable(metadataLabels))
	if err != nil {
		cli.ExitWithError("Failed to create obligation value", err)
	}

	rows := [][]string{
		{"Id", oblVal.GetId()},
		{"Name", oblVal.GetObligation().GetName()},
		{"Value", oblVal.GetValue()},
		{"Number of Triggers", strconv.Itoa(len(oblVal.GetTriggers()))},
	}
	if mdRows := getMetadataRows(oblVal.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, oblVal.GetId(), t, oblVal)
}

func policyGetObligationValue(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetOptionalID("id")
	fqn := c.Flags.GetOptionalString("fqn")

	value, err := h.GetObligationValue(cmd.Context(), id, fqn)
	if err != nil {
		identifier := fmt.Sprintf("id: %s", id)
		if id == "" {
			identifier = fmt.Sprintf("fqn: %s", fqn)
		}
		errMsg := fmt.Sprintf("Failed to find obligation value (%s)", identifier)
		cli.ExitWithError(errMsg, err)
	}

	rows := [][]string{
		{"Id", value.GetId()},
		{"Name", value.GetObligation().GetName()},
		{"Value", value.GetValue()},
		{"Number of Triggers", strconv.Itoa(len(value.GetTriggers()))},
	}
	if mdRows := getMetadataRows(value.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, value.GetId(), t, value)
}

func policyUpdateObligationValue(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")
	value := c.Flags.GetOptionalString("value")
	triggerJSON := c.Flags.GetOptionalString("triggers")
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	// Parse triggers if provided
	triggers, err := parseTriggers(triggerJSON)
	if err != nil {
		cli.ExitWithError("Invalid trigger configuration", err)
	}

	updated, err := h.UpdateObligationValue(
		cmd.Context(),
		id,
		value,
		triggers,
		getMetadataMutable(metadataLabels),
		getMetadataUpdateBehavior(),
	)
	if err != nil {
		cli.ExitWithError("Failed to update obligation value", err)
	}

	rows := [][]string{
		{"Id", id},
		{"Name", updated.GetObligation().GetName()},
		{"Value", updated.GetValue()},
		{"Number of Triggers", strconv.Itoa(len(updated.GetTriggers()))},
	}
	if mdRows := getMetadataRows(updated.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, id, t, updated)
}

func policyDeleteObligationValue(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetOptionalID("id")
	fqn := c.Flags.GetOptionalString("fqn")

	force := c.Flags.GetOptionalBool("force")
	ctx := cmd.Context()

	val, err := h.GetObligationValue(ctx, id, fqn)
	identifier := id
	if id == "" {
		identifier = fqn
	}
	if err != nil {
		errMsg := fmt.Sprintf("Failed to find obligation value (%s)", identifier)
		cli.ExitWithError(errMsg, err)
	}
	id = val.GetId()
	cli.ConfirmAction(cli.ActionDelete, "obligation value", identifier, force)

	err = h.DeleteObligationValue(ctx, id, fqn)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to delete obligation value (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	rows := [][]string{
		{"Id", id},
		{"Value", val.GetValue()},
	}
	if mdRows := getMetadataRows(val.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, id, t, val)
}

// ****
// Obligation Triggers
// ****
func policyCreateObligationTrigger(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	ctx := cmd.Context()
	attributeValue := c.Flags.GetRequiredString("attribute-value")
	action := c.Flags.GetRequiredString("action")
	obligationValue := c.Flags.GetRequiredString("obligation-value")
	clientID := c.Flags.GetOptionalString("client-id")
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	trigger, err := h.CreateObligationTrigger(ctx, attributeValue, action, obligationValue, clientID, getMetadataMutable(metadataLabels))
	if err != nil {
		cli.ExitWithError("Failed to create obligation trigger", err)
	}

	rows := getObligationTriggerRows(trigger)
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, trigger.GetId(), t, trigger)
}

func policyDeleteObligationTrigger(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredString("id")
	force := c.Flags.GetOptionalBool("force")
	ctx := cmd.Context()

	cli.ConfirmAction(cli.ActionDelete, "obligation trigger", id, force)

	resp, err := h.DeleteObligationTrigger(ctx, id)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to delete obligation trigger (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	rows := [][]string{
		{"Id", id},
	}
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, id, t, resp)
}

func policyListObligationTriggers(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	namespace := c.Flags.GetOptionalString("namespace")
	limit := c.Flags.GetRequiredInt32("limit")
	offset := c.Flags.GetRequiredInt32("offset")

	resp, err := h.ListObligationTriggers(cmd.Context(), namespace, limit, offset)
	if err != nil {
		cli.ExitWithError("Failed to list obligation triggers", err)
	}

	t := cli.NewTable(
		cli.NewUUIDColumn(),
		table.NewFlexColumn("attribute", "Attribute Value FQN", cli.FlexColumnWidthThree),
		table.NewFlexColumn("action", "Action", cli.FlexColumnWidthOne),
		table.NewFlexColumn("obligation", "Obligation Value FQN", cli.FlexColumnWidthThree),
		table.NewFlexColumn("client_ids", "Client IDs", cli.FlexColumnWidthOne),
	)
	rows := []table.Row{}
	for _, r := range resp.GetTriggers() {
		rows = append(rows, table.NewRow(table.RowData{
			"id":         r.GetId(),
			"attribute":  r.GetAttributeValue().GetFqn(),
			"action":     r.GetAction().GetName(),
			"obligation": r.GetObligationValue().GetFqn(),
			"client_ids": cli.CommaSeparated(cli.AggregateClientIDs(r.GetContext())),
		}))
	}
	t = t.WithRows(rows)
	t = cli.WithListPaginationFooter(t, resp.GetPagination())
	common.HandleSuccess(cmd, "", t, resp)
}

func getObligationTriggerRows(trigger *policy.ObligationTrigger) [][]string {
	rows := [][]string{
		{"Id", trigger.GetId()},
		{"Attribute Value FQN", trigger.GetAttributeValue().GetFqn()},
		{"Action", trigger.GetAction().GetName()},
		{"Obligation Value FQN", trigger.GetObligationValue().GetFqn()},
		{"Client IDs", cli.CommaSeparated(cli.AggregateClientIDs(trigger.GetContext()))},
	}
	if mdRows := getMetadataRows(trigger.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}
	return rows
}

// parseTriggers unmarshals the trigger JSON string or reads from file and validates required fields
func parseTriggers(triggerInput string) ([]*obligations.ValueTriggerRequest, error) {
	if triggerInput == "" {
		return nil, nil
	}

	// Determine if input is a file path or JSON string
	triggerJSON, err := cli.GetJSONInput(triggerInput)
	if err != nil {
		return nil, fmt.Errorf("failed to get JSON input: %w", err)
	}

	var triggerRequests []TriggerRequest
	if err := json.Unmarshal([]byte(triggerJSON), &triggerRequests); err != nil {
		return nil, fmt.Errorf("failed to parse trigger JSON: %w", err)
	}

	var valueTriggerRequests []*obligations.ValueTriggerRequest
	for i, tr := range triggerRequests {
		// Validate required fields
		if strings.TrimSpace(tr.Action) == "" {
			return nil, fmt.Errorf("trigger at index %d: action is required", i)
		}
		if strings.TrimSpace(tr.AttributeValue) == "" {
			return nil, fmt.Errorf("trigger at index %d: attribute_value is required", i)
		}

		// Create the ValueTriggerRequest
		valueTrigger := &obligations.ValueTriggerRequest{
			Action:         handlers.ParseToIDNameIdentifier(tr.Action),
			AttributeValue: handlers.ParseToIDFqnIdentifier(tr.AttributeValue),
		}

		// Add context if client_id is provided
		if tr.Context != nil {
			valueTrigger.Context = tr.Context
		}

		valueTriggerRequests = append(valueTriggerRequests, valueTrigger)
	}

	return valueTriggerRequests, nil
}

func initObligationsCommands() {
	// Obligations commands
	getDoc := man.Docs.GetCommand("policy/obligations/get",
		man.WithRun(policyGetObligation),
	)
	getDoc.Flags().StringP(
		getDoc.GetDocFlag("id").Name,
		getDoc.GetDocFlag("id").Shorthand,
		getDoc.GetDocFlag("id").Default,
		getDoc.GetDocFlag("id").Description,
	)
	getDoc.Flags().StringP(
		getDoc.GetDocFlag("fqn").Name,
		getDoc.GetDocFlag("fqn").Shorthand,
		getDoc.GetDocFlag("fqn").Default,
		getDoc.GetDocFlag("fqn").Description,
	)
	getDoc.MarkFlagsMutuallyExclusive("id", "fqn")
	getDoc.MarkFlagsOneRequired("id", "fqn")

	listDoc := man.Docs.GetCommand("policy/obligations/list",
		man.WithRun(policyListObligations),
	)
	listDoc.Flags().StringP(
		listDoc.GetDocFlag("namespace").Name,
		listDoc.GetDocFlag("namespace").Shorthand,
		listDoc.GetDocFlag("namespace").Default,
		listDoc.GetDocFlag("namespace").Description,
	)
	injectListPaginationFlags(listDoc)

	createDoc := man.Docs.GetCommand("policy/obligations/create",
		man.WithRun(policyCreateObligation),
	)
	createDoc.Flags().StringP(
		createDoc.GetDocFlag("name").Name,
		createDoc.GetDocFlag("name").Shorthand,
		createDoc.GetDocFlag("name").Default,
		createDoc.GetDocFlag("name").Description,
	)
	createDoc.Flags().StringP(
		createDoc.GetDocFlag("namespace").Name,
		createDoc.GetDocFlag("namespace").Shorthand,
		createDoc.GetDocFlag("namespace").Default,
		createDoc.GetDocFlag("namespace").Description,
	)
	createDoc.Flags().StringSliceVarP(
		&obligationValues,
		createDoc.GetDocFlag("value").Name,
		createDoc.GetDocFlag("value").Shorthand,
		[]string{},
		createDoc.GetDocFlag("value").Description,
	)
	injectLabelFlags(&createDoc.Command, false)

	updateDoc := man.Docs.GetCommand("policy/obligations/update",
		man.WithRun(policyUpdateObligation),
	)
	updateDoc.Flags().StringP(
		updateDoc.GetDocFlag("id").Name,
		updateDoc.GetDocFlag("id").Shorthand,
		updateDoc.GetDocFlag("id").Default,
		updateDoc.GetDocFlag("id").Description,
	)
	updateDoc.Flags().StringP(
		updateDoc.GetDocFlag("name").Name,
		updateDoc.GetDocFlag("name").Shorthand,
		updateDoc.GetDocFlag("name").Default,
		updateDoc.GetDocFlag("name").Description,
	)
	injectLabelFlags(&updateDoc.Command, true)

	deleteDoc := man.Docs.GetCommand("policy/obligations/delete",
		man.WithRun(policyDeleteObligation),
	)
	deleteDoc.Flags().StringP(
		deleteDoc.GetDocFlag("id").Name,
		deleteDoc.GetDocFlag("id").Shorthand,
		deleteDoc.GetDocFlag("id").Default,
		deleteDoc.GetDocFlag("id").Description,
	)
	deleteDoc.Flags().StringP(
		deleteDoc.GetDocFlag("fqn").Name,
		deleteDoc.GetDocFlag("fqn").Shorthand,
		deleteDoc.GetDocFlag("fqn").Default,
		deleteDoc.GetDocFlag("fqn").Description,
	)
	deleteDoc.Flags().Bool(
		deleteDoc.GetDocFlag("force").Name,
		false,
		deleteDoc.GetDocFlag("force").Description,
	)
	deleteDoc.MarkFlagsMutuallyExclusive("id", "fqn")
	deleteDoc.MarkFlagsOneRequired("id", "fqn")

	// Obligation Values commands

	getValueDoc := man.Docs.GetCommand("policy/obligations/values/get",
		man.WithRun(policyGetObligationValue),
	)
	getValueDoc.Flags().StringP(
		getValueDoc.GetDocFlag("id").Name,
		getValueDoc.GetDocFlag("id").Shorthand,
		getValueDoc.GetDocFlag("id").Default,
		getValueDoc.GetDocFlag("id").Description,
	)
	getValueDoc.Flags().StringP(
		getValueDoc.GetDocFlag("fqn").Name,
		getValueDoc.GetDocFlag("fqn").Shorthand,
		getValueDoc.GetDocFlag("fqn").Default,
		getValueDoc.GetDocFlag("fqn").Description,
	)
	getValueDoc.MarkFlagsMutuallyExclusive("id", "fqn")
	getValueDoc.MarkFlagsOneRequired("id", "fqn")

	createValueDoc := man.Docs.GetCommand("policy/obligations/values/create",
		man.WithRun(policyCreateObligationValue),
	)
	createValueDoc.Flags().StringP(
		createValueDoc.GetDocFlag("obligation").Name,
		createValueDoc.GetDocFlag("obligation").Shorthand,
		createValueDoc.GetDocFlag("obligation").Default,
		createValueDoc.GetDocFlag("obligation").Description,
	)
	createValueDoc.Flags().StringP(
		createValueDoc.GetDocFlag("value").Name,
		createValueDoc.GetDocFlag("value").Shorthand,
		createValueDoc.GetDocFlag("value").Default,
		createValueDoc.GetDocFlag("value").Description,
	)
	createValueDoc.Flags().StringP(
		createValueDoc.GetDocFlag("triggers").Name,
		createValueDoc.GetDocFlag("triggers").Shorthand,
		createValueDoc.GetDocFlag("triggers").Default,
		createValueDoc.GetDocFlag("triggers").Description,
	)
	injectLabelFlags(&createValueDoc.Command, false)

	updateValueDoc := man.Docs.GetCommand("policy/obligations/values/update",
		man.WithRun(policyUpdateObligationValue),
	)
	updateValueDoc.Flags().StringP(
		updateDoc.GetDocFlag("id").Name,
		updateDoc.GetDocFlag("id").Shorthand,
		updateDoc.GetDocFlag("id").Default,
		updateDoc.GetDocFlag("id").Description,
	)
	updateValueDoc.Flags().StringP(
		updateValueDoc.GetDocFlag("value").Name,
		updateValueDoc.GetDocFlag("value").Shorthand,
		updateValueDoc.GetDocFlag("value").Default,
		updateValueDoc.GetDocFlag("value").Description,
	)
	updateValueDoc.Flags().StringP(
		updateValueDoc.GetDocFlag("triggers").Name,
		updateValueDoc.GetDocFlag("triggers").Shorthand,
		updateValueDoc.GetDocFlag("triggers").Default,
		updateValueDoc.GetDocFlag("triggers").Description,
	)
	injectLabelFlags(&updateValueDoc.Command, true)
	deleteValueDoc := man.Docs.GetCommand("policy/obligations/values/delete",
		man.WithRun(policyDeleteObligationValue),
	)
	deleteValueDoc.Flags().StringP(
		deleteValueDoc.GetDocFlag("id").Name,
		deleteValueDoc.GetDocFlag("id").Shorthand,
		deleteValueDoc.GetDocFlag("id").Default,
		deleteValueDoc.GetDocFlag("id").Description,
	)
	deleteValueDoc.Flags().StringP(
		deleteValueDoc.GetDocFlag("fqn").Name,
		deleteValueDoc.GetDocFlag("fqn").Shorthand,
		deleteValueDoc.GetDocFlag("fqn").Default,
		deleteValueDoc.GetDocFlag("fqn").Description,
	)
	deleteValueDoc.Flags().Bool(
		deleteValueDoc.GetDocFlag("force").Name,
		false,
		deleteValueDoc.GetDocFlag("force").Description,
	)
	deleteValueDoc.MarkFlagsMutuallyExclusive("id", "fqn")
	deleteValueDoc.MarkFlagsOneRequired("id", "fqn")

	// Obligation Triggers commands
	createTriggerDoc := man.Docs.GetCommand("policy/obligations/triggers/create",
		man.WithRun(policyCreateObligationTrigger),
	)
	createTriggerDoc.Flags().StringP(
		createTriggerDoc.GetDocFlag("attribute-value").Name,
		createTriggerDoc.GetDocFlag("attribute-value").Shorthand,
		createTriggerDoc.GetDocFlag("attribute-value").Default,
		createTriggerDoc.GetDocFlag("attribute-value").Description,
	)
	createTriggerDoc.Flags().StringP(
		createTriggerDoc.GetDocFlag("action").Name,
		createTriggerDoc.GetDocFlag("action").Shorthand,
		createTriggerDoc.GetDocFlag("action").Default,
		createTriggerDoc.GetDocFlag("action").Description,
	)
	createTriggerDoc.Flags().StringP(
		createTriggerDoc.GetDocFlag("obligation-value").Name,
		createTriggerDoc.GetDocFlag("obligation-value").Shorthand,
		createTriggerDoc.GetDocFlag("obligation-value").Default,
		createTriggerDoc.GetDocFlag("obligation-value").Description,
	)
	createTriggerDoc.Flags().StringP(
		createTriggerDoc.GetDocFlag("client-id").Name,
		createTriggerDoc.GetDocFlag("client-id").Shorthand,
		createTriggerDoc.GetDocFlag("client-id").Default,
		createTriggerDoc.GetDocFlag("client-id").Description,
	)
	injectLabelFlags(&createTriggerDoc.Command, false)

	deleteTriggerDoc := man.Docs.GetCommand("policy/obligations/triggers/delete",
		man.WithRun(policyDeleteObligationTrigger),
	)
	deleteTriggerDoc.Flags().StringP(
		deleteTriggerDoc.GetDocFlag("id").Name,
		deleteTriggerDoc.GetDocFlag("id").Shorthand,
		deleteTriggerDoc.GetDocFlag("id").Default,
		deleteTriggerDoc.GetDocFlag("id").Description,
	)
	deleteTriggerDoc.Flags().Bool(
		deleteTriggerDoc.GetDocFlag("force").Name,
		false,
		deleteTriggerDoc.GetDocFlag("force").Description,
	)

	listTriggerDoc := man.Docs.GetCommand("policy/obligations/triggers/list",
		man.WithRun(policyListObligationTriggers),
	)
	listTriggerDoc.Flags().StringP(
		listTriggerDoc.GetDocFlag("namespace").Name,
		listTriggerDoc.GetDocFlag("namespace").Shorthand,
		listTriggerDoc.GetDocFlag("namespace").Default,
		listTriggerDoc.GetDocFlag("namespace").Description,
	)
	injectListPaginationFlags(listTriggerDoc)

	// Add commands to the policy command

	policyObligationsDoc := man.Docs.GetCommand("policy/obligations",
		man.WithSubcommands(
			getDoc,
			listDoc,
			createDoc,
			updateDoc,
			deleteDoc,
		),
	)

	policyObligationValuesDoc := man.Docs.GetCommand("policy/obligations/values",
		man.WithSubcommands(
			getValueDoc,
			createValueDoc,
			updateValueDoc,
			deleteValueDoc,
		),
	)

	policyObligationTriggersDoc := man.Docs.GetCommand("policy/obligations/triggers",
		man.WithSubcommands(
			createTriggerDoc,
			deleteTriggerDoc,
			listTriggerDoc,
		),
	)

	policyObligationsDoc.AddCommand(&policyObligationValuesDoc.Command)
	policyObligationsDoc.AddCommand(&policyObligationTriggersDoc.Command)
	Cmd.AddCommand(&policyObligationsDoc.Command)
}
