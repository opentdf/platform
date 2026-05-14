package policy

import (
	"fmt"
	"strings"

	"github.com/evertras/bubble-table/table"
	"github.com/google/uuid"
	"github.com/opentdf/platform/otdfctl/cmd/common"
	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/man"
	"github.com/opentdf/platform/protocol/go/policy/registeredresources"
	"github.com/spf13/cobra"
)

var (
	registeredResourceValues []string
	actionAttributeValues    []string
)

const actionAttributeValueArgSplitCount = 2

//
// Registered Resources
//

func policyCreateRegisteredResource(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	name := c.Flags.GetRequiredString("name")
	namespace := c.Flags.GetOptionalString("namespace")
	registeredResourceValues = c.Flags.GetStringSlice("value", registeredResourceValues, cli.FlagsStringSliceOptions{})
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	resource, err := h.CreateRegisteredResource(cmd.Context(), namespace, name, registeredResourceValues, getMetadataMutable(metadataLabels))
	if err != nil {
		cli.ExitWithError("Failed to create registered resource", err)
	}

	simpleRegResValues := cli.GetSimpleRegisteredResourceValues(resource.GetValues())

	rows := [][]string{
		{"Id", resource.GetId()},
		{"Name", resource.GetName()},
		{"Namespace", resource.GetNamespace().GetFqn()},
		{"Values", cli.CommaSeparated(simpleRegResValues)},
	}

	if mdRows := getMetadataRows(resource.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, resource.GetId(), t, resource)
}

func policyGetRegisteredResource(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetOptionalID("id")
	name := c.Flags.GetOptionalString("name")
	namespace := c.Flags.GetOptionalString("namespace")

	if id == "" && name == "" {
		cli.ExitWithError("Either 'id' or 'name' must be provided", nil)
	}

	resource, err := h.GetRegisteredResource(cmd.Context(), id, name, namespace)
	if err != nil {
		identifier := "id: " + id
		if id == "" {
			identifier = "name: " + name
		}
		errMsg := "Failed to find registered resource (" + identifier + ")"
		cli.ExitWithError(errMsg, err)
	}

	simpleRegResValues := cli.GetSimpleRegisteredResourceValues(resource.GetValues())

	rows := [][]string{
		{"Id", resource.GetId()},
		{"Name", resource.GetName()},
		{"Namespace", resource.GetNamespace().GetFqn()},
		{"Values", cli.CommaSeparated(simpleRegResValues)},
	}
	if mdRows := getMetadataRows(resource.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, resource.GetId(), t, resource)
}

func policyListRegisteredResources(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	namespace := c.Flags.GetOptionalString("namespace")
	limit := c.Flags.GetRequiredInt32("limit")
	offset := c.Flags.GetRequiredInt32("offset")
	sort := getSortOption(c)

	resp, err := h.ListRegisteredResources(cmd.Context(), limit, offset, namespace, sort)
	if err != nil {
		cli.ExitWithError("Failed to list registered resources", err)
	}

	t := cli.NewTable(
		cli.NewUUIDColumn(),
		table.NewFlexColumn("name", "Name", cli.FlexColumnWidthFour),
		table.NewFlexColumn("namespace", "Namespace", cli.FlexColumnWidthFour),
		table.NewFlexColumn("values", "Values", cli.FlexColumnWidthTwo),
	)
	rows := []table.Row{}
	for _, r := range resp.GetResources() {
		simpleRegResValues := cli.GetSimpleRegisteredResourceValues(r.GetValues())
		rows = append(rows, table.NewRow(table.RowData{
			"id":        r.GetId(),
			"name":      r.GetName(),
			"namespace": r.GetNamespace().GetFqn(),
			"values":    cli.CommaSeparated(simpleRegResValues),
		}))
	}
	t = t.WithRows(rows)
	t = cli.WithListPaginationFooter(t, resp.GetPagination())
	common.HandleSuccess(cmd, "", t, resp)
}

func policyUpdateRegisteredResource(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")
	name := c.Flags.GetOptionalString("name")
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	updated, err := h.UpdateRegisteredResource(
		cmd.Context(),
		id,
		name,
		getMetadataMutable(metadataLabels),
		getMetadataUpdateBehavior(),
	)
	if err != nil {
		cli.ExitWithError("Failed to update registered resource", err)
	}

	rows := [][]string{
		{"Id", id},
		{"Name", updated.GetName()},
		{"Namespace", updated.GetNamespace().GetFqn()},
	}
	if mdRows := getMetadataRows(updated.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, id, t, updated)
}

func policyDeleteRegisteredResource(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")
	force := c.Flags.GetRequiredBool("force")
	ctx := cmd.Context()

	resource, err := h.GetRegisteredResource(ctx, id, "", "")
	if err != nil {
		errMsg := fmt.Sprintf("Failed to find registered resource (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	cli.ConfirmAction(cli.ActionDelete, "registered resource", id, force)

	err = h.DeleteRegisteredResource(ctx, id)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to delete registered resource (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	rows := [][]string{
		{"Id", id},
		{"Name", resource.GetName()},
		{"Namespace", resource.GetNamespace().GetFqn()},
	}
	if mdRows := getMetadataRows(resource.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, id, t, resource)
}

//
// Registered Resource Values
//

func policyCreateRegisteredResourceValue(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	ctx := cmd.Context()
	resource := c.Flags.GetRequiredString("resource")
	value := c.Flags.GetRequiredString("value")
	actionAttributeValues = c.Flags.GetStringSlice("action-attribute-value", actionAttributeValues, cli.FlagsStringSliceOptions{Min: 0})
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	namespace := c.Flags.GetOptionalString("namespace")

	var resourceID string
	if uuid.Validate(resource) == nil {
		resourceID = resource
	} else {
		resourceByName, err := h.GetRegisteredResource(ctx, "", resource, namespace)
		if err != nil {
			cli.ExitWithError(fmt.Sprintf("Failed to find registered resource (name: %s)", resource), err)
		}
		resourceID = resourceByName.GetId()
	}

	parsedActionAttributeValues := parseActionAttributeValueArgs(actionAttributeValues)

	resourceValue, err := h.CreateRegisteredResourceValue(ctx, resourceID, value, parsedActionAttributeValues, getMetadataMutable(metadataLabels))
	if err != nil {
		cli.ExitWithError("Failed to create registered resource value", err)
	}

	simpleActionAttributeValues := cli.GetSimpleRegisteredResourceActionAttributeValues(resourceValue.GetActionAttributeValues())

	rows := [][]string{
		{"Id", resourceValue.GetId()},
		{"Value", resourceValue.GetValue()},
		{"Action Attribute Values", cli.CommaSeparated(simpleActionAttributeValues)},
	}
	if mdRows := getMetadataRows(resourceValue.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, resourceValue.GetId(), t, resourceValue)
}

func policyGetRegisteredResourceValue(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetOptionalID("id")
	fqn := c.Flags.GetOptionalString("fqn")

	if id == "" && fqn == "" {
		cli.ExitWithError("Either 'id' or 'fqn' must be provided", nil)
	}

	value, err := h.GetRegisteredResourceValue(cmd.Context(), id, fqn)
	if err != nil {
		identifier := "id: " + id
		if id == "" {
			identifier = "fqn: " + fqn
		}
		errMsg := "Failed to find registered resource value (" + identifier + ")"
		cli.ExitWithError(errMsg, err)
	}

	simpleActionAttributeValues := cli.GetSimpleRegisteredResourceActionAttributeValues(value.GetActionAttributeValues())

	rows := [][]string{
		{"Id", value.GetId()},
		{"Value", value.GetValue()},
		{"Action Attribute Values", cli.CommaSeparated(simpleActionAttributeValues)},
	}
	if mdRows := getMetadataRows(value.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, value.GetId(), t, value)
}

func policyListRegisteredResourceValues(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	ctx := cmd.Context()
	resource := c.Flags.GetRequiredString("resource")
	namespace := c.Flags.GetOptionalString("namespace")
	limit := c.Flags.GetRequiredInt32("limit")
	offset := c.Flags.GetRequiredInt32("offset")

	var resourceID string
	if uuid.Validate(resource) == nil {
		resourceID = resource
	} else {
		resourceByName, err := h.GetRegisteredResource(ctx, "", resource, namespace)
		if err != nil {
			cli.ExitWithError(fmt.Sprintf("Failed to find registered resource (name: %s)", resource), err)
		}
		resourceID = resourceByName.GetId()
	}

	resp, err := h.ListRegisteredResourceValues(ctx, resourceID, limit, offset)
	if err != nil {
		cli.ExitWithError("Failed to list registered resource values", err)
	}

	t := cli.NewTable(
		cli.NewUUIDColumn(),
		table.NewFlexColumn("value", "Value", cli.FlexColumnWidthFour),
		table.NewFlexColumn("action-attribute-values", "Action Attribute Values", cli.FlexColumnWidthFour),
	)
	rows := []table.Row{}
	for _, v := range resp.GetValues() {
		simpleActionAttributeValues := cli.GetSimpleRegisteredResourceActionAttributeValues(v.GetActionAttributeValues())

		rows = append(rows, table.NewRow(table.RowData{
			"id":                      v.GetId(),
			"value":                   v.GetValue(),
			"action-attribute-values": cli.CommaSeparated(simpleActionAttributeValues),
		}))
	}

	t = t.WithRows(rows)
	t = cli.WithListPaginationFooter(t, resp.GetPagination())
	common.HandleSuccess(cmd, "", t, resp)
}

func policyUpdateRegisteredResourceValue(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")
	value := c.Flags.GetOptionalString("value")
	actionAttributeValues = c.Flags.GetStringSlice("action-attribute-value", actionAttributeValues, cli.FlagsStringSliceOptions{Min: 0})
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})
	force := c.Flags.GetOptionalBool("force")

	parsedActionAttributeValues := parseActionAttributeValueArgs(actionAttributeValues)

	// only confirm if new action attribute values provided
	if len(parsedActionAttributeValues) > 0 {
		cli.ConfirmActionSubtext(cli.ActionUpdate, "registered resource value", id,
			"All existing action attribute values will be replaced with the new ones provided.",
			force)
	}

	updated, err := h.UpdateRegisteredResourceValue(
		cmd.Context(),
		id,
		value,
		parsedActionAttributeValues,
		getMetadataMutable(metadataLabels),
		getMetadataUpdateBehavior(),
	)
	if err != nil {
		cli.ExitWithError("Failed to update registered resource value", err)
	}

	simpleActionAttributeValues := cli.GetSimpleRegisteredResourceActionAttributeValues(updated.GetActionAttributeValues())

	rows := [][]string{
		{"Id", id},
		{"Value", updated.GetValue()},
		{"Action Attribute Values", cli.CommaSeparated(simpleActionAttributeValues)},
	}
	if mdRows := getMetadataRows(updated.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, id, t, updated)
}

func policyDeleteRegisteredResourceValue(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")
	force := c.Flags.GetOptionalBool("force")
	ctx := cmd.Context()

	resource, err := h.GetRegisteredResourceValue(ctx, id, "")
	if err != nil {
		errMsg := fmt.Sprintf("Failed to find registered resource value (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	cli.ConfirmAction(cli.ActionDelete, "registered resource value", id, force)

	err = h.DeleteRegisteredResourceValue(ctx, id)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to delete registered resource value (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	rows := [][]string{
		{"Id", id},
		{"Value", resource.GetValue()},
	}
	if mdRows := getMetadataRows(resource.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, id, t, resource)
}

func parseActionAttributeValueArgs(args []string) []*registeredresources.ActionAttributeValue {
	parsed := make([]*registeredresources.ActionAttributeValue, len(args))

	for i, a := range args {
		// split on semicolon
		split := strings.Split(a, ";")
		if len(split) != actionAttributeValueArgSplitCount {
			cli.ExitWithError("Invalid action attribute value arg format", nil)
		}

		actionIdentifier := split[0]
		attrValIdentifier := split[1]

		newActionAttrVal := &registeredresources.ActionAttributeValue{}

		if uuid.Validate(actionIdentifier) == nil {
			newActionAttrVal.ActionIdentifier = &registeredresources.ActionAttributeValue_ActionId{
				ActionId: actionIdentifier,
			}
		} else {
			newActionAttrVal.ActionIdentifier = &registeredresources.ActionAttributeValue_ActionName{
				ActionName: actionIdentifier,
			}
		}

		if uuid.Validate(attrValIdentifier) == nil {
			newActionAttrVal.AttributeValueIdentifier = &registeredresources.ActionAttributeValue_AttributeValueId{
				AttributeValueId: attrValIdentifier,
			}
		} else {
			newActionAttrVal.AttributeValueIdentifier = &registeredresources.ActionAttributeValue_AttributeValueFqn{
				AttributeValueFqn: attrValIdentifier,
			}
		}

		parsed[i] = newActionAttrVal
	}

	return parsed
}

func initRegisteredResourcesCommands() {
	// Registered Resources commands

	getDoc := man.Docs.GetCommand("policy/registered-resources/get",
		man.WithRun(policyGetRegisteredResource),
	)
	getDoc.Flags().StringP(
		getDoc.GetDocFlag("id").Name,
		getDoc.GetDocFlag("id").Shorthand,
		getDoc.GetDocFlag("id").Default,
		getDoc.GetDocFlag("id").Description,
	)
	getDoc.Flags().StringP(
		getDoc.GetDocFlag("name").Name,
		getDoc.GetDocFlag("name").Shorthand,
		getDoc.GetDocFlag("name").Default,
		getDoc.GetDocFlag("name").Description,
	)
	getDoc.Flags().StringP(
		getDoc.GetDocFlag("namespace").Name,
		getDoc.GetDocFlag("namespace").Shorthand,
		getDoc.GetDocFlag("namespace").Default,
		getDoc.GetDocFlag("namespace").Description,
	)

	listDoc := man.Docs.GetCommand("policy/registered-resources/list",
		man.WithRun(policyListRegisteredResources),
	)
	listDoc.Flags().StringP(
		listDoc.GetDocFlag("namespace").Name,
		listDoc.GetDocFlag("namespace").Shorthand,
		listDoc.GetDocFlag("namespace").Default,
		listDoc.GetDocFlag("namespace").Description,
	)
	injectListPaginationFlags(listDoc)
	injectListSortFlag(listDoc)

	createDoc := man.Docs.GetCommand("policy/registered-resources/create",
		man.WithRun(policyCreateRegisteredResource),
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
		&registeredResourceValues,
		createDoc.GetDocFlag("value").Name,
		createDoc.GetDocFlag("value").Shorthand,
		[]string{},
		createDoc.GetDocFlag("value").Description,
	)
	injectLabelFlags(&createDoc.Command, false)

	updateDoc := man.Docs.GetCommand("policy/registered-resources/update",
		man.WithRun(policyUpdateRegisteredResource),
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

	deleteDoc := man.Docs.GetCommand("policy/registered-resources/delete",
		man.WithRun(policyDeleteRegisteredResource),
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

	// Registered Resource Values commands

	getValueDoc := man.Docs.GetCommand("policy/registered-resources/values/get",
		man.WithRun(policyGetRegisteredResourceValue),
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

	listValuesDoc := man.Docs.GetCommand("policy/registered-resources/values/list",
		man.WithRun(policyListRegisteredResourceValues),
	)
	listValuesDoc.Flags().StringP(
		listValuesDoc.GetDocFlag("resource").Name,
		listValuesDoc.GetDocFlag("resource").Shorthand,
		listValuesDoc.GetDocFlag("resource").Default,
		listValuesDoc.GetDocFlag("resource").Description,
	)
	listValuesDoc.Flags().StringP(
		listValuesDoc.GetDocFlag("namespace").Name,
		listValuesDoc.GetDocFlag("namespace").Shorthand,
		listValuesDoc.GetDocFlag("namespace").Default,
		listValuesDoc.GetDocFlag("namespace").Description,
	)
	injectListPaginationFlags(listValuesDoc)

	createValueDoc := man.Docs.GetCommand("policy/registered-resources/values/create",
		man.WithRun(policyCreateRegisteredResourceValue),
	)
	createValueDoc.Flags().StringP(
		createValueDoc.GetDocFlag("resource").Name,
		createValueDoc.GetDocFlag("resource").Shorthand,
		createValueDoc.GetDocFlag("resource").Default,
		createValueDoc.GetDocFlag("resource").Description,
	)
	createValueDoc.Flags().StringP(
		createValueDoc.GetDocFlag("value").Name,
		createValueDoc.GetDocFlag("value").Shorthand,
		createValueDoc.GetDocFlag("value").Default,
		createValueDoc.GetDocFlag("value").Description,
	)
	createValueDoc.Flags().StringP(
		createValueDoc.GetDocFlag("namespace").Name,
		createValueDoc.GetDocFlag("namespace").Shorthand,
		createValueDoc.GetDocFlag("namespace").Default,
		createValueDoc.GetDocFlag("namespace").Description,
	)
	createValueDoc.Flags().StringSliceVarP(
		&actionAttributeValues,
		createValueDoc.GetDocFlag("action-attribute-value").Name,
		createValueDoc.GetDocFlag("action-attribute-value").Shorthand,
		[]string{},
		createValueDoc.GetDocFlag("action-attribute-value").Description,
	)
	injectLabelFlags(&createValueDoc.Command, false)

	updateValueDoc := man.Docs.GetCommand("policy/registered-resources/values/update",
		man.WithRun(policyUpdateRegisteredResourceValue),
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
	updateValueDoc.Flags().StringSliceVarP(
		&actionAttributeValues,
		updateValueDoc.GetDocFlag("action-attribute-value").Name,
		updateValueDoc.GetDocFlag("action-attribute-value").Shorthand,
		[]string{},
		updateValueDoc.GetDocFlag("action-attribute-value").Description,
	)
	injectLabelFlags(&updateValueDoc.Command, true)
	updateValueDoc.Flags().Bool(
		updateValueDoc.GetDocFlag("force").Name,
		false,
		updateValueDoc.GetDocFlag("force").Description,
	)

	deleteValueDoc := man.Docs.GetCommand("policy/registered-resources/values/delete",
		man.WithRun(policyDeleteRegisteredResourceValue),
	)
	deleteValueDoc.Flags().StringP(
		deleteValueDoc.GetDocFlag("id").Name,
		deleteValueDoc.GetDocFlag("id").Shorthand,
		deleteValueDoc.GetDocFlag("id").Default,
		deleteValueDoc.GetDocFlag("id").Description,
	)
	deleteValueDoc.Flags().Bool(
		deleteValueDoc.GetDocFlag("force").Name,
		false,
		deleteValueDoc.GetDocFlag("force").Description,
	)

	// Add commands to the policy command

	policyRegisteredResourcesDoc := man.Docs.GetCommand("policy/registered-resources",
		man.WithSubcommands(
			getDoc,
			listDoc,
			createDoc,
			updateDoc,
			deleteDoc,
		),
	)

	policyRegisteredResourceValuesDoc := man.Docs.GetCommand("policy/registered-resources/values",
		man.WithSubcommands(
			getValueDoc,
			listValuesDoc,
			createValueDoc,
			updateValueDoc,
			deleteValueDoc,
		),
	)

	policyRegisteredResourcesDoc.AddCommand(&policyRegisteredResourceValuesDoc.Command)
	Cmd.AddCommand(&policyRegisteredResourcesDoc.Command)
}
