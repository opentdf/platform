package policy

import (
	"fmt"
	"math"

	"github.com/evertras/bubble-table/table"
	"github.com/opentdf/platform/otdfctl/cmd/common"
	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/man"
	policycommon "github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/spf13/cobra"
)

var AttributeValuesCmd *cobra.Command

func createAttributeValue(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	ctx := cmd.Context()
	attrID := c.FlagHelper.GetRequiredID("attribute-id")
	value := c.FlagHelper.GetRequiredString("value")
	metadataLabels = c.FlagHelper.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	attr, err := h.GetAttribute(ctx, attrID)
	if err != nil {
		cli.ExitWithError(fmt.Sprintf("Failed to get parent attribute (%s)", attrID), err)
	}

	v, err := h.CreateAttributeValue(ctx, attr.GetId(), value, getMetadataMutable(metadataLabels))
	if err != nil {
		cli.ExitWithError("Failed to create attribute value", err)
	}

	handleValueSuccess(cmd, v)
}

func getAttributeValue(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.FlagHelper.GetRequiredID("id")

	v, err := h.GetAttributeValue(cmd.Context(), id)
	if err != nil {
		cli.ExitWithError("Failed to find attribute value", err)
	}

	handleValueSuccess(cmd, v)
}

func filterValuesByState(values []*policy.Value, state policycommon.ActiveStateEnum) []*policy.Value {
	var shouldBeActive bool
	switch state {
	case policycommon.ActiveStateEnum_ACTIVE_STATE_ENUM_ACTIVE:
		shouldBeActive = true
	case policycommon.ActiveStateEnum_ACTIVE_STATE_ENUM_INACTIVE:
		shouldBeActive = false
	case policycommon.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
		policycommon.ActiveStateEnum_ACTIVE_STATE_ENUM_UNSPECIFIED:
		return values
	}

	filtered := make([]*policy.Value, 0, len(values))
	for _, v := range values {
		if v.GetActive().GetValue() == shouldBeActive {
			filtered = append(filtered, v)
		}
	}
	return filtered
}

func paginateValues(values []*policy.Value, limit, offset int32) ([]*policy.Value, *policy.PageResponse) {
	total := len(values)
	pagination := &policy.PageResponse{
		Total:         int32(min(total, math.MaxInt32)),
		CurrentOffset: offset,
	}

	off := int(offset)
	if off < 0 {
		return nil, pagination
	}
	if off >= total {
		return nil, pagination
	}
	values = values[off:]

	lim := int(limit)
	if lim > 0 && lim < len(values) {
		values = values[:lim]
		pagination.NextOffset = offset + limit
	}

	return values, pagination
}

func listAttributeValue(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	attrID := c.FlagHelper.GetRequiredID("attribute-id")
	state := cli.GetState(cmd)
	limit := c.Flags.GetRequiredInt32("limit")
	offset := c.Flags.GetRequiredInt32("offset")

	values, err := h.ListAttributeValues(cmd.Context(), attrID)
	if err != nil {
		cli.ExitWithError("Failed to list attribute values", err)
	}

	filtered := filterValuesByState(values, state)
	paged, pagination := paginateValues(filtered, limit, offset)

	t := cli.NewTable(
		cli.NewUUIDColumn(),
		table.NewFlexColumn("fqn", "Fqn", cli.FlexColumnWidthFour),
		table.NewFlexColumn("active", "Active", cli.FlexColumnWidthThree),
		table.NewFlexColumn("labels", "Labels", cli.FlexColumnWidthOne),
		table.NewFlexColumn("created_at", "Created At", cli.FlexColumnWidthOne),
		table.NewFlexColumn("updated_at", "Updated At", cli.FlexColumnWidthOne),
	)
	rows := []table.Row{}
	for _, val := range paged {
		v := cli.GetSimpleAttributeValue(val)
		rows = append(rows, table.NewRow(table.RowData{
			"id":         v.ID,
			"fqn":        v.FQN,
			"active":     v.Active,
			"labels":     v.Metadata["Labels"],
			"created_at": v.Metadata["Created At"],
			"updated_at": v.Metadata["Updated At"],
		}))
	}
	t = t.WithRows(rows)
	t = cli.WithListPaginationFooter(t, pagination)

	resp := &attributes.ListAttributeValuesResponse{
		Values:     paged,
		Pagination: pagination,
	}
	common.HandleSuccess(cmd, "", t, resp)
}

func updateAttributeValue(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	ctx := cmd.Context()
	id := c.Flags.GetRequiredID("id")
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	_, err := h.GetAttributeValue(ctx, id)
	if err != nil {
		cli.ExitWithError(fmt.Sprintf("Failed to get attribute value (%s)", id), err)
	}

	v, err := h.UpdateAttributeValue(ctx, id, getMetadataMutable(metadataLabels), getMetadataUpdateBehavior())
	if err != nil {
		cli.ExitWithError("Failed to update attribute value", err)
	}

	handleValueSuccess(cmd, v)
}

func deactivateAttributeValue(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	ctx := cmd.Context()
	id := c.Flags.GetRequiredID("id")
	force := c.Flags.GetOptionalBool("force")

	value, err := h.GetAttributeValue(ctx, id)
	if err != nil {
		cli.ExitWithError(fmt.Sprintf("Failed to get attribute value (%s)", id), err)
	}

	cli.ConfirmAction(cli.ActionDeactivate, "attribute value", value.GetValue(), force)

	deactivated, err := h.DeactivateAttributeValue(ctx, id)
	if err != nil {
		cli.ExitWithError("Failed to deactivate attribute value", err)
	}

	handleValueSuccess(cmd, deactivated)
}

func unsafeReactivateAttributeValue(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	ctx := cmd.Context()
	id := c.Flags.GetRequiredID("id")

	v, err := h.GetAttributeValue(ctx, id)
	if err != nil {
		cli.ExitWithError(fmt.Sprintf("Failed to get attribute value (%s)", id), err)
	}

	if !forceUnsafe {
		cli.ConfirmTextInput(cli.ActionReactivate, "attribute value", cli.InputNameFQN, v.GetFqn())
	}

	if reactivated, err := h.UnsafeReactivateAttributeValue(ctx, id); err != nil {
		cli.ExitWithError(fmt.Sprintf("Failed to reactivate attribute value (%s)", id), err)
	} else {
		rows := [][]string{
			{"Id", reactivated.GetId()},
			{"Value", reactivated.GetValue()},
		}
		if mdRows := getMetadataRows(v.GetMetadata()); mdRows != nil {
			rows = append(rows, mdRows...)
		}
		t := cli.NewTabular(rows...)
		common.HandleSuccess(cmd, id, t, v)
	}
}

func unsafeUpdateAttributeValue(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	ctx := cmd.Context()
	id := c.Flags.GetRequiredID("id")
	value := c.Flags.GetOptionalString("value")

	v, err := h.GetAttributeValue(ctx, id)
	if err != nil {
		cli.ExitWithError(fmt.Sprintf("Failed to get attribute value (%s)", id), err)
	}

	if !forceUnsafe {
		cli.ConfirmTextInput(cli.ActionUpdateUnsafe, "attribute value", cli.InputNameFQN, v.GetFqn())
	}

	if err := h.UnsafeUpdateAttributeValue(ctx, id, value); err != nil {
		cli.ExitWithError(fmt.Sprintf("Failed to update attribute value (%s)", id), err)
	} else {
		rows := [][]string{
			{"Id", v.GetId()},
			{"Value", value},
		}
		if mdRows := getMetadataRows(v.GetMetadata()); mdRows != nil {
			rows = append(rows, mdRows...)
		}
		t := cli.NewTabular(rows...)
		common.HandleSuccess(cmd, id, t, v)
	}
}

func unsafeDeleteAttributeValue(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	ctx := cmd.Context()
	id := c.Flags.GetRequiredID("id")

	v, err := h.GetAttributeValue(ctx, id)
	if err != nil {
		cli.ExitWithError(fmt.Sprintf("Failed to get attribute value (%s)", id), err)
	}

	if !forceUnsafe {
		cli.ConfirmTextInput(cli.ActionDelete, "attribute value", cli.InputNameFQN, v.GetFqn())
	}

	if err := h.UnsafeDeleteAttributeValue(ctx, id, v.GetFqn()); err != nil {
		cli.ExitWithError(fmt.Sprintf("Failed to delete attribute (%s)", id), err)
	} else {
		rows := [][]string{
			{"Id", v.GetId()},
			{"Value", v.GetValue()},
			{"Deleted", "true"},
		}
		if mdRows := getMetadataRows(v.GetMetadata()); mdRows != nil {
			rows = append(rows, mdRows...)
		}
		t := cli.NewTabular(rows...)
		common.HandleSuccess(cmd, id, t, v)
	}
}

func policyAssignKeyToAttrValue(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	value := c.Flags.GetRequiredString("value")
	keyID := c.Flags.GetRequiredID("key-id")

	attrKey, err := h.AssignKeyToAttributeValue(c.Context(), value, keyID)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to assign key: (%s) to attribute value: (%s)", keyID, value)
		cli.ExitWithError(errMsg, err)
	}

	rows := [][]string{
		{"Value ID", attrKey.GetValueId()},
		{"Key ID", attrKey.GetKeyId()},
	}
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, value, t, attrKey)
}

func policyRemoveKeyFromAttrValue(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	value := c.Flags.GetRequiredString("value")
	keyID := c.Flags.GetRequiredID("key-id")

	err := h.RemoveKeyFromAttributeValue(c.Context(), value, keyID)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to remove key (%s) from attribute value (%s)", keyID, value)
		cli.ExitWithError(errMsg, err)
	}

	rows := [][]string{
		{"Removed", "true"},
		{"Value", value},
		{"Key ID", keyID},
	}
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, value, t, nil)
}

func initAttributeValuesCommands() {
	createCmd := man.Docs.GetCommand("policy/attributes/values/create",
		man.WithRun(createAttributeValue),
	)
	createCmd.Flags().StringP(
		createCmd.GetDocFlag("attribute-id").Name,
		createCmd.GetDocFlag("attribute-id").Shorthand,
		createCmd.GetDocFlag("attribute-id").Default,
		createCmd.GetDocFlag("attribute-id").Description,
	)
	createCmd.Flags().StringP(
		createCmd.GetDocFlag("value").Name,
		createCmd.GetDocFlag("value").Shorthand,
		createCmd.GetDocFlag("value").Default,
		createCmd.GetDocFlag("value").Description,
	)
	injectLabelFlags(&createCmd.Command, false)

	getCmd := man.Docs.GetCommand("policy/attributes/values/get",
		man.WithRun(getAttributeValue),
	)
	getCmd.Flags().StringP(
		getCmd.GetDocFlag("id").Name,
		getCmd.GetDocFlag("id").Shorthand,
		getCmd.GetDocFlag("id").Default,
		getCmd.GetDocFlag("id").Description,
	)

	listCmd := man.Docs.GetCommand("policy/attributes/values/list",
		man.WithRun(listAttributeValue),
	)
	listCmd.Flags().StringP(
		listCmd.GetDocFlag("attribute-id").Name,
		listCmd.GetDocFlag("attribute-id").Shorthand,
		listCmd.GetDocFlag("attribute-id").Default,
		listCmd.GetDocFlag("attribute-id").Description,
	)
	listCmd.Flags().StringP(
		listCmd.GetDocFlag("state").Name,
		listCmd.GetDocFlag("state").Shorthand,
		listCmd.GetDocFlag("state").Default,
		listCmd.GetDocFlag("state").Description,
	)
	injectListPaginationFlags(listCmd)

	updateCmd := man.Docs.GetCommand("policy/attributes/values/update",
		man.WithRun(updateAttributeValue),
	)
	updateCmd.Flags().StringP(
		updateCmd.GetDocFlag("id").Name,
		updateCmd.GetDocFlag("id").Shorthand,
		updateCmd.GetDocFlag("id").Default,
		updateCmd.GetDocFlag("id").Description,
	)
	injectLabelFlags(&updateCmd.Command, true)

	deactivateCmd := man.Docs.GetCommand("policy/attributes/values/deactivate",
		man.WithRun(deactivateAttributeValue),
	)
	deactivateCmd.Flags().StringP(
		deactivateCmd.GetDocFlag("id").Name,
		deactivateCmd.GetDocFlag("id").Shorthand,
		deactivateCmd.GetDocFlag("id").Default,
		deactivateCmd.GetDocFlag("id").Description,
	)
	deactivateCmd.Flags().Bool(
		deactivateCmd.GetDocFlag("force").Name,
		false,
		deactivateCmd.GetDocFlag("force").Description,
	)

	keyCmd := man.Docs.GetCommand("policy/attributes/values/key")

	assignKasKeyCmd := man.Docs.GetCommand("policy/attributes/values/key/assign",
		man.WithRun(policyAssignKeyToAttrValue),
	)
	assignKasKeyCmd.Flags().StringP(
		assignKasKeyCmd.GetDocFlag("value").Name,
		assignKasKeyCmd.GetDocFlag("value").Shorthand,
		assignKasKeyCmd.GetDocFlag("value").Default,
		assignKasKeyCmd.GetDocFlag("value").Description,
	)
	assignKasKeyCmd.Flags().StringP(
		assignKasKeyCmd.GetDocFlag("key-id").Name,
		assignKasKeyCmd.GetDocFlag("key-id").Shorthand,
		assignKasKeyCmd.GetDocFlag("key-id").Default,
		assignKasKeyCmd.GetDocFlag("key-id").Description,
	)

	removeKasKeyCmd := man.Docs.GetCommand("policy/attributes/values/key/remove",
		man.WithRun(policyRemoveKeyFromAttrValue),
	)
	removeKasKeyCmd.Flags().StringP(
		removeKasKeyCmd.GetDocFlag("value").Name,
		removeKasKeyCmd.GetDocFlag("value").Shorthand,
		removeKasKeyCmd.GetDocFlag("value").Default,
		removeKasKeyCmd.GetDocFlag("value").Description,
	)
	removeKasKeyCmd.Flags().StringP(
		removeKasKeyCmd.GetDocFlag("key-id").Name,
		removeKasKeyCmd.GetDocFlag("key-id").Shorthand,
		removeKasKeyCmd.GetDocFlag("key-id").Default,
		removeKasKeyCmd.GetDocFlag("key-id").Description,
	)

	unsafeReactivateCmd := man.Docs.GetCommand("policy/attributes/values/unsafe/reactivate",
		man.WithRun(unsafeReactivateAttributeValue),
	)
	unsafeReactivateCmd.Flags().StringP(
		unsafeReactivateCmd.GetDocFlag("id").Name,
		unsafeReactivateCmd.GetDocFlag("id").Shorthand,
		unsafeReactivateCmd.GetDocFlag("id").Default,
		unsafeReactivateCmd.GetDocFlag("id").Description,
	)

	unsafeDeleteCmd := man.Docs.GetCommand("policy/attributes/values/unsafe/delete",
		man.WithRun(unsafeDeleteAttributeValue),
	)
	unsafeDeleteCmd.Flags().StringP(
		unsafeDeleteCmd.GetDocFlag("id").Name,
		unsafeDeleteCmd.GetDocFlag("id").Shorthand,
		unsafeDeleteCmd.GetDocFlag("id").Default,
		unsafeDeleteCmd.GetDocFlag("id").Description,
	)

	unsafeUpdateCmd := man.Docs.GetCommand("policy/attributes/values/unsafe/update",
		man.WithRun(unsafeUpdateAttributeValue),
	)
	unsafeUpdateCmd.Flags().StringP(
		unsafeUpdateCmd.GetDocFlag("id").Name,
		unsafeUpdateCmd.GetDocFlag("id").Shorthand,
		unsafeUpdateCmd.GetDocFlag("id").Default,
		unsafeUpdateCmd.GetDocFlag("id").Description,
	)
	unsafeUpdateCmd.Flags().StringP(
		unsafeUpdateCmd.GetDocFlag("value").Name,
		unsafeUpdateCmd.GetDocFlag("value").Shorthand,
		unsafeUpdateCmd.GetDocFlag("value").Default,
		unsafeUpdateCmd.GetDocFlag("value").Description,
	)

	unsafeCmd := man.Docs.GetCommand("policy/attributes/values/unsafe")
	unsafeCmd.PersistentFlags().BoolVar(&forceUnsafe,
		unsafeCmd.GetDocFlag("force").Name,
		false,
		unsafeCmd.GetDocFlag("force").Description,
	)

	keyCmd.AddSubcommands(assignKasKeyCmd, removeKasKeyCmd)
	unsafeCmd.AddSubcommands(unsafeReactivateCmd, unsafeDeleteCmd, unsafeUpdateCmd)
	doc := man.Docs.GetCommand("policy/attributes/values",
		man.WithSubcommands(createCmd, getCmd, listCmd, updateCmd, deactivateCmd, unsafeCmd, keyCmd),
	)
	AttributeValuesCmd = &doc.Command
	AttributesCmd.AddCommand(AttributeValuesCmd)
}

func handleValueSuccess(cmd *cobra.Command, v *policy.Value) {
	rows := [][]string{
		{"Id", v.GetId()},
		{"FQN", v.GetFqn()},
		{"Value", v.GetValue()},
	}
	if mdRows := getMetadataRows(v.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, v.GetId(), t, v)
}
