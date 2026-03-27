package policy

import (
	"fmt"
	"strconv"

	"github.com/evertras/bubble-table/table"
	"github.com/opentdf/otdfctl/cmd/common"
	"github.com/opentdf/otdfctl/pkg/cli"
	"github.com/opentdf/otdfctl/pkg/man"
	"github.com/spf13/cobra"
)

var (
	NamespacesCmd = man.Docs.GetCommand("policy/attributes/namespaces")

	forceUnsafe bool
)

func getAttributeNamespace(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")

	ns, err := h.GetNamespace(cmd.Context(), id)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to get namespace (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	rows := [][]string{
		{"Id", ns.GetId()},
		{"Name", ns.GetName()},
	}
	if mdRows := getMetadataRows(ns.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, ns.GetId(), t, ns)
}

func listAttributeNamespaces(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	state := cli.GetState(cmd)
	limit := c.Flags.GetRequiredInt32("limit")
	offset := c.Flags.GetRequiredInt32("offset")

	resp, err := h.ListNamespaces(cmd.Context(), state, limit, offset)
	if err != nil {
		cli.ExitWithError("Failed to list namespaces", err)
	}
	t := cli.NewTable(
		cli.NewUUIDColumn(),
		table.NewFlexColumn("name", "Name", cli.FlexColumnWidthFour),
		table.NewFlexColumn("active", "Active", cli.FlexColumnWidthThree),
		table.NewFlexColumn("labels", "Labels", cli.FlexColumnWidthOne),
		table.NewFlexColumn("created_at", "Created At", cli.FlexColumnWidthOne),
		table.NewFlexColumn("updated_at", "Updated At", cli.FlexColumnWidthOne),
	)
	rows := []table.Row{}
	for _, ns := range resp.GetNamespaces() {
		metadata := cli.ConstructMetadata(ns.GetMetadata())
		rows = append(rows,
			table.NewRow(table.RowData{
				"id":         ns.GetId(),
				"name":       ns.GetName(),
				"active":     strconv.FormatBool(ns.GetActive().GetValue()),
				"labels":     metadata["Labels"],
				"created_at": metadata["Created At"],
				"updated_at": metadata["Updated At"],
			}),
		)
	}
	t = t.WithRows(rows)
	t = cli.WithListPaginationFooter(t, resp.GetPagination())
	common.HandleSuccess(cmd, "", t, resp)
}

func createAttributeNamespace(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	name := c.Flags.GetRequiredString("name")
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	created, err := h.CreateNamespace(cmd.Context(), name, getMetadataMutable(metadataLabels))
	if err != nil {
		cli.ExitWithError("Failed to create namespace", err)
	}
	rows := [][]string{
		{"Name", name},
		{"Id", created.GetId()},
	}
	if mdRows := getMetadataRows(created.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, created.GetId(), t, created)
}

func deactivateAttributeNamespace(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	ctx := cmd.Context()
	force := c.Flags.GetOptionalBool("force")
	id := c.Flags.GetRequiredID("id")

	ns, err := h.GetNamespace(ctx, id)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to find namespace (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	cli.ConfirmAction(cli.ActionDeactivate, "namespace", ns.GetName(), force)

	d, err := h.DeactivateNamespace(ctx, id)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to deactivate namespace (%s)", id)
		cli.ExitWithError(errMsg, err)
	}
	rows := [][]string{
		{"Id", ns.GetId()},
		{"Name", ns.GetName()},
	}
	if mdRows := getMetadataRows(d.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, ns.GetId(), t, d)
}

func updateAttributeNamespace(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	ns, err := h.UpdateNamespace(
		cmd.Context(),
		id,
		getMetadataMutable(metadataLabels),
		getMetadataUpdateBehavior(),
	)
	if err != nil {
		cli.ExitWithError(fmt.Sprintf("Failed to update namespace (%s)", id), err)
	}
	rows := [][]string{
		{"Id", ns.GetId()},
		{"Name", ns.GetName()},
	}
	if mdRows := getMetadataRows(ns.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, id, t, ns)
}

func unsafeDeleteAttributeNamespace(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	ctx := cmd.Context()
	id := c.Flags.GetRequiredID("id")

	ns, err := h.GetNamespace(ctx, id)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to find namespace (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	if !forceUnsafe {
		cli.ConfirmTextInput(cli.ActionDelete, "namespace", cli.InputNameFQN, ns.GetFqn())
	}

	if err := h.UnsafeDeleteNamespace(ctx, id, ns.GetFqn()); err != nil {
		errMsg := fmt.Sprintf("Failed to delete namespace (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	rows := [][]string{
		{"Id", ns.GetId()},
		{"Name", ns.GetName()},
	}
	if mdRows := getMetadataRows(ns.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, ns.GetId(), t, ns)
}

func unsafeReactivateAttributeNamespace(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	ctx := cmd.Context()
	id := c.Flags.GetRequiredID("id")

	ns, err := h.GetNamespace(ctx, id)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to find namespace (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	if !forceUnsafe {
		cli.ConfirmTextInput(cli.ActionReactivate, "namespace", cli.InputNameFQN, ns.GetFqn())
	}

	ns, err = h.UnsafeReactivateNamespace(ctx, id)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to reactivate namespace (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	rows := [][]string{
		{"Id", ns.GetId()},
		{"Name", ns.GetName()},
	}
	if mdRows := getMetadataRows(ns.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, ns.GetId(), t, ns)
}

func unsafeUpdateAttributeNamespace(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	ctx := cmd.Context()
	id := c.Flags.GetRequiredID("id")
	name := c.Flags.GetRequiredString("name")

	ns, err := h.GetNamespace(ctx, id)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to find namespace (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	if !forceUnsafe {
		cli.ConfirmTextInput(cli.ActionUpdateUnsafe, "namespace", cli.InputNameFQNUpdated, ns.GetFqn())
	}

	ns, err = h.UnsafeUpdateNamespace(ctx, id, name)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to reactivate namespace (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	rows := [][]string{
		{"Id", ns.GetId()},
		{"Name", ns.GetName()},
	}
	if mdRows := getMetadataRows(ns.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, ns.GetId(), t, ns)
}

func policyAssignKeyToNamespace(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	namespace := c.Flags.GetRequiredString("namespace")
	keyID := c.Flags.GetRequiredID("key-id")

	// Get the attribute namespace to show meaningful information in case of error
	attrKey, err := h.AssignKeyToAttributeNamespace(c.Context(), namespace, keyID)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to assign key: (%s) to attribute namespace: (%s)", keyID, namespace)
		cli.ExitWithError(errMsg, err)
	}

	// Prepare and display the result
	rows := [][]string{
		{"Namespace ID", attrKey.GetNamespaceId()},
		{"Key ID", attrKey.GetKeyId()},
	}
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, namespace, t, attrKey)
}

func policyRemoveKeyFromNamespace(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	namespace := c.Flags.GetRequiredString("namespace")
	keyID := c.Flags.GetRequiredID("key-id")

	err := h.RemoveKeyFromAttributeNamespace(c.Context(), namespace, keyID)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to remove key (%s) from attribute namespace (%s)", keyID, namespace)
		cli.ExitWithError(errMsg, err)
	}

	// Prepare and display the result
	rows := [][]string{
		{"Removed", "true"},
		{"Namespace", namespace},
		{"Key ID", keyID},
	}
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, namespace, t, nil)
}

func initNamespacesCommands() {
	getCmd := man.Docs.GetCommand("policy/attributes/namespaces/get",
		man.WithRun(getAttributeNamespace),
	)
	getCmd.Flags().StringP(
		getCmd.GetDocFlag("id").Name,
		getCmd.GetDocFlag("id").Shorthand,
		getCmd.GetDocFlag("id").Default,
		getCmd.GetDocFlag("id").Description,
	)

	listCmd := man.Docs.GetCommand("policy/attributes/namespaces/list",
		man.WithRun(listAttributeNamespaces),
	)
	listCmd.Flags().StringP(
		listCmd.GetDocFlag("state").Name,
		listCmd.GetDocFlag("state").Shorthand,
		listCmd.GetDocFlag("state").Default,
		listCmd.GetDocFlag("state").Description,
	)
	injectListPaginationFlags(listCmd)

	createDoc := man.Docs.GetCommand("policy/attributes/namespaces/create",
		man.WithRun(createAttributeNamespace),
	)
	createDoc.Flags().StringP(
		createDoc.GetDocFlag("name").Name,
		createDoc.GetDocFlag("name").Shorthand,
		createDoc.GetDocFlag("name").Default,
		createDoc.GetDocFlag("name").Description,
	)
	injectLabelFlags(&createDoc.Command, false)

	updateCmd := man.Docs.GetCommand("policy/attributes/namespaces/update",
		man.WithRun(updateAttributeNamespace),
	)
	updateCmd.Flags().StringP(
		updateCmd.GetDocFlag("id").Name,
		updateCmd.GetDocFlag("id").Shorthand,
		updateCmd.GetDocFlag("id").Default,
		updateCmd.GetDocFlag("id").Description,
	)
	injectLabelFlags(&updateCmd.Command, true)

	deactivateCmd := man.Docs.GetCommand("policy/attributes/namespaces/deactivate",
		man.WithRun(deactivateAttributeNamespace),
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

	// unsafe
	unsafeCmd := man.Docs.GetCommand("policy/attributes/namespaces/unsafe")
	unsafeCmd.PersistentFlags().BoolVar(
		&forceUnsafe,
		unsafeCmd.GetDocFlag("force").Name,
		false,
		unsafeCmd.GetDocFlag("force").Description,
	)
	deleteCmd := man.Docs.GetCommand("policy/attributes/namespaces/unsafe/delete",
		man.WithRun(unsafeDeleteAttributeNamespace),
	)
	deleteCmd.Flags().StringP(
		deactivateCmd.GetDocFlag("id").Name,
		deactivateCmd.GetDocFlag("id").Shorthand,
		deactivateCmd.GetDocFlag("id").Default,
		deactivateCmd.GetDocFlag("id").Description,
	)
	reactivateCmd := man.Docs.GetCommand("policy/attributes/namespaces/unsafe/reactivate",
		man.WithRun(unsafeReactivateAttributeNamespace),
	)
	reactivateCmd.Flags().StringP(
		deactivateCmd.GetDocFlag("id").Name,
		deactivateCmd.GetDocFlag("id").Shorthand,
		deactivateCmd.GetDocFlag("id").Default,
		deactivateCmd.GetDocFlag("id").Description,
	)
	unsafeUpdateCmd := man.Docs.GetCommand("policy/attributes/namespaces/unsafe/update",
		man.WithRun(unsafeUpdateAttributeNamespace),
	)
	unsafeUpdateCmd.Flags().StringP(
		deactivateCmd.GetDocFlag("id").Name,
		deactivateCmd.GetDocFlag("id").Shorthand,
		deactivateCmd.GetDocFlag("id").Default,
		deactivateCmd.GetDocFlag("id").Description,
	)
	unsafeUpdateCmd.Flags().StringP(
		unsafeUpdateCmd.GetDocFlag("name").Name,
		unsafeUpdateCmd.GetDocFlag("name").Shorthand,
		unsafeUpdateCmd.GetDocFlag("name").Default,
		unsafeUpdateCmd.GetDocFlag("name").Description,
	)

	keyCmd := man.Docs.GetCommand("policy/attributes/namespaces/key")

	// Assign KAS key to attribute namespace
	assignKasKeyCmd := man.Docs.GetCommand("policy/attributes/namespaces/key/assign",
		man.WithRun(policyAssignKeyToNamespace),
	)
	assignKasKeyCmd.Flags().StringP(
		assignKasKeyCmd.GetDocFlag("namespace").Name,
		assignKasKeyCmd.GetDocFlag("namespace").Shorthand,
		assignKasKeyCmd.GetDocFlag("namespace").Default,
		assignKasKeyCmd.GetDocFlag("namespace").Description,
	)
	assignKasKeyCmd.Flags().StringP(
		assignKasKeyCmd.GetDocFlag("key-id").Name,
		assignKasKeyCmd.GetDocFlag("key-id").Shorthand,
		assignKasKeyCmd.GetDocFlag("key-id").Default,
		assignKasKeyCmd.GetDocFlag("key-id").Description,
	)

	// Remove KAS key from attribute namespace
	removeKasKeyCmd := man.Docs.GetCommand("policy/attributes/namespaces/key/remove",
		man.WithRun(policyRemoveKeyFromNamespace),
	)
	removeKasKeyCmd.Flags().StringP(
		removeKasKeyCmd.GetDocFlag("namespace").Name,
		removeKasKeyCmd.GetDocFlag("namespace").Shorthand,
		removeKasKeyCmd.GetDocFlag("namespace").Default,
		removeKasKeyCmd.GetDocFlag("namespace").Description,
	)
	removeKasKeyCmd.Flags().StringP(
		removeKasKeyCmd.GetDocFlag("key-id").Name,
		removeKasKeyCmd.GetDocFlag("key-id").Shorthand,
		removeKasKeyCmd.GetDocFlag("key-id").Default,
		removeKasKeyCmd.GetDocFlag("key-id").Description,
	)

	keyCmd.AddSubcommands(assignKasKeyCmd, removeKasKeyCmd)
	unsafeCmd.AddSubcommands(deleteCmd, reactivateCmd, unsafeUpdateCmd)

	NamespacesCmd.AddSubcommands(getCmd, listCmd, createDoc, updateCmd, deactivateCmd, unsafeCmd, keyCmd)
	AttributesCmd.AddCommand(&NamespacesCmd.Command)
}
