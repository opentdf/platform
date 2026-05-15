package policy

import (
	"fmt"
	"strconv"

	"github.com/evertras/bubble-table/table"
	"github.com/opentdf/platform/otdfctl/cmd/common"
	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/man"
	"github.com/spf13/cobra"
)

var forceUnsafe bool

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
	sort := getSortOption(c)

	resp, err := h.ListNamespaces(cmd.Context(), state, limit, offset, sort)
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
	nsDoc := man.Docs.GetCommand("policy/namespaces")

	getDoc := man.Docs.GetCommand("policy/namespaces/get",
		man.WithRun(getAttributeNamespace),
	)
	getDoc.Flags().StringP(
		getDoc.GetDocFlag("id").Name,
		getDoc.GetDocFlag("id").Shorthand,
		getDoc.GetDocFlag("id").Default,
		getDoc.GetDocFlag("id").Description,
	)

	listDoc := man.Docs.GetCommand("policy/namespaces/list",
		man.WithRun(listAttributeNamespaces),
	)
	listDoc.Flags().StringP(
		listDoc.GetDocFlag("state").Name,
		listDoc.GetDocFlag("state").Shorthand,
		listDoc.GetDocFlag("state").Default,
		listDoc.GetDocFlag("state").Description,
	)
	injectListPaginationFlags(listDoc)
	injectListSortFlags(listDoc)

	createDoc := man.Docs.GetCommand("policy/namespaces/create",
		man.WithRun(createAttributeNamespace),
	)
	createDoc.Flags().StringP(
		createDoc.GetDocFlag("name").Name,
		createDoc.GetDocFlag("name").Shorthand,
		createDoc.GetDocFlag("name").Default,
		createDoc.GetDocFlag("name").Description,
	)
	injectLabelFlags(&createDoc.Command, false)

	updateDoc := man.Docs.GetCommand("policy/namespaces/update",
		man.WithRun(updateAttributeNamespace),
	)
	updateDoc.Flags().StringP(
		updateDoc.GetDocFlag("id").Name,
		updateDoc.GetDocFlag("id").Shorthand,
		updateDoc.GetDocFlag("id").Default,
		updateDoc.GetDocFlag("id").Description,
	)
	injectLabelFlags(&updateDoc.Command, true)

	deactivateDoc := man.Docs.GetCommand("policy/namespaces/deactivate",
		man.WithRun(deactivateAttributeNamespace),
	)
	deactivateDoc.Flags().StringP(
		deactivateDoc.GetDocFlag("id").Name,
		deactivateDoc.GetDocFlag("id").Shorthand,
		deactivateDoc.GetDocFlag("id").Default,
		deactivateDoc.GetDocFlag("id").Description,
	)
	deactivateDoc.Flags().Bool(
		deactivateDoc.GetDocFlag("force").Name,
		false,
		deactivateDoc.GetDocFlag("force").Description,
	)

	// unsafe
	unsafeDoc := man.Docs.GetCommand("policy/namespaces/unsafe")
	unsafeDoc.PersistentFlags().BoolVar(
		&forceUnsafe,
		unsafeDoc.GetDocFlag("force").Name,
		false,
		unsafeDoc.GetDocFlag("force").Description,
	)

	deleteDoc := man.Docs.GetCommand("policy/namespaces/unsafe/delete",
		man.WithRun(unsafeDeleteAttributeNamespace),
	)
	deleteDoc.Flags().StringP(
		deleteDoc.GetDocFlag("id").Name,
		deleteDoc.GetDocFlag("id").Shorthand,
		deleteDoc.GetDocFlag("id").Default,
		deleteDoc.GetDocFlag("id").Description,
	)

	reactivateDoc := man.Docs.GetCommand("policy/namespaces/unsafe/reactivate",
		man.WithRun(unsafeReactivateAttributeNamespace),
	)
	reactivateDoc.Flags().StringP(
		reactivateDoc.GetDocFlag("id").Name,
		reactivateDoc.GetDocFlag("id").Shorthand,
		reactivateDoc.GetDocFlag("id").Default,
		reactivateDoc.GetDocFlag("id").Description,
	)

	unsafeUpdateDoc := man.Docs.GetCommand("policy/namespaces/unsafe/update",
		man.WithRun(unsafeUpdateAttributeNamespace),
	)
	unsafeUpdateDoc.Flags().StringP(
		unsafeUpdateDoc.GetDocFlag("id").Name,
		unsafeUpdateDoc.GetDocFlag("id").Shorthand,
		unsafeUpdateDoc.GetDocFlag("id").Default,
		unsafeUpdateDoc.GetDocFlag("id").Description,
	)
	unsafeUpdateDoc.Flags().StringP(
		unsafeUpdateDoc.GetDocFlag("name").Name,
		unsafeUpdateDoc.GetDocFlag("name").Shorthand,
		unsafeUpdateDoc.GetDocFlag("name").Default,
		unsafeUpdateDoc.GetDocFlag("name").Description,
	)

	// key
	keyDoc := man.Docs.GetCommand("policy/namespaces/key")

	assignDoc := man.Docs.GetCommand("policy/namespaces/key/assign",
		man.WithRun(policyAssignKeyToNamespace),
	)
	assignDoc.Flags().StringP(
		assignDoc.GetDocFlag("namespace").Name,
		assignDoc.GetDocFlag("namespace").Shorthand,
		assignDoc.GetDocFlag("namespace").Default,
		assignDoc.GetDocFlag("namespace").Description,
	)
	assignDoc.Flags().StringP(
		assignDoc.GetDocFlag("key-id").Name,
		assignDoc.GetDocFlag("key-id").Shorthand,
		assignDoc.GetDocFlag("key-id").Default,
		assignDoc.GetDocFlag("key-id").Description,
	)

	removeDoc := man.Docs.GetCommand("policy/namespaces/key/remove",
		man.WithRun(policyRemoveKeyFromNamespace),
	)
	removeDoc.Flags().StringP(
		removeDoc.GetDocFlag("namespace").Name,
		removeDoc.GetDocFlag("namespace").Shorthand,
		removeDoc.GetDocFlag("namespace").Default,
		removeDoc.GetDocFlag("namespace").Description,
	)
	removeDoc.Flags().StringP(
		removeDoc.GetDocFlag("key-id").Name,
		removeDoc.GetDocFlag("key-id").Shorthand,
		removeDoc.GetDocFlag("key-id").Default,
		removeDoc.GetDocFlag("key-id").Description,
	)

	keyDoc.AddSubcommands(assignDoc, removeDoc)
	unsafeDoc.AddSubcommands(deleteDoc, reactivateDoc, unsafeUpdateDoc)
	nsDoc.AddSubcommands(getDoc, listDoc, createDoc, updateDoc, deactivateDoc, unsafeDoc, keyDoc)
	AttributesCmd.AddCommand(&nsDoc.Command)
	Cmd.AddCommand(&nsDoc.Command)
}
