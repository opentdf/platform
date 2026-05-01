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

// newCommandFromDoc creates an independent cobra.Command with metadata copied from a Doc.
// This allows registering the same logical command under multiple parents.
func newCommandFromDoc(doc *man.Doc, run func(*cobra.Command, []string)) *cobra.Command {
	cmd := &cobra.Command{
		Use:     doc.Use,
		Short:   doc.Short,
		Long:    doc.Long,
		Args:    doc.Args,
		Aliases: doc.Aliases,
		Hidden:  doc.Hidden,
		Run:     run,
	}
	return cmd
}

// buildNamespacesCommandTree creates a full namespaces command tree with all subcommands and flags.
// Each call returns an independent *cobra.Command so it can be parented under multiple commands.
func buildNamespacesCommandTree() *cobra.Command {
	nsDoc := man.Docs.GetDoc("policy/namespaces")
	nsCmd := newCommandFromDoc(nsDoc, nil)

	getDoc := man.Docs.GetDoc("policy/namespaces/get")
	getCmd := newCommandFromDoc(getDoc, getAttributeNamespace)
	getCmd.Flags().StringP(
		getDoc.GetDocFlag("id").Name,
		getDoc.GetDocFlag("id").Shorthand,
		getDoc.GetDocFlag("id").Default,
		getDoc.GetDocFlag("id").Description,
	)

	listDoc := man.Docs.GetDoc("policy/namespaces/list")
	listCmd := newCommandFromDoc(listDoc, listAttributeNamespaces)
	listCmd.Flags().StringP(
		listDoc.GetDocFlag("state").Name,
		listDoc.GetDocFlag("state").Shorthand,
		listDoc.GetDocFlag("state").Default,
		listDoc.GetDocFlag("state").Description,
	)
	listCmd.Flags().Int32P(
		listDoc.GetDocFlag("limit").Name,
		listDoc.GetDocFlag("limit").Shorthand,
		defaultListFlagLimit,
		listDoc.GetDocFlag("limit").Description,
	)
	listCmd.Flags().Int32P(
		listDoc.GetDocFlag("offset").Name,
		listDoc.GetDocFlag("offset").Shorthand,
		defaultListFlagOffset,
		listDoc.GetDocFlag("offset").Description,
	)

	createDoc := man.Docs.GetDoc("policy/namespaces/create")
	createCmd := newCommandFromDoc(createDoc, createAttributeNamespace)
	createCmd.Flags().StringP(
		createDoc.GetDocFlag("name").Name,
		createDoc.GetDocFlag("name").Shorthand,
		createDoc.GetDocFlag("name").Default,
		createDoc.GetDocFlag("name").Description,
	)
	injectLabelFlags(createCmd, false)

	updateDoc := man.Docs.GetDoc("policy/namespaces/update")
	updateCmd := newCommandFromDoc(updateDoc, updateAttributeNamespace)
	updateCmd.Flags().StringP(
		updateDoc.GetDocFlag("id").Name,
		updateDoc.GetDocFlag("id").Shorthand,
		updateDoc.GetDocFlag("id").Default,
		updateDoc.GetDocFlag("id").Description,
	)
	injectLabelFlags(updateCmd, true)

	deactivateDoc := man.Docs.GetDoc("policy/namespaces/deactivate")
	deactivateCmd := newCommandFromDoc(deactivateDoc, deactivateAttributeNamespace)
	deactivateCmd.Flags().StringP(
		deactivateDoc.GetDocFlag("id").Name,
		deactivateDoc.GetDocFlag("id").Shorthand,
		deactivateDoc.GetDocFlag("id").Default,
		deactivateDoc.GetDocFlag("id").Description,
	)
	deactivateCmd.Flags().Bool(
		deactivateDoc.GetDocFlag("force").Name,
		false,
		deactivateDoc.GetDocFlag("force").Description,
	)

	// unsafe
	unsafeDoc := man.Docs.GetDoc("policy/namespaces/unsafe")
	unsafeCmd := newCommandFromDoc(unsafeDoc, nil)
	unsafeCmd.PersistentFlags().BoolVar(
		&forceUnsafe,
		unsafeDoc.GetDocFlag("force").Name,
		false,
		unsafeDoc.GetDocFlag("force").Description,
	)

	deleteDoc := man.Docs.GetDoc("policy/namespaces/unsafe/delete")
	deleteCmd := newCommandFromDoc(deleteDoc, unsafeDeleteAttributeNamespace)
	deleteCmd.Flags().StringP(
		deleteDoc.GetDocFlag("id").Name,
		deleteDoc.GetDocFlag("id").Shorthand,
		deleteDoc.GetDocFlag("id").Default,
		deleteDoc.GetDocFlag("id").Description,
	)

	reactivateDoc := man.Docs.GetDoc("policy/namespaces/unsafe/reactivate")
	reactivateCmd := newCommandFromDoc(reactivateDoc, unsafeReactivateAttributeNamespace)
	reactivateCmd.Flags().StringP(
		reactivateDoc.GetDocFlag("id").Name,
		reactivateDoc.GetDocFlag("id").Shorthand,
		reactivateDoc.GetDocFlag("id").Default,
		reactivateDoc.GetDocFlag("id").Description,
	)

	unsafeUpdateDoc := man.Docs.GetDoc("policy/namespaces/unsafe/update")
	unsafeUpdateCmd := newCommandFromDoc(unsafeUpdateDoc, unsafeUpdateAttributeNamespace)
	unsafeUpdateCmd.Flags().StringP(
		unsafeUpdateDoc.GetDocFlag("id").Name,
		unsafeUpdateDoc.GetDocFlag("id").Shorthand,
		unsafeUpdateDoc.GetDocFlag("id").Default,
		unsafeUpdateDoc.GetDocFlag("id").Description,
	)
	unsafeUpdateCmd.Flags().StringP(
		unsafeUpdateDoc.GetDocFlag("name").Name,
		unsafeUpdateDoc.GetDocFlag("name").Shorthand,
		unsafeUpdateDoc.GetDocFlag("name").Default,
		unsafeUpdateDoc.GetDocFlag("name").Description,
	)

	// key
	keyDoc := man.Docs.GetDoc("policy/namespaces/key")
	keyCmd := newCommandFromDoc(keyDoc, nil)

	assignDoc := man.Docs.GetDoc("policy/namespaces/key/assign")
	assignCmd := newCommandFromDoc(assignDoc, policyAssignKeyToNamespace)
	assignCmd.Flags().StringP(
		assignDoc.GetDocFlag("namespace").Name,
		assignDoc.GetDocFlag("namespace").Shorthand,
		assignDoc.GetDocFlag("namespace").Default,
		assignDoc.GetDocFlag("namespace").Description,
	)
	assignCmd.Flags().StringP(
		assignDoc.GetDocFlag("key-id").Name,
		assignDoc.GetDocFlag("key-id").Shorthand,
		assignDoc.GetDocFlag("key-id").Default,
		assignDoc.GetDocFlag("key-id").Description,
	)

	removeDoc := man.Docs.GetDoc("policy/namespaces/key/remove")
	removeCmd := newCommandFromDoc(removeDoc, policyRemoveKeyFromNamespace)
	removeCmd.Flags().StringP(
		removeDoc.GetDocFlag("namespace").Name,
		removeDoc.GetDocFlag("namespace").Shorthand,
		removeDoc.GetDocFlag("namespace").Default,
		removeDoc.GetDocFlag("namespace").Description,
	)
	removeCmd.Flags().StringP(
		removeDoc.GetDocFlag("key-id").Name,
		removeDoc.GetDocFlag("key-id").Shorthand,
		removeDoc.GetDocFlag("key-id").Default,
		removeDoc.GetDocFlag("key-id").Description,
	)

	keyCmd.AddCommand(assignCmd, removeCmd)
	unsafeCmd.AddCommand(deleteCmd, reactivateCmd, unsafeUpdateCmd)
	nsCmd.AddCommand(getCmd, listCmd, createCmd, updateCmd, deactivateCmd, unsafeCmd, keyCmd)

	return nsCmd
}

func initNamespacesCommands() {
	Cmd.AddCommand(buildNamespacesCommandTree())
	AttributesCmd.AddCommand(buildNamespacesCommandTree())
}
