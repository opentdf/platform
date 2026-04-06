package policy

import (
	"fmt"

	"github.com/evertras/bubble-table/table"
	"github.com/opentdf/otdfctl/cmd/common"
	"github.com/opentdf/otdfctl/pkg/cli"
	"github.com/opentdf/otdfctl/pkg/man"
	"github.com/spf13/cobra"
)

var (
	policyResourceMappingGroupsCmd *cobra.Command
)

func policyCreateResourceMappingGroup(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	nsID := c.Flags.GetRequiredID("namespace-id")
	name := c.Flags.GetRequiredString("name")
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	resourceMappingGroup, err := h.CreateResourceMappingGroup(cmd.Context(), nsID, name, getMetadataMutable(metadataLabels))
	if err != nil {
		cli.ExitWithError("Failed to create resource mapping group", err)
	}
	rows := [][]string{
		{"Id", resourceMappingGroup.GetId()},
		{"Namespace Id", resourceMappingGroup.GetNamespaceId()},
		{"Group Name", resourceMappingGroup.GetName()},
	}
	if mdRows := getMetadataRows(resourceMappingGroup.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, resourceMappingGroup.GetId(), t, resourceMappingGroup)
}

func policyGetResourceMappingGroup(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")

	resourceMappingGroup, err := h.GetResourceMappingGroup(cmd.Context(), id)
	if err != nil {
		cli.ExitWithError(fmt.Sprintf("Failed to get resource mapping group (%s)", id), err)
	}
	rows := [][]string{
		{"Id", resourceMappingGroup.GetId()},
		{"Namespace Id", resourceMappingGroup.GetNamespaceId()},
		{"Group Name", resourceMappingGroup.GetName()},
	}
	if mdRows := getMetadataRows(resourceMappingGroup.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, resourceMappingGroup.GetId(), t, resourceMappingGroup)
}

func policyListResourceMappingGroups(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	limit := c.Flags.GetRequiredInt32("limit")
	offset := c.Flags.GetRequiredInt32("offset")

	resp, err := h.ListResourceMappingGroups(cmd.Context(), limit, offset)
	if err != nil {
		cli.ExitWithError("Failed to list resource mapping groups", err)
	}

	t := cli.NewTable(
		cli.NewUUIDColumn(),
		table.NewFlexColumn("ns_id", "Namespace ID", cli.FlexColumnWidthFour),
		table.NewFlexColumn("name", "Name", cli.FlexColumnWidthFour),
		table.NewFlexColumn("labels", "Labels", cli.FlexColumnWidthOne),
		table.NewFlexColumn("created_at", "Created At", cli.FlexColumnWidthOne),
		table.NewFlexColumn("updated_at", "Updated At", cli.FlexColumnWidthOne),
	)
	rows := []table.Row{}
	for _, rmg := range resp.GetResourceMappingGroups() {
		metadata := cli.ConstructMetadata(rmg.GetMetadata())
		rows = append(rows, table.NewRow(table.RowData{
			"id":         rmg.GetId(),
			"ns_id":      rmg.GetNamespaceId(),
			"name":       rmg.GetName(),
			"labels":     metadata["Labels"],
			"created_at": metadata["Created At"],
			"updated_at": metadata["Updated At"],
		}))
	}
	t = t.WithRows(rows)
	t = cli.WithListPaginationFooter(t, resp.GetPagination())
	common.HandleSuccess(cmd, "", t, resp)
}

func policyUpdateResourceMappingGroup(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")
	nsID := c.Flags.GetOptionalID("namespace-id")
	name := c.Flags.GetOptionalString("name")
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	resourceMappingGroup, err := h.UpdateResourceMappingGroup(cmd.Context(), id, nsID, name, getMetadataMutable(metadataLabels), getMetadataUpdateBehavior())
	if err != nil {
		cli.ExitWithError(fmt.Sprintf("Failed to update resource mapping group (%s)", id), err)
	}
	rows := [][]string{
		{"Id", resourceMappingGroup.GetId()},
		{"Namespace Id", resourceMappingGroup.GetNamespaceId()},
		{"Group Name", resourceMappingGroup.GetName()},
	}
	if mdRows := getMetadataRows(resourceMappingGroup.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, resourceMappingGroup.GetId(), t, resourceMappingGroup)
}

func policyDeleteResourceMappingGroup(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")
	force := c.Flags.GetOptionalBool("force")

	cli.ConfirmAction(cli.ActionDelete, "resource-mapping-group", id, force)

	resourceMappingGroup, err := h.GetResourceMappingGroup(cmd.Context(), id)
	if err != nil {
		cli.ExitWithError(fmt.Sprintf("Failed to get resource mapping group for delete (%s)", id), err)
	}

	_, err = h.DeleteResourceMappingGroup(cmd.Context(), id)
	if err != nil {
		cli.ExitWithError(fmt.Sprintf("Failed to delete resource mapping group (%s)", id), err)
	}
	rows := [][]string{
		{"Id", resourceMappingGroup.GetId()},
		{"Namespace Id", resourceMappingGroup.GetNamespaceId()},
		{"Group Name", resourceMappingGroup.GetName()},
	}
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, resourceMappingGroup.GetId(), t, resourceMappingGroup)
}

func initResourceMappingGroupsCommands() {
	createDoc := man.Docs.GetCommand("policy/resource-mapping-groups/create",
		man.WithRun(policyCreateResourceMappingGroup),
	)
	createDoc.Flags().String(
		createDoc.GetDocFlag("namespace-id").Name,
		createDoc.GetDocFlag("namespace-id").Default,
		createDoc.GetDocFlag("namespace-id").Description,
	)
	createDoc.Flags().String(
		createDoc.GetDocFlag("name").Name,
		createDoc.GetDocFlag("name").Default,
		createDoc.GetDocFlag("name").Description,
	)
	injectLabelFlags(&createDoc.Command, false)

	getDoc := man.Docs.GetCommand("policy/resource-mapping-groups/get",
		man.WithRun(policyGetResourceMappingGroup),
	)
	getDoc.Flags().String(
		getDoc.GetDocFlag("id").Name,
		getDoc.GetDocFlag("id").Default,
		getDoc.GetDocFlag("id").Description,
	)

	listDoc := man.Docs.GetCommand("policy/resource-mapping-groups/list",
		man.WithRun(policyListResourceMappingGroups),
	)
	injectListPaginationFlags(listDoc)

	updateDoc := man.Docs.GetCommand("policy/resource-mapping-groups/update",
		man.WithRun(policyUpdateResourceMappingGroup),
	)
	updateDoc.Flags().String(
		updateDoc.GetDocFlag("id").Name,
		updateDoc.GetDocFlag("id").Default,
		updateDoc.GetDocFlag("id").Description,
	)
	updateDoc.Flags().String(
		updateDoc.GetDocFlag("namespace-id").Name,
		updateDoc.GetDocFlag("namespace-id").Default,
		updateDoc.GetDocFlag("namespace-id").Description,
	)
	updateDoc.Flags().String(
		updateDoc.GetDocFlag("name").Name,
		updateDoc.GetDocFlag("name").Default,
		updateDoc.GetDocFlag("name").Description,
	)
	injectLabelFlags(&updateDoc.Command, true)

	deleteDoc := man.Docs.GetCommand("policy/resource-mapping-groups/delete",
		man.WithRun(policyDeleteResourceMappingGroup),
	)
	deleteDoc.Flags().String(
		deleteDoc.GetDocFlag("id").Name,
		deleteDoc.GetDocFlag("id").Default,
		deleteDoc.GetDocFlag("id").Description,
	)
	deleteDoc.Flags().Bool(
		deleteDoc.GetDocFlag("force").Name,
		false,
		deleteDoc.GetDocFlag("force").Description,
	)

	doc := man.Docs.GetCommand("policy/resource-mapping-groups",
		man.WithSubcommands(createDoc, getDoc, listDoc, updateDoc, deleteDoc),
	)
	policyResourceMappingGroupsCmd = &doc.Command
	Cmd.AddCommand(policyResourceMappingGroupsCmd)
}
