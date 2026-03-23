package policy

import (
	"fmt"

	"github.com/evertras/bubble-table/table"
	"github.com/opentdf/otdfctl/cmd/common"
	"github.com/opentdf/otdfctl/pkg/cli"
	"github.com/opentdf/otdfctl/pkg/man"
	"github.com/spf13/cobra"
)

func policyGetAction(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetOptionalID("id")
	name := c.Flags.GetOptionalString("name")

	if id == "" && name == "" {
		cli.ExitWithError("Either 'id' or 'name' must be provided", nil)
	}

	action, err := h.GetAction(cmd.Context(), id, name)
	if err != nil {
		identifier := fmt.Sprintf("id: %s", id)
		if id == "" {
			identifier = fmt.Sprintf("name: %s", name)
		}
		errMsg := fmt.Sprintf("Failed to find action (%s)", identifier)
		cli.ExitWithError(errMsg, err)
	}

	rows := [][]string{
		{"Id", action.GetId()},
		{"Name", action.GetName()},
	}
	if mdRows := getMetadataRows(action.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, action.GetId(), t, action)
}

func policyListActions(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	limit := c.Flags.GetRequiredInt32("limit")
	offset := c.Flags.GetRequiredInt32("offset")

	resp, err := h.ListActions(cmd.Context(), limit, offset)
	if err != nil {
		cli.ExitWithError("Failed to list actions", err)
	}
	t := cli.NewTable(
		cli.NewUUIDColumn(),
		table.NewFlexColumn("name", "Name", cli.FlexColumnWidthFour),
		table.NewFlexColumn("action_type", "Action Type", cli.FlexColumnWidthFour),
	)
	rows := []table.Row{}
	for _, a := range resp.GetActionsStandard() {
		rows = append(rows, table.NewRow(table.RowData{
			"id":          a.GetId(),
			"action_type": "standard",
			"name":        a.GetName(),
		}))
	}
	for _, a := range resp.GetActionsCustom() {
		rows = append(rows, table.NewRow(table.RowData{
			"id":          a.GetId(),
			"action_type": "custom",
			"name":        a.GetName(),
		}))
	}

	t = t.WithRows(rows)
	t = cli.WithListPaginationFooter(t, resp.GetPagination())
	common.HandleSuccess(cmd, "", t, resp)
}

func policyCreateAction(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	name := c.Flags.GetRequiredString("name")
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	action, err := h.CreateAction(cmd.Context(), name, getMetadataMutable(metadataLabels))
	if err != nil {
		cli.ExitWithError("Failed to create action", err)
	}

	rows := [][]string{
		{"Id", action.GetId()},
		{"Name", action.GetName()},
	}

	if mdRows := getMetadataRows(action.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}

	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, action.GetId(), t, action)
}

func policyDeleteAction(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")
	force := c.Flags.GetOptionalBool("force")
	ctx := cmd.Context()

	action, err := h.GetAction(ctx, id, "")
	if err != nil {
		errMsg := fmt.Sprintf("Failed to find action (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	cli.ConfirmAction(cli.ActionDelete, "action", id, force)

	err = h.DeleteAction(ctx, id)
	if err != nil {
		errMsg := fmt.Sprintf("Failed to delete action (%s)", id)
		cli.ExitWithError(errMsg, err)
	}
	rows := [][]string{{"Id", id}, {"Name", action.GetName()}}
	if mdRows := getMetadataRows(action.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, id, t, action)
}

func policyUpdateAction(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")
	name := c.Flags.GetOptionalString("name")
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	updated, err := h.UpdateAction(
		cmd.Context(),
		id,
		name,
		getMetadataMutable(metadataLabels),
		getMetadataUpdateBehavior(),
	)
	if err != nil {
		cli.ExitWithError("Failed to update action", err)
	}
	rows := [][]string{{"Id", id}, {"Name", updated.GetName()}}
	if mdRows := getMetadataRows(updated.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}
	t := cli.NewTabular(rows...)

	common.HandleSuccess(cmd, id, t, updated)
}

func initActionsCommands() {
	getDoc := man.Docs.GetCommand("policy/actions/get",
		man.WithRun(policyGetAction),
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

	listDoc := man.Docs.GetCommand("policy/actions/list",
		man.WithRun(policyListActions),
	)
	injectListPaginationFlags(listDoc)

	createDoc := man.Docs.GetCommand("policy/actions/create",
		man.WithRun(policyCreateAction),
	)
	createDoc.Flags().StringP(
		createDoc.GetDocFlag("name").Name,
		createDoc.GetDocFlag("name").Shorthand,
		createDoc.GetDocFlag("name").Default,
		createDoc.GetDocFlag("name").Description,
	)
	injectLabelFlags(&createDoc.Command, false)

	updateDoc := man.Docs.GetCommand("policy/actions/update",
		man.WithRun(policyUpdateAction),
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

	deleteDoc := man.Docs.GetCommand("policy/actions/delete",
		man.WithRun(policyDeleteAction),
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

	policyActionsDoc := man.Docs.GetCommand("policy/actions",
		man.WithSubcommands(
			getDoc,
			listDoc,
			createDoc,
			updateDoc,
			deleteDoc,
		),
	)
	Cmd.AddCommand(&policyActionsDoc.Command)
}
