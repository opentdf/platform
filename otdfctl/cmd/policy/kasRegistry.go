package policy

import (
	"fmt"

	"github.com/evertras/bubble-table/table"
	"github.com/opentdf/otdfctl/cmd/common"
	"github.com/opentdf/otdfctl/pkg/cli"
	"github.com/opentdf/otdfctl/pkg/handlers"
	"github.com/opentdf/otdfctl/pkg/man"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/spf13/cobra"
)

var (
	KasRegistryCmd = man.Docs.GetCommand("policy/kas-registry")
)

func getKeyAccessRegistry(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.FlagHelper.GetRequiredID("id")

	kas, err := h.GetKasRegistryEntry(cmd.Context(), handlers.KasIdentifier{
		ID: id,
	})
	if err != nil {
		errMsg := fmt.Sprintf("Failed to get Registered KAS entry (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	// TODO: Remove in next release
	key := &policy.PublicKey{}
	key.PublicKey = &policy.PublicKey_Cached{Cached: kas.GetPublicKey().GetCached()}
	if kas.GetPublicKey().GetRemote() != "" {
		key.PublicKey = &policy.PublicKey_Remote{Remote: kas.GetPublicKey().GetRemote()}
	}

	rows := [][]string{
		{"Id", kas.GetId()},
		{"URI", kas.GetUri()},
		{"PublicKey", kas.GetPublicKey().String()},
	}
	name := kas.GetName()
	if name != "" {
		rows = append(rows, []string{"Name", name})
	}

	if mdRows := getMetadataRows(kas.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}
	t := cli.NewTabular(rows...)

	common.HandleSuccess(cmd, kas.GetId(), t, kas)
}

func listKeyAccessRegistries(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	limit := c.Flags.GetRequiredInt32("limit")
	offset := c.Flags.GetRequiredInt32("offset")

	resp, err := h.ListKasRegistryEntries(cmd.Context(), limit, offset)
	if err != nil {
		cli.ExitWithError("Failed to list Registered KAS entries", err)
	}

	t := cli.NewTable(
		cli.NewUUIDColumn(),
		table.NewFlexColumn("uri", "URI", cli.FlexColumnWidthFour),
		table.NewFlexColumn("name", "Name", cli.FlexColumnWidthThree),
		table.NewFlexColumn("pk", "PublicKey", cli.FlexColumnWidthFour),
	)
	rows := []table.Row{}
	for _, kas := range resp.GetKeyAccessServers() {
		//TODO: Remove in next release
		key := policy.PublicKey{}
		key.PublicKey = &policy.PublicKey_Cached{Cached: kas.GetPublicKey().GetCached()}
		if kas.GetPublicKey().GetRemote() != "" {
			key.PublicKey = &policy.PublicKey_Remote{Remote: kas.GetPublicKey().GetRemote()}
		}
		rows = append(rows, table.NewRow(table.RowData{
			"id":   kas.GetId(),
			"uri":  kas.GetUri(),
			"name": kas.GetName(),
			"pk":   kas.GetPublicKey().String(),
		}))
	}
	t = t.WithRows(rows)
	t = cli.WithListPaginationFooter(t, resp.GetPagination())
	common.HandleSuccess(cmd, "", t, resp)
}

func createKeyAccessRegistry(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	uri := c.Flags.GetRequiredString("uri")
	cachedJSON := c.Flags.GetOptionalString("public-keys")   // Deprecated
	remote := c.Flags.GetOptionalString("public-key-remote") // Deprecated
	name := c.Flags.GetOptionalString("name")
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	if cachedJSON != "" || remote != "" {
		message := "\nDEPRECATION WARNING: --public-keys and --public-key-remote are deprecated and will be removed in an upcoming release.\n" +
			"Please use the 'policy kas-registry key' command instead.\n"
		cmd.Println(cli.WarningMessage(message))
	}

	created, err := h.CreateKasRegistryEntry(
		cmd.Context(),
		uri,
		name,
		getMetadataMutable(metadataLabels),
	)
	if err != nil {
		cli.ExitWithError("Failed to create Registered KAS entry", err)
	}

	rows := [][]string{
		{"Id", created.GetId()},
		{"URI", created.GetUri()},
	}
	if name != "" {
		rows = append(rows, []string{"Name", name})
	}
	if mdRows := getMetadataRows(created.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}
	t := cli.NewTabular(rows...)

	common.HandleSuccess(cmd, created.GetId(), t, created)
}

func updateKeyAccessRegistry(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	id := c.Flags.GetRequiredID("id")
	uri := c.Flags.GetOptionalString("uri")
	name := c.Flags.GetOptionalString("name")
	cachedJSON := c.Flags.GetOptionalString("public-keys")   // Deprecated
	remote := c.Flags.GetOptionalString("public-key-remote") // Deprecated
	metadataLabels = c.Flags.GetStringSlice("label", metadataLabels, cli.FlagsStringSliceOptions{Min: 0})

	if cachedJSON != "" || remote != "" {
		message := "\nDEPRECATION WARNING: --public-keys and --public-key-remote are deprecated and will be removed in an upcoming release.\n" +
			"Please use the 'policy kas-registry key' command instead.\n"
		cmd.Println(cli.WarningMessage(message))
	}

	updated, err := h.UpdateKasRegistryEntry(
		cmd.Context(),
		id,
		uri,
		name,
		getMetadataMutable(metadataLabels),
		getMetadataUpdateBehavior(),
	)
	if err != nil {
		cli.ExitWithError(fmt.Sprintf("Failed to update Registered KAS entry (%s)", id), err)
	}
	rows := [][]string{
		{"Id", id},
		{"URI", updated.GetUri()},
	}
	if updated.GetName() != "" {
		rows = append(rows, []string{"Name", updated.GetName()})
	}

	if mdRows := getMetadataRows(updated.GetMetadata()); mdRows != nil {
		rows = append(rows, mdRows...)
	}
	t := cli.NewTabular(rows...)
	common.HandleSuccess(cmd, id, t, updated)
}

func deleteKeyAccessRegistry(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	ctx := cmd.Context()
	id := c.Flags.GetRequiredID("id")
	force := c.Flags.GetOptionalBool("force")

	kas, err := h.GetKasRegistryEntry(ctx, handlers.KasIdentifier{
		ID: id,
	})
	if err != nil {
		errMsg := fmt.Sprintf("Failed to get Registered KAS entry (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	cli.ConfirmAction(cli.ActionDelete, "Registered KAS", id, force)

	if _, err := h.DeleteKasRegistryEntry(ctx, id); err != nil {
		errMsg := fmt.Sprintf("Failed to delete Registered KAS entry (%s)", id)
		cli.ExitWithError(errMsg, err)
	}

	t := cli.NewTabular(
		[]string{"Id", kas.GetId()},
		[]string{"URI", kas.GetUri()},
	)

	common.HandleSuccess(cmd, kas.GetId(), t, kas)
}

func initKASRegistryCommands() {
	getDoc := man.Docs.GetCommand("policy/kas-registry/get",
		man.WithRun(getKeyAccessRegistry),
	)
	getDoc.Flags().StringP(
		getDoc.GetDocFlag("id").Name,
		getDoc.GetDocFlag("id").Shorthand,
		getDoc.GetDocFlag("id").Default,
		getDoc.GetDocFlag("id").Description,
	)

	listDoc := man.Docs.GetCommand("policy/kas-registry/list",
		man.WithRun(listKeyAccessRegistries),
	)
	injectListPaginationFlags(listDoc)

	createDoc := man.Docs.GetCommand("policy/kas-registry/create",
		man.WithRun(createKeyAccessRegistry),
	)
	createDoc.Flags().StringP(
		createDoc.GetDocFlag("uri").Name,
		createDoc.GetDocFlag("uri").Shorthand,
		createDoc.GetDocFlag("uri").Default,
		createDoc.GetDocFlag("uri").Description,
	)
	createDoc.Flags().StringP(
		createDoc.GetDocFlag("public-keys").Name,
		createDoc.GetDocFlag("public-keys").Shorthand,
		createDoc.GetDocFlag("public-keys").Default,
		createDoc.GetDocFlag("public-keys").Description,
	)
	createDoc.Flags().StringP(
		createDoc.GetDocFlag("public-key-remote").Name,
		createDoc.GetDocFlag("public-key-remote").Shorthand,
		createDoc.GetDocFlag("public-key-remote").Default,
		createDoc.GetDocFlag("public-key-remote").Description,
	)
	createDoc.Flags().StringP(
		createDoc.GetDocFlag("name").Name,
		createDoc.GetDocFlag("name").Shorthand,
		createDoc.GetDocFlag("name").Default,
		createDoc.GetDocFlag("name").Description,
	)
	injectLabelFlags(&createDoc.Command, false)

	updateDoc := man.Docs.GetCommand("policy/kas-registry/update",
		man.WithRun(updateKeyAccessRegistry),
	)
	updateDoc.Flags().StringP(
		updateDoc.GetDocFlag("id").Name,
		updateDoc.GetDocFlag("id").Shorthand,
		updateDoc.GetDocFlag("id").Default,
		updateDoc.GetDocFlag("id").Description,
	)
	updateDoc.Flags().StringP(
		updateDoc.GetDocFlag("uri").Name,
		updateDoc.GetDocFlag("uri").Shorthand,
		updateDoc.GetDocFlag("uri").Default,
		updateDoc.GetDocFlag("uri").Description,
	)
	updateDoc.Flags().StringP(
		updateDoc.GetDocFlag("public-keys").Name,
		updateDoc.GetDocFlag("public-keys").Shorthand,
		updateDoc.GetDocFlag("public-keys").Default,
		updateDoc.GetDocFlag("public-keys").Description,
	)
	updateDoc.Flags().StringP(
		updateDoc.GetDocFlag("public-key-remote").Name,
		updateDoc.GetDocFlag("public-key-remote").Shorthand,
		updateDoc.GetDocFlag("public-key-remote").Default,
		updateDoc.GetDocFlag("public-key-remote").Description,
	)
	updateDoc.Flags().StringP(
		updateDoc.GetDocFlag("name").Name,
		updateDoc.GetDocFlag("name").Shorthand,
		updateDoc.GetDocFlag("name").Default,
		updateDoc.GetDocFlag("name").Description,
	)
	injectLabelFlags(&updateDoc.Command, true)

	deleteDoc := man.Docs.GetCommand("policy/kas-registry/delete",
		man.WithRun(deleteKeyAccessRegistry),
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

	KasRegistryCmd.AddSubcommands(createDoc, getDoc, listDoc, updateDoc, deleteDoc)
	Cmd.AddCommand(&KasRegistryCmd.Command)
}
