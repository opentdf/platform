package policy

import (
	"errors"
	"fmt"

	"github.com/evertras/bubble-table/table"
	"github.com/google/uuid"
	"github.com/opentdf/otdfctl/cmd/common"
	"github.com/opentdf/otdfctl/pkg/cli"
	"github.com/opentdf/otdfctl/pkg/handlers"
	"github.com/opentdf/otdfctl/pkg/man"
	"github.com/spf13/cobra"
)

var forceFlagValue = false

func assignKasGrant(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	cmd.Println(cli.WarningMessage(`Grants are now Key Mappings. To assign a key to attribute definition, value or namespace use the following commands.

	policy attributes namespace key assign

	policy attributes key assign
	
	policy attributes value key assign
	`))
}

func unassignKasGrant(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	cmd.Println(cli.WarningMessage(`Grants are now Key Mappings. The unassign grant command will be removed in the next release.
	
	policy attributes namespace key remove

	policy attributes key remove
	
	policy attributes value key remove
	`))

	ctx := cmd.Context()
	nsID := c.Flags.GetOptionalID("namespace-id")
	attrID := c.Flags.GetOptionalID("attribute-id")
	valID := c.Flags.GetOptionalID("value-id")
	kasID := c.Flags.GetRequiredID("kas-id")
	force := c.Flags.GetOptionalBool("force")

	count := 0
	for _, v := range []string{nsID, attrID, valID} {
		if v != "" {
			count++
		}
	}
	if count != 1 {
		cli.ExitWithError("Must specify exactly one Attribute Namespace ID, Definition ID, or Value ID to unassign", errors.New("invalid flag values"))
	}
	var (
		res     interface{}
		err     error
		confirm string
		rowID   []string
		rowFQN  []string
	)

	kas, err := h.GetKasRegistryEntry(ctx, handlers.KasIdentifier{
		ID: kasID,
	})
	if err != nil || kas == nil {
		cli.ExitWithError("Failed to get registered KAS", err)
	}
	kasURI := kas.GetUri()

	//nolint:gocritic,nestif // this is more readable than a switch statement
	if nsID != "" {
		ns, err := h.GetNamespace(ctx, nsID)
		if err != nil || ns == nil {
			cli.ExitWithError("Failed to get namespace definition", err)
		}
		confirm = fmt.Sprintf("the grant to namespace FQN (%s) of KAS URI", ns.GetFqn())
		cli.ConfirmAction(cli.ActionDelete, confirm, kasURI, force)
		res, err = h.DeleteKasGrantFromNamespace(ctx, nsID, kasID)
		if err != nil {
			cli.ExitWithError("Failed to update KAS grant for namespace", err)
		}

		rowID = []string{"Namespace ID", nsID}
		rowFQN = []string{"Namespace FQN", ns.GetFqn()}
	} else if attrID != "" {
		attr, err := h.GetAttribute(ctx, attrID)
		if err != nil || attr == nil {
			cli.ExitWithError("Failed to get attribute definition", err)
		}
		confirm = fmt.Sprintf("the grant to attribute FQN (%s) of KAS URI", attr.GetFqn())
		cli.ConfirmAction(cli.ActionDelete, confirm, kasURI, force)
		res, err = h.DeleteKasGrantFromAttribute(ctx, attrID, kasID)
		if err != nil {
			cli.ExitWithError("Failed to update KAS grant for attribute", err)
		}

		rowID = []string{"Attribute ID", attrID}
		rowFQN = []string{"Attribute FQN", attr.GetFqn()}
	} else {
		val, err := h.GetAttributeValue(ctx, valID)
		if err != nil || val == nil {
			cli.ExitWithError("Failed to get attribute value", err)
		}
		confirm = fmt.Sprintf("the grant to attribute value FQN (%s) of KAS URI", val.GetFqn())
		cli.ConfirmAction(cli.ActionDelete, confirm, kasURI, force)
		_, err = h.DeleteKasGrantFromValue(ctx, valID, kasID)
		if err != nil {
			cli.ExitWithError("Failed to update KAS grant for attribute value", err)
		}
		rowID = []string{"Value ID", valID}
		rowFQN = []string{"Value FQN", val.GetFqn()}
	}

	t := cli.NewTabular(rowID, rowFQN,
		[]string{"KAS ID", kasID},
		[]string{"Unassigned Granted KAS URI", kasURI},
	)
	common.HandleSuccess(cmd, "", t, res)
}

func listKasGrants(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	cmd.Println(cli.WarningMessage(`Grants are now Key Mappings. The ability to list grants will be removed in the next release.`))

	kasF := c.Flags.GetOptionalString("kas")
	limit := c.Flags.GetRequiredInt32("limit")
	offset := c.Flags.GetRequiredInt32("offset")
	var (
		kasID  string
		kasURI string
	)

	// if not a UUID, infer flag value passed was a URI
	if kasF != "" {
		_, err := uuid.Parse(kasF)
		if err != nil {
			kasURI = kasF
		} else {
			kasID = kasF
		}
	}

	grants, page, err := h.ListKasGrants(cmd.Context(), kasID, kasURI, limit, offset)
	if err != nil {
		cli.ExitWithError("Failed to list assigned KAS Grants", err)
	}

	rows := []table.Row{}
	t := cli.NewTable(
		// columns should be kas id, kas uri, type, id, fqn
		table.NewFlexColumn("kas_id", "KAS ID", cli.FlexColumnWidthThree),
		table.NewFlexColumn("kas_uri", "KAS URI", cli.FlexColumnWidthThree),
		table.NewFlexColumn("grant_type", "Assigned To", cli.FlexColumnWidthOne),
		table.NewFlexColumn("id", "Granted Object ID", cli.FlexColumnWidthThree),
		table.NewFlexColumn("fqn", "Granted Object FQN", cli.FlexColumnWidthThree),
	)

	for _, g := range grants {
		grantedKasID := g.GetKeyAccessServer().GetId()
		grantedKasURI := g.GetKeyAccessServer().GetUri()
		for _, ag := range g.GetAttributeGrants() {
			rows = append(rows, table.NewRow(table.RowData{
				"kas_id":     grantedKasID,
				"kas_uri":    grantedKasURI,
				"grant_type": "Definition",
				"id":         ag.GetId(),
				"fqn":        ag.GetFqn(),
			}))
		}
		for _, vg := range g.GetValueGrants() {
			rows = append(rows, table.NewRow(table.RowData{
				"kas_id":     grantedKasID,
				"kas_uri":    grantedKasURI,
				"grant_type": "Value",
				"id":         vg.GetId(),
				"fqn":        vg.GetFqn(),
			}))
		}
		for _, ng := range g.GetNamespaceGrants() {
			rows = append(rows, table.NewRow(table.RowData{
				"kas_id":     grantedKasID,
				"kas_uri":    grantedKasURI,
				"grant_type": "Namespace",
				"id":         ng.GetId(),
				"fqn":        ng.GetFqn(),
			}))
		}
	}
	t = t.WithRows(rows)
	t = cli.WithListPaginationFooter(t, page)

	// Do not supporting printing the 'get --id=...' helper message as grants are atypical
	// with no individual ID.
	cmd.Use = ""
	common.HandleSuccess(cmd, "", t, grants)
}

func initKASGrantsCommands() {
	assignCmd := man.Docs.GetCommand("policy/kas-grants/assign",
		man.WithRun(assignKasGrant),
	)
	assignCmd.Flags().StringP(
		assignCmd.GetDocFlag("namespace-id").Name,
		assignCmd.GetDocFlag("namespace-id").Shorthand,
		assignCmd.GetDocFlag("namespace-id").Default,
		assignCmd.GetDocFlag("namespace-id").Description,
	)
	assignCmd.Flags().StringP(
		assignCmd.GetDocFlag("attribute-id").Name,
		assignCmd.GetDocFlag("attribute-id").Shorthand,
		assignCmd.GetDocFlag("attribute-id").Default,
		assignCmd.GetDocFlag("attribute-id").Description,
	)
	assignCmd.Flags().StringP(
		assignCmd.GetDocFlag("value-id").Name,
		assignCmd.GetDocFlag("value-id").Shorthand,
		assignCmd.GetDocFlag("value-id").Default,
		assignCmd.GetDocFlag("value-id").Description,
	)
	assignCmd.Flags().StringP(
		assignCmd.GetDocFlag("kas-id").Name,
		assignCmd.GetDocFlag("kas-id").Shorthand,
		assignCmd.GetDocFlag("kas-id").Default,
		assignCmd.GetDocFlag("kas-id").Description,
	)
	injectLabelFlags(&assignCmd.Command, true)

	unassignCmd := man.Docs.GetCommand("policy/kas-grants/unassign",
		man.WithRun(unassignKasGrant),
	)
	unassignCmd.Flags().StringP(
		unassignCmd.GetDocFlag("namespace-id").Name,
		unassignCmd.GetDocFlag("namespace-id").Shorthand,
		unassignCmd.GetDocFlag("namespace-id").Default,
		unassignCmd.GetDocFlag("namespace-id").Description,
	)
	unassignCmd.Flags().StringP(
		unassignCmd.GetDocFlag("attribute-id").Name,
		unassignCmd.GetDocFlag("attribute-id").Shorthand,
		unassignCmd.GetDocFlag("attribute-id").Default,
		unassignCmd.GetDocFlag("attribute-id").Description,
	)
	unassignCmd.Flags().StringP(
		unassignCmd.GetDocFlag("value-id").Name,
		unassignCmd.GetDocFlag("value-id").Shorthand,
		unassignCmd.GetDocFlag("value-id").Default,
		unassignCmd.GetDocFlag("value-id").Description,
	)
	unassignCmd.Flags().StringP(
		unassignCmd.GetDocFlag("kas-id").Name,
		unassignCmd.GetDocFlag("kas-id").Shorthand,
		unassignCmd.GetDocFlag("kas-id").Default,
		unassignCmd.GetDocFlag("kas-id").Description,
	)
	unassignCmd.Flags().BoolVar(
		&forceFlagValue,
		unassignCmd.GetDocFlag("force").Name,
		false,
		unassignCmd.GetDocFlag("force").Description,
	)

	listCmd := man.Docs.GetCommand("policy/kas-grants/list",
		man.WithRun(listKasGrants),
	)
	listCmd.Flags().StringP(
		listCmd.GetDocFlag("kas").Name,
		listCmd.GetDocFlag("kas").Shorthand,
		listCmd.GetDocFlag("kas").Default,
		listCmd.GetDocFlag("kas").Description,
	)
	injectListPaginationFlags(listCmd)

	cmd := man.Docs.GetCommand("policy/kas-grants",
		man.WithSubcommands(assignCmd, unassignCmd, listCmd),
	)
	Cmd.AddCommand(&cmd.Command)
}
