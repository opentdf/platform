package policy

import (
	"fmt"

	"github.com/evertras/bubble-table/table"
	"github.com/opentdf/otdfctl/cmd/common"
	"github.com/opentdf/otdfctl/pkg/cli"
	"github.com/opentdf/otdfctl/pkg/man"
	"github.com/opentdf/otdfctl/pkg/utils"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/spf13/cobra"
)

const (
	kasURIKey       = "kas_uri"
	kasURIColumn    = "Kas URI"
	algKey          = "algorithm"
	algColumn       = "Algorithm"
	pubPemKey       = "public_key_pem"
	pubPemColumn    = "Public Key PEM"
	kasKidKey       = "kas_key_id"
	kasKidColumn    = "Key ID"
	isBaseKey       = "is_base_key"
	isBaseKeyColumn = "Is Base Key"
)

// KAS Registry Base Keys Command
var policyKasRegistryBaseKeysCmd *cobra.Command

func getKasKeyIdentifier(c *cli.Cli) (*kasregistry.KasKeyIdentifier, error) {
	keyIdentifier := c.Flags.GetRequiredString("key")
	kasIdentifier := c.Flags.GetRequiredString("kas")

	identifier := &kasregistry.KasKeyIdentifier{
		Kid: keyIdentifier,
	}

	kasInputType := utils.ClassifyString(kasIdentifier)
	switch kasInputType { //nolint:exhaustive // default catches unknown
	case utils.StringTypeUUID:
		identifier.Identifier = &kasregistry.KasKeyIdentifier_KasId{KasId: kasIdentifier}
	case utils.StringTypeURI:
		identifier.Identifier = &kasregistry.KasKeyIdentifier_Uri{Uri: kasIdentifier}
	case utils.StringTypeGeneric:
		identifier.Identifier = &kasregistry.KasKeyIdentifier_Name{Name: kasIdentifier}
	default: // Catches StringTypeUnknown and any other unexpected types
		return nil, fmt.Errorf("invalid KAS identifier: '%s'. Must be a KAS UUID, URI, or Name", kasIdentifier)
	}
	return identifier, nil
}

func getBaseKeyTableRows(simpleKey *policy.SimpleKasKey, additionalInfo map[string]string) table.Row {
	readableAlg, _ := cli.KeyEnumToAlg(simpleKey.GetPublicKey().GetAlgorithm())
	rowData := table.RowData{
		kasKidKey: simpleKey.GetPublicKey().GetKid(),
		pubPemKey: simpleKey.GetPublicKey().GetPem(),
		algKey:    readableAlg,
		kasURIKey: simpleKey.GetKasUri(),
	}

	if len(additionalInfo) > 0 {
		for key, value := range additionalInfo {
			rowData[key] = value
		}
	}

	return table.NewRow(rowData)
}

func getBaseKeyTable(additionalColumns []table.Column) table.Model {
	columns := []table.Column{
		table.NewFlexColumn(kasURIKey, kasURIColumn, cli.FlexColumnWidthOne),
		table.NewFlexColumn(kasKidKey, kasKidColumn, cli.FlexColumnWidthOne),
		table.NewFlexColumn(pubPemKey, pubPemColumn, cli.FlexColumnWidthOne),
		table.NewFlexColumn(algKey, algColumn, cli.FlexColumnWidthOne),
	}
	columns = append(columns, additionalColumns...)

	return cli.NewTable(
		columns...,
	)
}

func getBaseKey(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	baseKey, err := h.GetBaseKey(c.Context())
	if err != nil {
		cli.ExitWithError("Failed to get base key", err)
	}

	if baseKey == nil {
		cli.ExitWithError("No base key found", nil)
	}

	t := getBaseKeyTable(nil)
	t = t.WithRows([]table.Row{getBaseKeyTableRows(baseKey, nil)})
	common.HandleSuccess(cmd, "", t, baseKey)
}

func setBaseKey(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	h := common.NewHandler(c)
	defer h.Close()

	var identifier *kasregistry.KasKeyIdentifier
	var err error

	id := c.Flags.GetOptionalString("key")
	if utils.ClassifyString(id) != utils.StringTypeUUID {
		identifier, err = getKasKeyIdentifier(c)
		if err != nil {
			c.ExitWithError("Invalid key identifier", err)
		}
	}
	baseKey, err := h.SetBaseKey(c.Context(), id, identifier)
	if err != nil {
		cli.ExitWithError("Failed to set base key", err)
	}

	t := getBaseKeyTable([]table.Column{
		table.NewFlexColumn(isBaseKey, isBaseKeyColumn, cli.FlexColumnWidthOne),
	})

	rows := []table.Row{
		getBaseKeyTableRows(baseKey.GetNewBaseKey(), map[string]string{
			isBaseKey: "true",
		}),
	}
	if baseKey.GetPreviousBaseKey() != nil {
		rows = append(rows, getBaseKeyTableRows(baseKey.GetPreviousBaseKey(), map[string]string{
			isBaseKey: "false",
		}))
	}

	t = t.WithRows(rows)
	common.HandleSuccess(cmd, "", t, baseKey)
}

// initBaseKeysCommands sets up the base-keys command and its subcommands.
func initBaseKeysCommands() {
	getDoc := man.Docs.GetCommand("policy/kas-registry/key/base/get",
		man.WithRun(getBaseKey),
	)

	setDoc := man.Docs.GetCommand("policy/kas-registry/key/base/set",
		man.WithRun(setBaseKey),
	)
	setDoc.Flags().StringP(
		setDoc.GetDocFlag("key").Name,
		setDoc.GetDocFlag("key").Shorthand,
		setDoc.GetDocFlag("key").Default,
		setDoc.GetDocFlag("key").Description,
	)
	setDoc.Flags().StringP(
		setDoc.GetDocFlag("kas").Name,
		setDoc.GetDocFlag("kas").Shorthand,
		setDoc.GetDocFlag("kas").Default,
		setDoc.GetDocFlag("kas").Description,
	)

	doc := man.Docs.GetCommand("policy/kas-registry/key/base",
		man.WithSubcommands(getDoc, setDoc))
	policyKasRegistryBaseKeysCmd = &doc.Command
	policyKasRegistryKeysCmd.AddCommand(
		policyKasRegistryBaseKeysCmd,
	)
}
