package tdf

import (
	"errors"

	"github.com/opentdf/otdfctl/cmd/common"
	"github.com/opentdf/otdfctl/pkg/cli"
	"github.com/opentdf/otdfctl/pkg/handlers"
	"github.com/opentdf/otdfctl/pkg/man"
	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

type tdfInspectManifest struct {
	Algorithm             string                    `json:"algorithm"`
	KeyAccessType         string                    `json:"keyAccessType"`
	MimeType              string                    `json:"mimeType"`
	Policy                string                    `json:"policy"`
	Protocol              string                    `json:"protocol"`
	SegmentHashAlgorithm  string                    `json:"segmentHashAlgorithm"`
	Signature             string                    `json:"signature"`
	Type                  string                    `json:"type"`
	Method                sdk.Method                `json:"method"`
	IntegrityInformation  sdk.IntegrityInformation  `json:"integrityInformation"`
	EncryptionInformation sdk.EncryptionInformation `json:"encryptionInformation"`
	Assertions            []sdk.Assertion           `json:"assertions,omitempty"`
	SchemaVersion         string                    `json:"schemaVersion,omitempty"`
}

type tdfInspectResult struct {
	Manifest   tdfInspectManifest `json:"manifest"`
	Attributes []string           `json:"attributes"`
}

var (
	inspectDoc = man.Docs.GetCommand("inspect", man.WithRun(inspectRun))
	InspectCmd = &inspectDoc.Command
)

func inspectRun(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args, cli.WithPrintJSON())
	h := common.NewHandler(c)
	defer h.Close()

	data := cli.ReadFromArgsOrPipe(args, nil)
	if len(data) == 0 {
		c.ExitWithError("must provide ONE of the following: [file argument, stdin input]", errors.New("no input provided"))
	}

	result, errs := h.InspectTDF(data)
	for _, err := range errs {
		if errors.Is(err, handlers.ErrTDFInspectFailNotValidTDF) {
			c.ExitWithError("not a valid TDF", err)
		} else if errors.Is(err, handlers.ErrTDFInspectFailNotInspectable) {
			c.ExitWithError("failed to inspect TDF", err)
		}
	}

	if result.ZTDFManifest != nil {
		m := tdfInspectResult{
			Manifest: tdfInspectManifest{
				Algorithm:             result.ZTDFManifest.Algorithm,
				KeyAccessType:         result.ZTDFManifest.KeyAccessType,
				MimeType:              result.ZTDFManifest.MimeType,
				Policy:                result.ZTDFManifest.Policy,
				Protocol:              result.ZTDFManifest.Protocol,
				SegmentHashAlgorithm:  result.ZTDFManifest.SegmentHashAlgorithm,
				Signature:             result.ZTDFManifest.Signature,
				Type:                  result.ZTDFManifest.Type,
				Method:                result.ZTDFManifest.Method,
				IntegrityInformation:  result.ZTDFManifest.IntegrityInformation,
				EncryptionInformation: result.ZTDFManifest.EncryptionInformation,
				Assertions:            result.ZTDFManifest.Assertions,
				SchemaVersion:         result.ZTDFManifest.TDFVersion,
			},
			Attributes: result.Attributes,
		}

		c.ExitWithJSON(m, cli.ExitCodeSuccess)
	}
	c.ExitWithError("failed to inspect TDF", nil)
}

func InitInspectCommand() {
	inspectDoc.GroupID = TDF

	inspectDoc.PreRun = func(cmd *cobra.Command, args []string) {
		// Set the json flag to true since we only support json output
		cmd.SetArgs(append(args, "--json"))
	}
}
