package tdf

import (
	"errors"

	"github.com/opentdf/platform/otdfctl/cmd/common"
	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/handlers"
	"github.com/opentdf/platform/otdfctl/pkg/man"
	"github.com/opentdf/platform/otdfctl/pkg/streamio"
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

	var path string
	if len(args) > 0 {
		path = args[0]
	}
	in, cleanup, err := streamio.OpenSeekable(path)
	if err != nil {
		if errors.Is(err, streamio.ErrNoInput) {
			c.ExitWithError("must provide ONE of the following: [file argument, stdin input]", err)
		}
		c.ExitWithError("failed to read input", err)
	}
	// cli.ExitWithError calls os.Exit, which does not run deferred functions, so
	// cleanup is also invoked explicitly before every exit below — including the
	// successful one, since piped input is spooled to a temporary file.
	defer cleanup()

	result, errs := h.InspectTDF(in)
	for _, err := range errs {
		if errors.Is(err, handlers.ErrTDFInspectFailNotValidTDF) {
			cleanup()
			c.ExitWithError("not a valid TDF", err)
		} else if errors.Is(err, handlers.ErrTDFInspectFailNotInspectable) {
			cleanup()
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

		cleanup()
		c.ExitWithJSON(m, cli.ExitCodeSuccess)
	}
	cleanup()
	c.ExitWithError("failed to inspect TDF", nil)
}

func InitInspectCommand() {
	inspectDoc.GroupID = TDF

	inspectDoc.PreRun = func(cmd *cobra.Command, args []string) {
		// Set the json flag to true since we only support json output
		cmd.SetArgs(append(args, "--json"))
	}
}
