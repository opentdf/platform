package tdf

import (
	"os"

	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/sdk"
)

// dpopSDKOpts reads --dpop and --dpop-key flags from the CLI and returns the
// corresponding SDK options. Returns an empty slice when DPoP is not configured.
func dpopSDKOpts(c *cli.Cli) []sdk.Option {
	dpopAlg := c.Flags.GetOptionalString("dpop")
	dpopKeyPath := c.Flags.GetOptionalString("dpop-key")

	var opts []sdk.Option
	if dpopKeyPath != "" {
		pemBytes, err := os.ReadFile(dpopKeyPath)
		if err != nil {
			cli.ExitWithError("Failed to read DPoP key file", err)
		}
		opts = append(opts, sdk.WithDPoPKeyPEM(pemBytes))
		if dpopAlg != "" {
			opts = append(opts, sdk.WithDPoPAlgorithm(dpopAlg))
		}
	} else if dpopAlg != "" {
		opts = append(opts, sdk.WithDPoPAlgorithm(dpopAlg))
	}
	return opts
}
