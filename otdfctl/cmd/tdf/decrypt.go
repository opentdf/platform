package tdf

import (
	"errors"
	"io"
	"os"

	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/otdfctl/cmd/common"
	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/handlers"
	"github.com/opentdf/platform/otdfctl/pkg/man"
	"github.com/opentdf/platform/otdfctl/pkg/streamio"
	"github.com/spf13/cobra"
)

var (
	assertionVerification string
	kasAllowList          []string

	decryptDoc = man.Docs.GetCommand("decrypt", man.WithRun(decryptRun))
	DecryptCmd = &decryptDoc.Command
)

func decryptRun(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args, cli.WithPrintJSON())
	h := common.NewHandler(c)
	defer h.Close()

	output := c.Flags.GetOptionalString("out")
	disableAssertionVerification := c.Flags.GetOptionalBool("no-verify-assertions")
	sessionKeyAlgStr := c.Flags.GetOptionalString("session-key-algorithm")
	var sessionKeyAlgorithm ocrypto.KeyType
	switch sessionKeyAlgStr {
	case string(ocrypto.RSA2048Key):
		sessionKeyAlgorithm = ocrypto.RSA2048Key
	case string(ocrypto.EC256Key):
		sessionKeyAlgorithm = ocrypto.EC256Key
	case string(ocrypto.EC384Key):
		sessionKeyAlgorithm = ocrypto.EC384Key
	case string(ocrypto.EC521Key):
		sessionKeyAlgorithm = ocrypto.EC521Key
	default:
		sessionKeyAlgorithm = ocrypto.RSA2048Key
	}

	// Prefer the file argument over piped input.
	var tdfFile string
	if len(args) > 0 {
		tdfFile = args[0]
	}
	in, closeIn, err := streamio.OpenSeekable(tdfFile)
	switch {
	case errors.Is(err, streamio.ErrNoInput):
		cli.ExitWithError("Must provide ONE of the following to decrypt: [file argument, stdin input]", err)
	case err != nil:
		cli.ExitWithError("Failed to read file:", err)
	}
	defer closeIn()

	// Resolve the destination before decrypting, so the plaintext streams
	// straight to it rather than accumulating in memory first.
	var dest io.Writer = os.Stdout
	var outFile *streamio.OutputFile
	if output != "" {
		outFile, err = streamio.NewOutputFile(output)
		if err != nil {
			closeIn()
			cli.ExitWithError("Failed to write decrypted data to file", err)
		}
		defer outFile.Cleanup()
		dest = outFile
	}

	// cli.ExitWithError calls os.Exit, which skips deferred functions, so both
	// the spooled input and the partial output have to be discarded first.
	fail := func(msg string, err error) {
		closeIn()
		if outFile != nil {
			outFile.Cleanup()
		}
		cli.ExitWithError(msg, err)
	}

	ignoreAllowlist := len(kasAllowList) == 1 && kasAllowList[0] == "*"

	err = h.Decrypt(c.Context(), dest, in, handlers.DecryptOptions{
		AssertionVerificationKeysFile: assertionVerification,
		DisableAssertionCheck:         disableAssertionVerification,
		SessionKeyAlgorithm:           sessionKeyAlgorithm,
		KASAllowList:                  kasAllowList,
		IgnoreAllowlist:               ignoreAllowlist,
	})
	if err != nil {
		fail("Failed to decrypt file", err)
	}

	if outFile != nil {
		if err := outFile.Commit(); err != nil {
			fail("Failed to write decrypted data to file", err)
		}
	}
}

func InitDecryptCommand() {
	decryptDoc.Flags().StringP(
		decryptDoc.GetDocFlag("out").Name,
		decryptDoc.GetDocFlag("out").Shorthand,
		decryptDoc.GetDocFlag("out").Default,
		decryptDoc.GetDocFlag("out").Description,
	)
	// deprecated flag
	decryptDoc.Flags().StringP(
		decryptDoc.GetDocFlag("tdf-type").Name,
		decryptDoc.GetDocFlag("tdf-type").Shorthand,
		decryptDoc.GetDocFlag("tdf-type").Default,
		decryptDoc.GetDocFlag("tdf-type").Description,
	)
	decryptDoc.Flags().StringVarP(
		&assertionVerification,
		decryptDoc.GetDocFlag("with-assertion-verification-keys").Name,
		decryptDoc.GetDocFlag("with-assertion-verification-keys").Shorthand,
		"",
		decryptDoc.GetDocFlag("with-assertion-verification-keys").Description,
	)
	decryptDoc.Flags().String(
		decryptDoc.GetDocFlag("session-key-algorithm").Name,
		decryptDoc.GetDocFlag("session-key-algorithm").Default,
		decryptDoc.GetDocFlag("session-key-algorithm").Description,
	)
	decryptDoc.Flags().Bool(
		decryptDoc.GetDocFlag("no-verify-assertions").Name,
		decryptDoc.GetDocFlag("no-verify-assertions").DefaultAsBool(),
		decryptDoc.GetDocFlag("no-verify-assertions").Description,
	)
	decryptDoc.Flags().StringSliceVarP(
		&kasAllowList,
		decryptDoc.GetDocFlag("kas-allowlist").Name,
		decryptDoc.GetDocFlag("kas-allowlist").Shorthand,
		nil,
		decryptDoc.GetDocFlag("kas-allowlist").Description,
	)

	decryptDoc.GroupID = TDF
}
