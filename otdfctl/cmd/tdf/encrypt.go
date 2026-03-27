package tdf

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/gabriel-vasile/mimetype"
	"github.com/opentdf/otdfctl/cmd/common"
	"github.com/opentdf/otdfctl/pkg/cli"
	"github.com/opentdf/otdfctl/pkg/man"
	"github.com/opentdf/otdfctl/pkg/utils"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/spf13/cobra"
)

var (
	attrValues []string
	assertions string

	encryptDoc = man.Docs.GetCommand("encrypt", man.WithRun(encryptRun))
	EncryptCmd = &encryptDoc.Command
)

func encryptRun(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args, cli.WithPrintJSON())
	h := common.NewHandler(c)
	defer h.Close()

	var filePath string
	var fileExt string
	if len(args) > 0 {
		filePath = args[0]
		fileExt = strings.ToLower(strings.TrimPrefix(filepath.Ext(filePath), "."))
	}

	out := c.Flags.GetOptionalString("out")
	fileMimeType := c.Flags.GetOptionalString("mime-type")
	attrValues = c.Flags.GetStringSlice("attr", attrValues, cli.FlagsStringSliceOptions{Min: 0})
	tdfType := c.Flags.GetOptionalString("tdf-type")
	kasURLPath := c.Flags.GetOptionalString("kas-url-path")
	wrappingKeyAlgStr := c.Flags.GetOptionalString("wrapping-key-algorithm")
	targetMode := c.Flags.GetOptionalString("target-mode")
	var wrappingKeyAlgorithm ocrypto.KeyType
	switch wrappingKeyAlgStr {
	case string(ocrypto.RSA2048Key):
		wrappingKeyAlgorithm = ocrypto.RSA2048Key
	case string(ocrypto.EC256Key):
		wrappingKeyAlgorithm = ocrypto.EC256Key
	case string(ocrypto.EC384Key):
		wrappingKeyAlgorithm = ocrypto.EC384Key
	case string(ocrypto.EC521Key):
		wrappingKeyAlgorithm = ocrypto.EC521Key
	default:
		wrappingKeyAlgorithm = ocrypto.RSA2048Key
	}

	piped := readPipedStdin()

	inputCount := 0
	if filePath != "" {
		inputCount++
	}
	if len(piped) > 0 {
		inputCount++
	}

	cliExit := func(s string) {
		cli.ExitWithError("Must provide "+s+" of the following to encrypt: [file argument, stdin input]", nil)
	}
	if inputCount == 0 {
		cliExit("ONE")
	} else if inputCount > 1 {
		cliExit("ONLY ONE")
	}

	// prefer filepath argument over stdin input
	bytesSlice := piped
	var err error
	if filePath != "" {
		bytesSlice, err = utils.ReadBytesFromFile(filePath, MaxFileSize)
		if err != nil {
			cli.ExitWithError("Failed to read file:", err)
		}
	}

	// auto-detect mime type if not provided
	if fileMimeType == "" {
		slog.Debug("Detecting mime type of file")
		// get the mime type of the file
		mimetype.SetLimit(Size1MB) // limit to 1MB
		m := mimetype.Detect(bytesSlice)
		// default to application/octet-stream if no mime type is detected
		fileMimeType = m.String()

		if fileMimeType == "application/octet-stream" {
			if fileExt != "" {
				fileMimeType = mimetype.Lookup(fileExt).String()
			}
		}
	}
	slog.Debug("Encrypting file",
		slog.Int("file-len", len(bytesSlice)),
		slog.String("mime-type", fileMimeType),
	)

	// Do the encryption
	encrypted, err := h.EncryptBytes(
		tdfType,
		bytesSlice,
		attrValues,
		fileMimeType,
		kasURLPath,
		assertions,
		wrappingKeyAlgorithm,
		targetMode,
	)
	if err != nil {
		cli.ExitWithError("Failed to encrypt", err)
	}

	// Find the destination as the output flag filename or stdout
	var dest *os.File
	if out != "" {
		// make sure output ends in .tdf extension
		if !strings.HasSuffix(out, ".tdf") {
			out += ".tdf"
		}
		tdfFile, err := os.Create(out)
		if err != nil {
			cli.ExitWithError(fmt.Sprintf("Failed to write encrypted file %s", out), err)
		}
		defer tdfFile.Close()
		dest = tdfFile
	} else {
		dest = os.Stdout
	}

	_, e := io.Copy(dest, encrypted)
	if e != nil {
		cli.ExitWithError("Failed to write encrypted data to stdout", e)
	}
}

func InitEncryptCommand() {
	encryptDoc.Flags().StringP(
		encryptDoc.GetDocFlag("out").Name,
		encryptDoc.GetDocFlag("out").Shorthand,
		encryptDoc.GetDocFlag("out").Default,
		encryptDoc.GetDocFlag("out").Description,
	)
	encryptDoc.Flags().StringSliceVarP(
		&attrValues,
		encryptDoc.GetDocFlag("attr").Name,
		encryptDoc.GetDocFlag("attr").Shorthand,
		[]string{},
		encryptDoc.GetDocFlag("attr").Description,
	)
	encryptDoc.Flags().StringVarP(
		&assertions,
		encryptDoc.GetDocFlag("with-assertions").Name,
		encryptDoc.GetDocFlag("with-assertions").Shorthand,
		"",
		encryptDoc.GetDocFlag("with-assertions").Description,
	)
	encryptDoc.Flags().String(
		encryptDoc.GetDocFlag("mime-type").Name,
		encryptDoc.GetDocFlag("mime-type").Default,
		encryptDoc.GetDocFlag("mime-type").Description,
	)
	encryptDoc.Flags().String(
		encryptDoc.GetDocFlag("tdf-type").Name,
		encryptDoc.GetDocFlag("tdf-type").Default,
		encryptDoc.GetDocFlag("tdf-type").Description,
	)
	encryptDoc.Flags().StringP(
		encryptDoc.GetDocFlag("wrapping-key-algorithm").Name,
		encryptDoc.GetDocFlag("wrapping-key-algorithm").Shorthand,
		encryptDoc.GetDocFlag("wrapping-key-algorithm").Default,
		encryptDoc.GetDocFlag("wrapping-key-algorithm").Description,
	)
	encryptDoc.Flags().String(
		encryptDoc.GetDocFlag("kas-url-path").Name,
		encryptDoc.GetDocFlag("kas-url-path").Default,
		encryptDoc.GetDocFlag("kas-url-path").Description,
	)
	encryptDoc.Flags().String(
		encryptDoc.GetDocFlag("target-mode").Name,
		encryptDoc.GetDocFlag("target-mode").Default,
		encryptDoc.GetDocFlag("target-mode").Description,
	)
	encryptDoc.GroupID = TDF
}
