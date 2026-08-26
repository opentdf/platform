package tdf

import (
	"bufio"
	"errors"
	"io"
	"log/slog"
	"mime"
	"os"
	"path/filepath"
	"strings"

	"github.com/gabriel-vasile/mimetype"
	"github.com/opentdf/platform/lib/ocrypto"
	"github.com/opentdf/platform/otdfctl/cmd/common"
	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/handlers"
	"github.com/opentdf/platform/otdfctl/pkg/man"
	"github.com/spf13/cobra"
)

var (
	attrValues []string
	assertions string

	encryptDoc = man.Docs.GetCommand("encrypt", man.WithRun(encryptRun))
	EncryptCmd = &encryptDoc.Command
)

// detectMimeType sniffs at most the first megabyte and returns a reader that
// still yields the complete payload.
func detectMimeType(in io.Reader, fileExt string) (string, io.Reader, error) {
	buffered, ok := in.(*bufio.Reader)
	if !ok {
		buffered = bufio.NewReaderSize(in, Size1MB)
		in = buffered
	}

	mimetype.SetLimit(Size1MB)
	head, err := buffered.Peek(Size1MB)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, bufio.ErrBufferFull) {
		return "", in, err
	}

	detected := mimetype.Detect(head).String()
	if detected == "application/octet-stream" && fileExt != "" {
		if byExtension := mime.TypeByExtension("." + strings.TrimPrefix(fileExt, ".")); byExtension != "" {
			detected = byExtension
		}
	}
	return detected, in, nil
}

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

	piped, hasPiped := stdinReader()

	inputCount := 0
	if filePath != "" {
		inputCount++
	}
	if hasPiped {
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

	var in io.Reader = piped
	if filePath != "" {
		file, err := os.Open(filePath)
		if err != nil {
			cli.ExitWithError("Failed to read file:", err)
		}
		defer file.Close()
		fileInfo, err := file.Stat()
		if err != nil {
			cli.ExitWithError("Failed to read file:", err)
		}
		if fileInfo.Size() > MaxFileSize {
			cli.ExitWithError("Failed to read file:", errors.New("file size exceeds the 10 GB limit"))
		}
		in = file
	}

	// auto-detect mime type if not provided
	if fileMimeType == "" {
		slog.Debug("detecting mime type of file")
		var err error
		fileMimeType, in, err = detectMimeType(in, fileExt)
		if err != nil {
			cli.ExitWithError("Failed to read file:", err)
		}
	}
	slog.Debug("encrypting file",
		slog.String("mime_type", fileMimeType),
	)

	var dest io.Writer
	var tdfFile *outputFile
	if out != "" {
		// make sure output ends in .tdf extension
		if !strings.HasSuffix(out, ".tdf") {
			out += ".tdf"
		}
		var err error
		tdfFile, err = newOutputFile(out)
		if err != nil {
			cli.ExitWithError("Failed to write encrypted file "+out, err)
		}
		defer tdfFile.Cleanup()
		dest = tdfFile
	} else {
		dest = os.Stdout
	}

	fail := func(message string, err error) {
		if tdfFile != nil {
			tdfFile.Cleanup()
		}
		cli.ExitWithError(message, err)
	}

	err := h.Encrypt(c.Context(), dest, in, handlers.EncryptOptions{
		TDFType:              tdfType,
		Attributes:           attrValues,
		MimeType:             fileMimeType,
		KASURLPath:           kasURLPath,
		Assertions:           assertions,
		WrappingKeyAlgorithm: wrappingKeyAlgorithm,
		TargetMode:           targetMode,
	})
	if err != nil {
		fail("Failed to encrypt", err)
	}

	if tdfFile != nil {
		if err := tdfFile.Commit(); err != nil {
			fail("Failed to write encrypted file "+out, err)
		}
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
