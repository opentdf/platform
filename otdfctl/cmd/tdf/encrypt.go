package tdf

import (
	"bytes"
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
	"github.com/opentdf/platform/otdfctl/pkg/streamio"
	"github.com/spf13/cobra"
)

var (
	attrValues []string
	assertions string

	encryptDoc = man.Docs.GetCommand("encrypt", man.WithRun(encryptRun))
	EncryptCmd = &encryptDoc.Command
)

// detectMimeType sniffs the payload's type from its head and returns a reader
// that still yields the whole payload.
//
// Detection needs only the first megabyte, which is what mimetype is limited to
// anyway, so this reads a bounded prefix rather than the whole payload. A
// seekable input is rewound and handed back unchanged, which matters: the SDK
// measures a seekable payload and keeps the archive in the compact ZIP32
// layout. A pipe cannot be rewound, so the sniffed prefix is pushed back in
// front of it instead — a megabyte held in memory at most.
func detectMimeType(in io.Reader, fileExt string) (string, io.Reader, error) {
	mimetype.SetLimit(Size1MB) // limit to 1MB

	head := make([]byte, Size1MB)
	// A payload shorter than the sniff window is the common case, not an error.
	n, err := io.ReadFull(in, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", nil, err
	}
	head = head[:n]

	rest := in
	if seeker, ok := in.(io.Seeker); ok {
		if _, err := seeker.Seek(0, io.SeekStart); err != nil {
			return "", nil, err
		}
	} else {
		rest = io.MultiReader(bytes.NewReader(head), in)
	}

	// defaults to application/octet-stream if nothing is recognized
	detected := mimetype.Detect(head).String()
	if detected == "application/octet-stream" && fileExt != "" {
		// mime.TypeByExtension is the extension lookup. mimetype.Lookup takes a
		// MIME type string, so passing it a bare extension always returned nil
		// and dereferencing that panicked — which is what happened for any file
		// whose contents were unrecognizable and whose name had an extension.
		// An extension with no known type leaves octet-stream in place.
		if byExt := mime.TypeByExtension("." + fileExt); byExt != "" {
			detected = byExt
		}
	}
	return detected, rest, nil
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

	piped, hasPiped, err := streamio.PipeReader(os.Stdin)
	if err != nil {
		cli.ExitWithError("failed to scan bytes from stdin", err)
	}

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

	// The SDK encrypts straight from a reader, so piped input goes to it as-is
	// rather than through a temporary file. A file is still opened seekably: the
	// SDK measures a seekable payload and keeps the archive in the compact ZIP32
	// layout, which a pipe has to give up.
	var in io.Reader = piped
	cleanup := func() {}
	if filePath != "" {
		f, err := os.Open(filePath)
		if err != nil {
			cli.ExitWithError("Failed to read file:", err)
		}
		in, cleanup = f, func() { f.Close() }
	}
	// cli.ExitWithError calls os.Exit, which skips deferred functions, so every
	// exit below goes through fail() to discard any partial output.
	defer cleanup()

	// Resolve the destination before encrypting, so the payload streams straight
	// to it rather than accumulating in memory first.
	var dest io.Writer
	var tdfFile *streamio.OutputFile
	if out != "" {
		// make sure output ends in .tdf extension
		if !strings.HasSuffix(out, ".tdf") {
			out += ".tdf"
		}
		tdfFile, err = streamio.NewOutputFile(out)
		if err != nil {
			cleanup()
			cli.ExitWithError("Failed to write encrypted file "+out, err)
		}
		defer tdfFile.Cleanup()
		dest = tdfFile
	} else {
		dest = os.Stdout
	}

	fail := func(msg string, err error) {
		if tdfFile != nil {
			tdfFile.Cleanup()
		}
		cleanup()
		cli.ExitWithError(msg, err)
	}

	// auto-detect mime type if not provided
	if fileMimeType == "" {
		slog.Debug("detecting mime type of file")
		fileMimeType, in, err = detectMimeType(in, fileExt)
		if err != nil {
			fail("Failed to read file:", err)
		}
	}
	slog.Debug("encrypting file", slog.String("mime_type", fileMimeType))

	// Do the encryption
	err = h.Encrypt(c.Context(), dest, in, handlers.EncryptOptions{
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
