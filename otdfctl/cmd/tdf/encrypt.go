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

const encryptedOutputFileMode = 0o644

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
// anyway, so this reads a bounded prefix rather than the whole payload. An input
// that can be rewound is handed back unchanged, keeping it measurable; anything
// else gets the sniffed prefix pushed back in front of it, a megabyte in memory
// at most.
//
// On error the returned reader is nil, and the payload has been partly consumed.
func detectMimeType(in io.Reader, fileExt string) (string, io.Reader, error) {
	mimetype.SetLimit(Size1MB) // limit to 1MB

	// The rewind below restores where the payload started rather than seeking to
	// zero: stdin can arrive part-consumed — `{ read -r header; otdfctl encrypt; }
	// < payload.txt` leaves it mid-file — and the payload is what remains.
	seeker, start, _ := streamio.Seekable(in)

	head := make([]byte, Size1MB)
	// A payload shorter than the sniff window is the common case, not an error.
	n, err := io.ReadFull(in, head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return "", nil, err
	}
	head = head[:n]

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

	// Rewinding keeps the payload measurable; replaying the prefix is always
	// correct, since a failed lseek(2) leaves the offset untouched. So a refused
	// seek is a fallback, not an error — the SDK draws the same line when it
	// sizes the payload.
	if seeker != nil {
		if _, err := seeker.Seek(start, io.SeekStart); err == nil {
			return detected, in, nil
		}
		slog.Debug("payload rewind failed after its position probe succeeded; replaying the sniffed prefix instead")
	}
	return detected, io.MultiReader(bytes.NewReader(head), in), nil
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

	inputName := "stdin"
	if filePath != "" {
		inputName = filePath
	}

	// Whichever source it is, it goes to the SDK as-is rather than through a
	// temporary file, since CreateTDF takes a plain io.Reader.
	in, cleanup := piped, func() {}
	if filePath != "" {
		in, cleanup, err = streamio.OpenFile(filePath)
		if err != nil {
			cli.ExitWithError("Failed to read "+inputName+":", err)
		}
	}
	// cli.ExitWithError calls os.Exit, which skips deferred functions, so every
	// exit below goes through fail() instead of relying on this.
	defer cleanup()

	// fail does not return -- cli.ExitWithError ends in os.Exit -- but call sites
	// return immediately afterwards so encryptRun reads top to bottom. With -o it
	// discards the partial TDF, the no-partial-output guarantee streamio.OutputFile
	// exists to provide; a stdout destination cannot be given one, since the bytes
	// are already gone. Declared before tdfFile exists, which is why the nil guard.
	var tdfFile *streamio.OutputFile
	fail := func(msg string, err error) {
		if tdfFile != nil {
			tdfFile.Cleanup()
		}
		cleanup()
		cli.ExitWithError(msg, err)
	}

	// Resolve the destination before encrypting, so the payload streams straight
	// to it rather than accumulating in memory first.
	var dest io.Writer
	if out != "" {
		// make sure output ends in .tdf extension
		if !strings.HasSuffix(out, ".tdf") {
			out += ".tdf"
		}
		tdfFile, err = streamio.NewOutputFile(out, encryptedOutputFileMode)
		if err != nil {
			fail("Failed to write encrypted file "+out, err)
			return
		}
		defer tdfFile.Cleanup()
		dest = tdfFile
	} else {
		dest = os.Stdout
	}

	// auto-detect mime type if not provided
	if fileMimeType == "" {
		slog.Debug("detecting mime type of file")
		// Assigned through temporaries rather than straight into fileMimeType and
		// in: on error detectMimeType returns a nil reader, and writing that into
		// in would arm a nil dereference for anyone who later drops the return.
		mimeType, rest, err := detectMimeType(in, fileExt)
		if err != nil {
			fail("Failed to read "+inputName+" to detect its type (pass --mime-type to skip detection):", err)
			return
		}
		fileMimeType, in = mimeType, rest
	}
	slog.Debug("encrypting file", slog.String("mime_type", fileMimeType))
	// Worth a breadcrumb: the same bytes encrypt to a slightly larger TDF this
	// way, and nothing else tells the user why. Asked here rather than inside
	// detectMimeType so --mime-type, which skips detection entirely, still logs.
	if !streamio.Measurable(in) {
		slog.Debug("payload length is not knowable up front; writing a ZIP64 archive")
	}

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
		// The return matters: the Commit below would otherwise rename a
		// partially-written TDF into place, which is the exact outcome
		// streamio.OutputFile exists to prevent.
		fail("Failed to encrypt", err)
		return
	}

	if tdfFile != nil {
		if err := tdfFile.Commit(); err != nil {
			fail("Failed to write encrypted file "+out, err)
			return
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
