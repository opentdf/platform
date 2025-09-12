package cmd

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

var (
	inFile      string
	outFile     string
	magicWordAA string
)

// assertionCmd represents the assertion command
var assertionCmd = &cobra.Command{
	Use:   "assertion",
	Short: "Demonstrates custom assertion providers",
	Long: `Examples for using custom assertion providers with the AssertionProviderFactory.

The "Magic Word" provider is a basic implementation used for demonstration purposes.
It "signs" assertions by appending a secret word and validates them by checking for it.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var addAssertionCmd = &cobra.Command{
	Use:   "add",
	Short: "Adds a new assertion to an existing TDF",
	RunE:  appendAssertion,
	Long: `This command demonstrates adding an assertion to an existing TDF file
by efficiently modifying the manifest without full decryption or KAS calls.

Example:
  ./examples-cli assertion add --in sensitive.txt.tdf --out sensitive-with-assertion.txt.tdf --magic-word swordfish
`,
}

func appendAssertion(cmd *cobra.Command, _ []string) error {
	s, err := newSDK()
	if err != nil {
		return err
	}

	inFileReader, err := os.Open(inFile)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	// Read TDF
	tdfReader, err := s.LoadTDF(inFileReader)
	if err != nil {
		return err
	}
	inFileReader.Close()
	// Construct Assertion Provider
	assertionProvider := NewMagicWordAssertionProvider(magicWordAA)
	// Configure Assertion Config
	assertionConfig, err := assertionProvider.Configure(cmd.Context())
	if err != nil {
		panic(err)
	}
	// Create (Bind) Assertion
	assertion, err := assertionProvider.Bind(cmd.Context(), assertionConfig, tdfReader.Manifest())
	if err != nil {
		panic(err)
	}
	// Update TDF with Assertion
	err = tdfReader.AppendAssertion(cmd.Context(), assertion)
	if err != nil {
		panic(err)
	}
	// Write Assertion
	if err := writeTDFWithUpdatedManifest(inFile, outFile, tdfReader.Manifest()); err != nil {
		return err
	}

	return nil
}

func init() {
	addAssertionCmd.Flags().StringVar(&inFile, "in", "", "Input TDF file path.")
	addAssertionCmd.Flags().StringVar(&outFile, "out", "", "Output TDF file path.")
	addAssertionCmd.Flags().StringVar(&magicWordAA, "magic-word", "", "The magic word to use for the new assertion.")
	_ = addAssertionCmd.MarkFlagRequired("in")
	_ = addAssertionCmd.MarkFlagRequired("out")
	_ = addAssertionCmd.MarkFlagRequired("magic-word")

	assertionCmd.AddCommand(addAssertionCmd)
	ExamplesCmd.AddCommand(assertionCmd)
}

// FIXME move to SDK

// writeTDFWithUpdatedManifest copies the original TDF ZIP verbatim while replacing only the manifest entry.
// This avoids re-encrypting payload by preserving all other entries byte-for-byte.
func writeTDFWithUpdatedManifest(inPath, outPath string, manifest sdk.Manifest) error {
	// Prepare updated manifest JSON without re-encrypting payload
	updatedManifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal updated manifest: %w", err)
	}

	inF, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("failed to open input TDF: %w", err)
	}
	defer inF.Close()

	stat, err := inF.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat input TDF: %w", err)
	}

	zr, err := zip.NewReader(inF, stat.Size())
	if err != nil {
		return fmt.Errorf("failed to open TDF as zip: %w", err)
	}

	outF, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("failed to create output TDF: %w", err)
	}
	defer func() {
		// Ensure the file is closed even if zip writer close fails
		_ = outF.Close()
	}()

	zw := zip.NewWriter(outF)

	// Track if we replaced an existing manifest
	replaced := false

	for _, f := range zr.File {
		isManifest := f.Name == "0.manifest.json" || f.Name == "manifest.json"

		// Clone header for faithful copy
		hdr := &zip.FileHeader{
			Name:           f.Name,
			Comment:        f.Comment,
			Method:         f.Method,
			NonUTF8:        f.NonUTF8,
			Modified:       f.Modified,
			ExternalAttrs:  f.ExternalAttrs,
			CreatorVersion: f.CreatorVersion,
			ReaderVersion:  f.ReaderVersion,
			Extra:          append([]byte(nil), f.Extra...),
		}

		// zip.FileHeader doesn't expose uncompressed/compressed sizes pre-write; they’re computed by Writer.

		if isManifest {
			// Replace the manifest contents
			// Use Deflate for manifest to keep typical compression; preserve Modified timestamp if present
			if hdr.Method == 0 {
				// If the original was stored (rare for manifest), keep it; else deflate by default
				hdr.Method = zip.Store
			}
			ww, err := zw.CreateHeader(hdr)
			if err != nil {
				_ = zw.Close()
				return fmt.Errorf("failed to create manifest entry in output TDF: %w", err)
			}
			// Ensure deterministic-ish timestamp if missing
			if hdr.Modified.IsZero() {
				hdr.SetModTime(time.Now().UTC())
			}
			if _, err := ww.Write(updatedManifestBytes); err != nil {
				_ = zw.Close()
				return fmt.Errorf("failed to write updated manifest: %w", err)
			}
			replaced = true
			continue
		}

		// Copy other entries byte-for-byte
		// Preserve compression method and metadata
		rc, err := f.Open()
		if err != nil {
			_ = zw.Close()
			return fmt.Errorf("failed to open input entry %q: %w", f.Name, err)
		}

		ww, err := zw.CreateHeader(hdr)
		if err != nil {
			rc.Close()
			_ = zw.Close()
			return fmt.Errorf("failed to create output entry %q: %w", f.Name, err)
		}

		if _, err := io.Copy(ww, rc); err != nil {
			rc.Close()
			_ = zw.Close()
			return fmt.Errorf("failed to copy entry %q: %w", f.Name, err)
		}
		rc.Close()
	}

	if !replaced {
		// If no manifest was found, add one as 0.manifest.json
		hdr := &zip.FileHeader{
			Name:     "0.manifest.json",
			Method:   zip.Deflate,
			Modified: time.Now().UTC(),
		}
		ww, err := zw.CreateHeader(hdr)
		if err != nil {
			_ = zw.Close()
			return fmt.Errorf("failed to create new manifest entry: %w", err)
		}
		if _, err := ww.Write(updatedManifestBytes); err != nil {
			_ = zw.Close()
			return fmt.Errorf("failed to write new manifest: %w", err)
		}
	}

	if err := zw.Close(); err != nil {
		return fmt.Errorf("failed to finalize output TDF: %w", err)
	}
	if err := outF.Close(); err != nil {
		return fmt.Errorf("failed to close output TDF: %w", err)
	}

	return nil
}
