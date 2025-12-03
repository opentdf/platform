package cmd

import (
	"fmt"
	"os"

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
	Long: `Examples for using custom assertion providers with the assertionManager.

The "Magic Word" provider is a basic implementation used for demonstration purposes.
It "signs" assertions by appending a secret word and validates them by checking for it.`,
	Run: func(cmd *cobra.Command, _ []string) {
		_ = cmd.Help()
	},
}

var addAssertionCmd = &cobra.Command{
	Use:   "add",
	Short: "Adds a new assertion to an existing TDF",
	RunE:  appendAssertion,
	Long: `This command demonstrates adding an assertion to an existing TDF file.

The TDF manifest is read, updated with the new assertion, and rewritten to a new file.
This updates only the manifest structure without re-encrypting the payload data.

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
	defer inFileReader.Close()

	// Read TDF
	tdfReader, err := s.LoadTDF(inFileReader)
	if err != nil {
		return err
	}
	// Construct Assertion Provider
	assertionProvider := NewMagicWordAssertionProvider(magicWordAA)
	// Create (Bind) Assertion
	assertion, err := assertionProvider.Bind(cmd.Context(), tdfReader.Manifest())
	if err != nil {
		return fmt.Errorf("failed to bind assertion: %w", err)
	}
	// Update TDF with Assertion
	err = tdfReader.AppendAssertion(cmd.Context(), assertion)
	if err != nil {
		return fmt.Errorf("failed to append assertion: %w", err)
	}
	// Write Assertion using SDK function
	if err := tdfReader.WriteTDFWithUpdatedManifest(inFile, outFile); err != nil {
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
