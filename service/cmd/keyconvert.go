package cmd

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/spf13/cobra"
)

var keyconvertCmd = &cobra.Command{
	Use:   "keyconvert <input> [--out pem|jwk]",
	Short: "Convert a PEM key to PEM or JWK (auto-detects type)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		inputPath := args[0]
		outFormat, _ := cmd.Flags().GetString("out")
		pemBytes, err := os.ReadFile(inputPath)
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			return errors.New("input is not a valid PEM file")
		}
		key, err := jwk.ParseKey(pemBytes, jwk.WithPEM(true))
		if err != nil {
			return fmt.Errorf("failed to parse PEM as JWK: %w", err)
		}
		// Auto-detect output format if not specified
		if outFormat == "" {
			isPriv, err := jwk.IsPrivateKey(key)
			if err != nil {
				return fmt.Errorf("failed to determine key type: %w", err)
			}
			if isPriv {
				outFormat = "pem"
			} else {
				outFormat = "jwk"
			}
		}
		if outFormat == "jwk" {
			jsonbuf, err := json.MarshalIndent(key, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal JWK to JSON: %w", err)
			}
			cmd.Print(string(jsonbuf) + "\n")
			return nil
		} else if outFormat == "pem" {
			pemOut, err := jwk.Pem(key)
			if err != nil {
				// fallback: print original PEM if conversion fails
				cmd.Print(string(pemBytes))
				return nil
			}
			cmd.Print(string(pemOut))
			return nil
		}
		return fmt.Errorf("unsupported output format: %s", outFormat)
	},
}

func init() {
	keyconvertCmd.Flags().String("out", "", "Output format: pem|jwk (default: auto-detect)")
	rootCmd.AddCommand(keyconvertCmd)
}
