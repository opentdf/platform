package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

func init() {
	isValidCmd := &cobra.Command{
		Use:   "isvalid [files...]",
		Short: "Check validity of a TDF",
		RunE:  areValid,
	}

	ExamplesCmd.AddCommand(isValidCmd)
}

type typeInfo struct {
	Valid bool
	Type  string
	Error error
}

func (t typeInfo) String() string {
	if t.Valid {
		return fmt.Sprintf("[✅ %s]", t.Type)
	}
	if t.Error != nil {
		return fmt.Sprintf("[🚮🔥 %s %v]", t.Type, t.Error)
	}
	return fmt.Sprintf("[📛 %s]", t.Type)
}

func areValid(cmd *cobra.Command, files []string) error {
	if len(files) == 0 {
		// TK Add support for handling stdin
		return cmd.Usage()
	}
	for _, file := range files {
		in, err := os.Open(file)
		if err != nil {
			cmd.PrintErrf("Error opening file %s: %v\n", file, err)
			return err
		}
		defer in.Close()

		cmd.Printf("File: [%s], TypeInfo: %v\n", file, isValid(cmd, in))
	}
	return nil
}

func isValid(cmd *cobra.Command, in io.ReadSeeker) []typeInfo {
	var typeInfos []typeInfo

	isValidTdf, err := sdk.IsValidTdf(in)
	typeInfos = append(typeInfos, typeInfo{Valid: isValidTdf, Error: err, Type: "TDF3"})

	if _, err := in.Seek(0, io.SeekStart); err != nil {
		cmd.PrintErrf("Error seeking to start of file: %v\n", err)
		return typeInfos
	}

	tdfType := sdk.GetTdfType(in)
	typeInfos = append(typeInfos, typeInfo{Valid: tdfType != sdk.Invalid, Error: nil, Type: tdfType.String()})

	return typeInfos
}
