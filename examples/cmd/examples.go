package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var platformEndpoint string

var ExamplesCmd = &cobra.Command{
	Use: "examples",
}

func init() {
	ExamplesCmd.PersistentFlags().StringVarP(&platformEndpoint, "platformEndpoint", "e", "localhost:8080", "Platform Endpoint")
}

func Execute() {
	if err := ExamplesCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
