package migrate

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	otdfctl "github.com/opentdf/platform/otdfctl/cmd/common"
	namespacedpolicy "github.com/opentdf/platform/otdfctl/migrations/namespacedpolicy"
	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/opentdf/platform/otdfctl/pkg/man"
	"github.com/spf13/cobra"
)

func migrateNamespacedPolicyCmd() *cobra.Command {
	doc := man.Docs.GetCommand("migrate/namespaced-policy", man.WithRun(migrateNamespacedPolicy))
	doc.Args = cobra.NoArgs
	doc.Hidden = true
	doc.Flags().StringP(
		doc.GetDocFlag("scope").Name,
		doc.GetDocFlag("scope").Shorthand,
		doc.GetDocFlag("scope").Default,
		doc.GetDocFlag("scope").Description,
	)
	doc.Flags().StringP(
		doc.GetDocFlag("output").Name,
		doc.GetDocFlag("output").Shorthand,
		doc.GetDocFlag("output").Default,
		doc.GetDocFlag("output").Description,
	)

	return &doc.Command
}

func migrateNamespacedPolicy(cmd *cobra.Command, args []string) {
	c := cli.New(cmd, args)
	scopeCSV := c.Flags.GetRequiredString("scope")
	outputPath := c.Flags.GetRequiredString("output")

	commit, err := cmd.InheritedFlags().GetBool("commit")
	if err != nil {
		cli.ExitWithError("could not read --commit flag", err)
	}
	if commit {
		cli.ExitWithError("commit is not implemented for namespaced-policy", errors.New("--commit is not supported yet"))
	}

	h := otdfctl.NewHandler(c)
	defer h.Close()

	planner, err := namespacedpolicy.NewPlanner(&h, scopeCSV)
	if err != nil {
		cli.ExitWithError("could not create namespacedpolicy planner", err)
	}

	plan, err := planner.Plan(cmd.Context())
	if err != nil {
		cli.ExitWithError("could not build namespacedpolicy plan", err)
	}

	if err := writeNamespacedPolicyPlan(outputPath, plan); err != nil {
		cli.ExitWithError("could not write namespacedpolicy plan", err)
	}
}

func writeNamespacedPolicyPlan(path string, plan *namespacedpolicy.Plan) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	return encoder.Encode(plan)
}
