package man

import (
	"fmt"

	"github.com/opentdf/platform/otdfctl/pkg/cli"
	"github.com/spf13/cobra"
)

// SensitiveAnnotationKey is the pflag annotation key used to mark flags whose
// values contain secrets (cryptographic keys, tokens, etc.) and must not appear
// in logs or process listings.
const SensitiveAnnotationKey = "sensitive"

type DocFlag struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Shorthand   string   `yaml:"shorthand"`
	Default     string   `yaml:"default"`
	Enum        []string `yaml:"enum"`
	Sensitive   bool     `yaml:"sensitive"`
	Required    bool     `yaml:"required"`
}

func (d *Doc) GetDocFlag(name string) DocFlag {
	for _, f := range d.DocFlags {
		if f.Name == name {
			if len(f.Enum) > 0 {
				f.Description = fmt.Sprintf("%s %s", f.Description, cli.CommaSeparated(f.Enum))
			}
			return f
		}
	}
	panic(fmt.Sprintf("No doc flag found for name, %s for command %s", name, d.Use))
}

func (f DocFlag) DefaultAsBool() bool {
	return f.Default == "true"
}

// AddStringFlag registers a string flag on cmd from the doc's flag definition,
// wiring the flag's name, shorthand, default, and description in one call. It
// reduces the boilerplate of reading each field from GetDocFlag by hand, which
// is useful for commands that register many flags.
func (d *Doc) AddStringFlag(cmd *cobra.Command, name string) {
	f := d.GetDocFlag(name)
	cmd.Flags().StringP(f.Name, f.Shorthand, f.Default, f.Description)
}

// MarkSensitiveFlags sets pflag annotations on all flags in the command's
// FlagSet that are marked sensitive in the doc metadata. Call after all
// flags have been registered.
func (d *Doc) MarkSensitiveFlags() {
	for _, df := range d.DocFlags {
		if df.Sensitive {
			if err := d.Flags().SetAnnotation(df.Name, SensitiveAnnotationKey, []string{"true"}); err != nil {
				panic(fmt.Sprintf("failed to mark flag %q as sensitive for command %q: %v", df.Name, d.Use, err))
			}
		}
	}
}

// MarkRequiredFlags marks every flag the doc metadata declares `required: true`
// as required on the command, so cobra rejects an invocation that omits it and
// generated tooling (e.g. the MCP server) can advertise the flag as required.
//
// Unlike MarkSensitiveFlags, flags declared required in the doc but not
// registered on this command are skipped rather than panicking: the registry
// sweep visits every doc, including parent/index docs and commands that were
// never built into the active tree, and flags may be registered on a subcommand
// or via a shared injector. Call after all flags have been registered.
func (d *Doc) MarkRequiredFlags() {
	for _, df := range d.DocFlags {
		if !df.Required {
			continue
		}
		if d.Flags().Lookup(df.Name) == nil {
			continue
		}
		if err := d.MarkFlagRequired(df.Name); err != nil {
			panic(fmt.Sprintf("failed to mark flag %q as required for command %q: %v", df.Name, d.Use, err))
		}
	}
}
