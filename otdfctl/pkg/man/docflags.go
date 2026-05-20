package man

import (
	"fmt"

	"github.com/opentdf/platform/otdfctl/pkg/cli"
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
