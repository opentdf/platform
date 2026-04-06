package man

import (
	"fmt"

	"github.com/opentdf/otdfctl/pkg/cli"
)

type DocFlag struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Shorthand   string   `yaml:"shorthand"`
	Default     string   `yaml:"default"`
	Enum        []string `yaml:"enum"`
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
