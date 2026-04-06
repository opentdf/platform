package config

import (
	"github.com/opentdf/otdfctl/pkg/man"
)

var (
	outputDoc = man.Docs.GetCommand("config/output")
	configDoc = man.Docs.GetCommand("config", man.WithSubcommands(outputDoc))
	Cmd       = &configDoc.Command
)

const (
	cfgDeprecationNotice    = "use profile commands"
	cfgOutputDeprecationMsg = "use profile set-output-format instead"
)

func InitCommands() {
	// Mark the entire config command as deprecated so users migrate to profiles.
	Cmd.Deprecated = cfgDeprecationNotice
	outputDoc.Deprecated = cfgOutputDeprecationMsg

	outputDoc.Flags().String(
		outputDoc.GetDocFlag("format").Name,
		outputDoc.GetDocFlag("format").Default,
		outputDoc.GetDocFlag("format").Description,
	)
}
