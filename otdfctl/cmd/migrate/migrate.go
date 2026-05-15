package migrate

import (
	"errors"
	"fmt"

	"github.com/opentdf/platform/otdfctl/cmd/migrate/prune"
	"github.com/opentdf/platform/otdfctl/pkg/man"
	"github.com/spf13/cobra"
)

var (
	migrateDoc = man.Docs.GetDoc("migrate")

	Cmd = &migrateDoc.Command

	initialized bool

	ErrNilParentCommand                = errors.New("parent command is nil")
	ErrNilMigrateCommand               = errors.New("migrate command is nil")
	ErrEmptyMigrateCommandName         = errors.New("migrate command name is empty")
	ErrMigrateCommandAlreadyRegistered = errors.New("migrate command is already registered")
	ErrMigrateCommandsNotInitialized   = errors.New("migrate commands are not initialized")
)

// InitCommands wires the built-in migrate command tree.
func InitCommands() {
	Cmd.PersistentFlags().BoolP(
		migrateDoc.GetDocFlag("commit").Name,
		migrateDoc.GetDocFlag("commit").Shorthand,
		migrateDoc.GetDocFlag("commit").DefaultAsBool(),
		migrateDoc.GetDocFlag("commit").Description,
	)

	Cmd.PersistentFlags().BoolP(
		migrateDoc.GetDocFlag("interactive").Name,
		migrateDoc.GetDocFlag("interactive").Shorthand,
		migrateDoc.GetDocFlag("interactive").DefaultAsBool(),
		migrateDoc.GetDocFlag("interactive").Description,
	)

	prune.InitCommands()

	Cmd.AddCommand(
		migrateNamespacedPolicyCmd(),
		prune.Cmd,
	)
	initialized = true
}

// AddCommands appends migration subcommands to the shared migrate command.
func AddCommands(commands ...*cobra.Command) error {
	if !initialized {
		return ErrMigrateCommandsNotInitialized
	}
	if Cmd == nil {
		return ErrNilParentCommand
	}

	registeredNames := registeredCommandNames(Cmd)
	for _, command := range commands {
		if err := validateCommandCanBeAdded(registeredNames, command); err != nil {
			return err
		}
		for name := range commandNames(command) {
			registeredNames[name] = struct{}{}
		}
	}

	Cmd.AddCommand(commands...)
	return nil
}

func validateCommandCanBeAdded(registeredNames map[string]struct{}, command *cobra.Command) error {
	if command == nil {
		return ErrNilMigrateCommand
	}
	if command.Name() == "" {
		return ErrEmptyMigrateCommandName
	}

	for name := range commandNames(command) {
		if _, ok := registeredNames[name]; ok {
			return fmt.Errorf("%w: %q", ErrMigrateCommandAlreadyRegistered, name)
		}
	}

	return nil
}

func registeredCommandNames(parent *cobra.Command) map[string]struct{} {
	names := make(map[string]struct{})
	for _, command := range parent.Commands() {
		for name := range commandNames(command) {
			names[name] = struct{}{}
		}
	}
	return names
}

func commandNames(command *cobra.Command) map[string]struct{} {
	names := map[string]struct{}{
		command.Name(): {},
	}
	for _, alias := range command.Aliases {
		names[alias] = struct{}{}
	}
	return names
}
