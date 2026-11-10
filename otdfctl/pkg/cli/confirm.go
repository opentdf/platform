package cli

import (
	"fmt"

	"github.com/charmbracelet/huh"
)

const (
	// top level actions
	ActionGet          = "get"
	ActionList         = "list"
	ActionCreate       = "create"
	ActionUpdate       = "update"
	ActionUpdateUnsafe = "unsafely update"
	ActionDeactivate   = "deactivate"
	ActionReactivate   = "reactivate"
	ActionDelete       = "delete"

	// text input names
	InputNameFQN        = "fully qualified name (FQN)"
	InputNameFQNUpdated = "deprecated fully qualified name (FQN) being altered"
)

func ConfirmActionSubtext(action, resource, id, subtext string, force bool) {
	if force {
		return
	}
	var confirm bool
	title := fmt.Sprintf("Are you sure you want to %s %s:\n\n\t%s", action, resource, id)
	if subtext != "" {
		// since we don't return an error to stay consistent with the original function,
		// only append the subtext if populated
		title += fmt.Sprintf("\n\n%s", subtext)
	}
	err := huh.NewConfirm().
		Title(title).
		Affirmative("yes").
		Negative("no").
		Value(&confirm).
		Run()
	if err != nil {
		ExitWithError("Confirmation prompt failed", err)
	}

	if !confirm {
		ExitWithError("Aborted", nil)
	}
}

func ConfirmAction(action, resource, id string, force bool) {
	if force {
		return
	}
	var confirm bool
	err := huh.NewConfirm().
		Title(fmt.Sprintf("Are you sure you want to %s %s:\n\n\t%s", action, resource, id)).
		Affirmative("yes").
		Negative("no").
		Value(&confirm).
		Run()
	if err != nil {
		ExitWithError("Confirmation prompt failed", err)
	}

	if !confirm {
		ExitWithError("Aborted", nil)
	}
}

func ConfirmTextInput(action, resource, inputName, shouldMatchValue string) {
	var input string
	err := huh.NewInput().
		Title(fmt.Sprintf("To confirm you want to %s this %s and accept any side effects, please enter the %s to proceed: %s", action, resource, inputName, shouldMatchValue)).
		Value(&input).
		Validate(func(s string) error {
			if s != shouldMatchValue {
				return fmt.Errorf("entered FQN [%s] does not match required %s: %s", s, inputName, shouldMatchValue)
			}
			return nil
		}).Run()
	if err != nil {
		ExitWithError("Confirmation prompt failed", err)
	}
}

func AskForInput(message string) string {
	var input string
	err := huh.NewInput().
		Value(&input).
		Title(message).
		Run()
	if err != nil {
		ExitWithError("Prompt for input failed", err)
	}
	return input
}

func AskForSecret(message string) string {
	var secret string
	err := huh.NewInput().
		Value(&secret).
		Title(message).
		EchoMode(huh.EchoModePassword).
		Run()
	if err != nil {
		ExitWithError("Prompt for secret failed", err)
	}
	return secret
}
