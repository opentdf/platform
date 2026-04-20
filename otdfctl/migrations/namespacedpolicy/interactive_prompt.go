package namespacedpolicy

import (
	"context"
	"errors"
	"strings"

	"github.com/charmbracelet/huh"
)

var ErrInteractiveReviewAborted = errors.New("interactive review aborted by user")

// ConfirmPrompt is a generic confirmation prompt for planner-owned review flows.
type ConfirmPrompt struct {
	Title        string
	Description  []string
	ConfirmLabel string
	CancelLabel  string
}

// PromptOption is one selectable value in a generic interactive prompt.
type PromptOption struct {
	Label       string
	Value       string
	Description string
}

// SelectPrompt is a generic single-select prompt for planner-owned review flows.
type SelectPrompt struct {
	Title       string
	Description []string
	Options     []PromptOption
}

// InteractivePrompter abstracts the concrete prompt implementation so review
// orchestration stays planner-owned and testable.
type InteractivePrompter interface {
	Confirm(context.Context, ConfirmPrompt) error
	Select(context.Context, SelectPrompt) (string, error)
}

// HuhPrompter implements InteractivePrompter using charmbracelet/huh forms.
type HuhPrompter struct{}

func (p *HuhPrompter) Confirm(ctx context.Context, prompt ConfirmPrompt) error {
	confirmLabel := strings.TrimSpace(prompt.ConfirmLabel)
	if confirmLabel == "" {
		confirmLabel = "Continue"
	}

	cancelLabel := strings.TrimSpace(prompt.CancelLabel)
	if cancelLabel == "" {
		cancelLabel = "Abort"
	}

	var choice bool
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(strings.TrimSpace(prompt.Title)).
				Description(promptDescription(prompt.Description)).
				Affirmative(confirmLabel).
				Negative(cancelLabel).
				Value(&choice),
		),
	)

	if err := form.RunWithContext(ctx); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return ErrInteractiveReviewAborted
		}
		return err
	}

	if !choice {
		return ErrInteractiveReviewAborted
	}

	return nil
}

func (p *HuhPrompter) Select(ctx context.Context, prompt SelectPrompt) (string, error) {
	options := make([]huh.Option[string], 0, len(prompt.Options))
	for _, option := range prompt.Options {
		label := option.Label
		if description := strings.TrimSpace(option.Description); description != "" {
			label += " - " + description
		}
		options = append(options, huh.NewOption(label, option.Value))
	}

	var choice string
	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title(strings.TrimSpace(prompt.Title)).
				Description(promptDescription(prompt.Description)).
				Options(options...).
				Value(&choice),
		),
	)

	if err := form.RunWithContext(ctx); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return "", ErrInteractiveReviewAborted
		}
		return "", err
	}

	return choice, nil
}

func promptDescription(description []string) string {
	lines := make([]string, 0, len(description))
	for _, line := range description {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}

	return strings.Join(lines, "\n")
}
