package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/opentdf/otdfctl/tui/constants"
)

type AttributeCreateModel struct {
	form *huh.Form
}

func InitAttributeCreateModel() (tea.Model, tea.Cmd) {
	namespace := ""
	m := AttributeCreateModel{}
	m.form = huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Namespace").
				Options(
					huh.NewOption("demo.com", "demo.com"),
					huh.NewOption("demo.net", "demo.net"),
				).
				Validate(func(str string) error {
					// Check if namespace exists
					fmt.Println(str)
					return nil
				}).
				Value(&namespace),
		),
	)

	return m, nil
}

func (m AttributeCreateModel) Init() tea.Cmd {
	return nil
}

func (m AttributeCreateModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		constants.WindowSize = msg
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		}
	}

	return m, nil
}

func (m AttributeCreateModel) View() string {
	return ""
}
