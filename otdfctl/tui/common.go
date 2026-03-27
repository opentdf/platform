package tui

import (
	"log"
	"os"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/opentdf/otdfctl/pkg/cli"
	"github.com/opentdf/otdfctl/pkg/handlers"
	"github.com/opentdf/otdfctl/tui/constants"
)

// StartTea the entry point for the UI. Initializes the model.
func StartTea(h handlers.Handler) error {
	if f, err := tea.LogToFile("debug.log", "help"); err != nil {
		cli.ExitWithError("Couldn't open a file for logging:", err)
		os.Exit(1)
	} else {
		defer func() {
			err = f.Close()
			if err != nil {
				log.Fatal(err)
			}
		}()
	}

	m, _ := InitAppMenu(h)
	constants.P = tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := constants.P.Run(); err != nil {
		cli.ExitWithError("Error running program:", err)
	}
	return nil
}

func ViewList(m list.Model) string {
	//nolint:mnd // styling is magic
	lipgloss.NewStyle().Padding(1, 2, 1, 2)
	return lipgloss.JoinVertical(lipgloss.Top, m.View())
}

func WindowMsg() tea.WindowSizeMsg {
	return tea.WindowSizeMsg{Width: constants.WindowSize.Width, Height: constants.WindowSize.Height}
}
