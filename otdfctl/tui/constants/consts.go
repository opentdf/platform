package constants

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	P *tea.Program

	WindowSize struct {
		Width  int
		Height int
	}

	Magenta = lipgloss.Color("#EE6FF8")
)
