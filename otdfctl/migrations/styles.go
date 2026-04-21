package migrations

import "github.com/charmbracelet/lipgloss"

// migrationDisplayStyles holds all lipgloss styles for migration output.
type migrationDisplayStyles struct {
	styleTitle      lipgloss.Style
	styleResourceID lipgloss.Style
	styleNamespace  lipgloss.Style
	styleName       lipgloss.Style
	styleValue      lipgloss.Style
	styleID         lipgloss.Style
	styleWarning    lipgloss.Style
	styleInfo       lipgloss.Style
	styleSeparator  lipgloss.Style
	styleAction     lipgloss.Style
	separatorText   string
}

// initMigrationDisplayStyles initializes and returns a migrationDisplayStyles struct.
func initMigrationDisplayStyles() *migrationDisplayStyles {
	return &migrationDisplayStyles{
		styleTitle:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12")),
		styleResourceID: lipgloss.NewStyle().Foreground(lipgloss.Color("10")),
		styleNamespace:  lipgloss.NewStyle().Foreground(lipgloss.Color("11")),
		styleName:       lipgloss.NewStyle().Foreground(lipgloss.Color("13")),
		styleValue:      lipgloss.NewStyle().Foreground(lipgloss.Color("14")),
		styleID:         lipgloss.NewStyle().Foreground(lipgloss.Color("15")),
		styleWarning:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("9")),
		styleInfo:       lipgloss.NewStyle(),
		styleSeparator:  lipgloss.NewStyle().Faint(true),
		styleAction:     lipgloss.NewStyle().Foreground(lipgloss.Color("6")),
		separatorText:   "----------------------------------------------------------------------------------------------------",
	}
}
