package cli

import (
	"github.com/charmbracelet/lipgloss"
)

func SuccessMessage(msg string) string {
	return lipgloss.JoinHorizontal(lipgloss.Left, styleSuccessStatusBar.Render("SUCCESS"), msg)
}

func FooterMessage(msg string) string {
	if msg == "" {
		return ""
	}
	w := lipgloss.Width
	note := footerLabelStyle.Render("NOTE")
	footer := footerTextStyle.Width(TermWidth() - w(note)).Render(msg)
	return lipgloss.JoinHorizontal(
		lipgloss.Left,
		note,
		footer,
	)
}

func DebugMessage(msg string) string {
	return lipgloss.JoinHorizontal(lipgloss.Left, styleDebugStatusBar.Render("DEBUG"), msg)
}

func ErrorMessage(msg string, err error) string {
	if err != nil {
		msg += ": " + err.Error()
	}
	return lipgloss.JoinHorizontal(lipgloss.Left, styleErrorStatusBar.Render("ERROR"), msg)
}

func WarningMessage(msg string) string {
	return lipgloss.JoinHorizontal(lipgloss.Left, styleWarningStatusBar.Render("WARNING"), msg)
}
