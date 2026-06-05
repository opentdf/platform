package migrations

import "github.com/charmbracelet/lipgloss"

// DisplayStyles holds all lipgloss styles for migration output.
type DisplayStyles struct {
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

// NewDisplayStyles initializes and returns migration display styles.
func NewDisplayStyles() *DisplayStyles {
	return &DisplayStyles{
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

func (s *DisplayStyles) Title() lipgloss.Style {
	return s.styleTitle
}

func (s *DisplayStyles) ResourceID() lipgloss.Style {
	return s.styleResourceID
}

func (s *DisplayStyles) Namespace() lipgloss.Style {
	return s.styleNamespace
}

func (s *DisplayStyles) Name() lipgloss.Style {
	return s.styleName
}

func (s *DisplayStyles) Value() lipgloss.Style {
	return s.styleValue
}

func (s *DisplayStyles) ID() lipgloss.Style {
	return s.styleID
}

func (s *DisplayStyles) Warning() lipgloss.Style {
	return s.styleWarning
}

func (s *DisplayStyles) Info() lipgloss.Style {
	return s.styleInfo
}

func (s *DisplayStyles) Separator() lipgloss.Style {
	return s.styleSeparator
}

func (s *DisplayStyles) Action() lipgloss.Style {
	return s.styleAction
}

func (s *DisplayStyles) SeparatorText() string {
	return s.separatorText
}
