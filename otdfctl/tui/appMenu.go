//nolint:gocritic // still in development
package tui

import (
	"context"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/opentdf/otdfctl/pkg/handlers"
	"github.com/opentdf/otdfctl/tui/constants"
)

const (
	mainMenu menuState = iota
	namespaceMenu
	attributeMenu
	entitlementMenu
	resourceEncodingMenu
	subjectEncodingMenu
)

type menuState int

type AppMenuItem struct {
	id          menuState
	title       string
	description string
}

func (m AppMenuItem) FilterValue() string {
	return m.title
}

func (m AppMenuItem) Title() string {
	return m.title
}

func (m AppMenuItem) Description() string {
	return m.description
}

type AppMenu struct {
	list list.Model
	view tea.Model
	sdk  handlers.Handler
}

func InitAppMenu(h handlers.Handler) (AppMenu, tea.Cmd) {
	m := AppMenu{
		view: nil,
		sdk:  h,
	}
	//nolint:mnd // styling is magic
	m.list = list.New([]list.Item{}, list.NewDefaultDelegate(), 8, 8)
	m.list.Title = "OpenTDF"
	m.list.SetItems([]list.Item{
		// AppMenuItem{title: "Namespaces", description: "Manage namespaces", id: namespaceMenu},
		AppMenuItem{title: "Attributes", description: "Manage attributes", id: attributeMenu},
		// AppMenuItem{title: "Entitlements", description: "Manage entitlements", id: entitlementMenu},
		// AppMenuItem{title: "Resource Encodings", description: "Manage resource encodings", id: resourceEncodingMenu},
		// AppMenuItem{title: "Subject Encodings", description: "Manage subject encodings", id: subjectEncodingMenu},
	})
	return m, func() tea.Msg { return nil }
}

func (m AppMenu) Init() tea.Cmd {
	return nil
}

func (m AppMenu) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	ctx := context.Background()

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		constants.WindowSize = msg
		m.list.SetSize(msg.Width, msg.Height)
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "ctrl+d":
			return m, nil
		case "enter":
			switch m.list.SelectedItem().(AppMenuItem).id {
			// case namespaceMenu:
			// 	// get namespaces
			// 	nl, cmd := InitNamespaceList([]list.Item{}, 0)
			// 	return nl, cmd
			case attributeMenu:
				// list attributes
				al, cmd := InitAttributeList(ctx, "", m.sdk)
				return al, cmd
			}
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m AppMenu) View() string {
	return ViewList(m.list)
}
