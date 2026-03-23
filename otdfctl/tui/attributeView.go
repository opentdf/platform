package tui

import (
	"context"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/opentdf/otdfctl/pkg/cli"
	"github.com/opentdf/otdfctl/pkg/handlers"
	"github.com/opentdf/otdfctl/tui/constants"
	"github.com/opentdf/platform/protocol/go/policy"
)

type AttributeSubItem struct {
	title       string
	description string
}

func (m AttributeSubItem) FilterValue() string {
	return m.title
}

func (m AttributeSubItem) Title() string {
	return m.title
}

func (m AttributeSubItem) Description() string {
	return m.description
}

type AttributeView struct {
	attr *policy.Attribute
	read Read
	sdk  handlers.Handler
}

func InitAttributeView(ctx context.Context, id string, h handlers.Handler) (AttributeView, tea.Cmd) {
	// TODO: handle and return error view
	attr, _ := h.GetAttribute(ctx, id)
	sa := cli.GetSimpleAttribute(attr)
	items := []list.Item{
		AttributeSubItem{title: "ID", description: sa.ID},
		AttributeSubItem{title: "Name", description: sa.Name},
		AttributeSubItem{title: "Rule", description: sa.Rule},
		AttributeSubItem{title: "Values", description: cli.CommaSeparated(sa.Values)},
		AttributeSubItem{title: "Namespace", description: sa.Namespace},
		AttributeSubItem{title: "Active", description: sa.Active},
		AttributeSubItem{title: "Labels", description: sa.Metadata["Labels"]},
		AttributeSubItem{title: "Created At", description: sa.Metadata["Created At"]},
		AttributeSubItem{title: "Updated At", description: sa.Metadata["Updated At"]},
	}
	model, _ := InitRead("Read Attribute", items)

	mod, _ := model.(Read)
	m := AttributeView{sdk: h, attr: attr, read: mod}
	model, msg := m.Update(WindowMsg())
	m = model.(AttributeView)
	return m, msg
}

func (m AttributeView) Init() tea.Cmd {
	return nil
}

func (m AttributeView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	ctx := context.Background()

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		constants.WindowSize = msg
		m.read.list.SetSize(msg.Width, msg.Height)
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "backspace":
			return InitAttributeList(ctx, m.attr.GetId(), m.sdk)
		case "ctrl+c", "q":
			return m, tea.Quit
		case "ctrl+d":
			return m, nil
		case "enter":
			if m.read.list.SelectedItem().(AttributeSubItem).title == "Labels" {
				return InitLabelList(m.attr, m.sdk)
			}
			// case "enter":
			// 	switch m.list.SelectedItem().(AttributeItem).id {
			// 	// case namespaceMenu:
			// 	// 	// get namespaces
			// 	// 	nl, cmd := InitNamespaceList([]list.Item{}, 0)
			// 	// 	return nl, cmd
			// 	case attributeMenu:
			// 		// list attributes
			// 		al, cmd := InitAttributeList("", m.sdk)
			// 		return al, cmd
			// 	}
		}
	}

	var cmd tea.Cmd
	m.read.list, cmd = m.read.list.Update(msg)
	return m, cmd
}

func (m AttributeView) View() string {
	return m.read.View()
}
