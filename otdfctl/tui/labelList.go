package tui

import (
	"context"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/opentdf/otdfctl/pkg/handlers"
	"github.com/opentdf/otdfctl/tui/constants"
	"github.com/opentdf/platform/protocol/go/policy"
)

type LabelList struct {
	attr *policy.Attribute
	sdk  handlers.Handler
	read Read
}

type LabelItem struct {
	title       string
	description string
}

func (m LabelItem) FilterValue() string {
	return m.title
}

func (m LabelItem) Title() string {
	return m.title
}

func (m LabelItem) Description() string {
	return m.description
}

func InitLabelList(attr *policy.Attribute, sdk handlers.Handler) (tea.Model, tea.Cmd) {
	labels := attr.GetMetadata().GetLabels()
	var items []list.Item
	for k, v := range labels {
		item := LabelItem{
			title:       k,
			description: v,
		}
		items = append(items, item)
	}
	model, _ := InitRead("Read Labels", items)
	// TODO: handle and return error view
	mod, _ := model.(Read)
	return LabelList{attr: attr, sdk: sdk, read: mod}, nil
}

func (m LabelList) Init() tea.Cmd {
	return nil
}

func (m LabelList) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	ctx := context.Background()

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		constants.WindowSize = msg
		m.read.list.SetSize(msg.Width, msg.Height)
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "backspace":
			return InitAttributeView(ctx, m.attr.GetId(), m.sdk)
		case "ctrl+c", "q", "esc":
			return m, tea.Quit
		case "enter", "e":
			return InitLabelUpdate(m.read.list.Items()[m.read.list.Index()].(LabelItem), m.attr, m.sdk), nil
		case "c":
			return InitLabelUpdate(LabelItem{}, m.attr, m.sdk), nil
		case "d":
			// delete label
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.read.list, cmd = m.read.list.Update(msg)
	return m, cmd
}

func (m LabelList) View() string {
	return ViewList(m.read.list)
}
