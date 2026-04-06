package tui

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/opentdf/otdfctl/pkg/handlers"
	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
)

type LabelUpdate struct {
	label  LabelItem
	update Update
	attr   *policy.Attribute
	sdk    handlers.Handler
}

func InitLabelUpdate(label LabelItem, attr *policy.Attribute, sdk handlers.Handler) LabelUpdate {
	return LabelUpdate{
		label:  label,
		update: InitUpdate([]string{"Key", "Value"}, []string{label.title, label.description}),
		attr:   attr,
		sdk:    sdk,
	}
}

func (m LabelUpdate) Init() tea.Cmd {
	return nil
}

func (m LabelUpdate) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	ctx := context.Background()

	if msg, ok := msg.(tea.KeyMsg); ok {
		switch msg.String() {
		case "enter":
			if m.update.focusIndex == len(m.update.inputs) {
				// update the label
				metadata := &common.MetadataMutable{Labels: m.attr.GetMetadata().GetLabels()}
				oldKey := m.label.title
				newKey := m.update.inputs[0].Value()
				newVal := m.update.inputs[1].Value()
				if oldKey != newKey {
					delete(metadata.GetLabels(), oldKey)
				}
				metadata.Labels[newKey] = newVal
				behavior := common.MetadataUpdateEnum_METADATA_UPDATE_ENUM_REPLACE
				// TODO: handle and return error view
				attr, _ := m.sdk.UpdateAttribute(ctx, m.attr.GetId(), metadata, behavior)
				return InitLabelList(attr, m.sdk)
			}
		}
	}
	update, cmd := m.update.Update(msg)
	m.update = update.(Update)
	return m, cmd
}

func (m LabelUpdate) View() string {
	return m.update.View()
}
