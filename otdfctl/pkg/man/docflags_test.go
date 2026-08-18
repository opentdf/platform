package man

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDocFlagSensitiveParsing(t *testing.T) {
	doc, err := ProcessDoc(`---
title: Test Command
command:
  name: test
  flags:
    - name: wrapping-key
      sensitive: true
      description: A sensitive flag
    - name: algorithm
      description: A non-sensitive flag
---

Test doc body.
`)
	require.NoError(t, err)
	require.Len(t, doc.DocFlags, 2)

	wk := doc.GetDocFlag("wrapping-key")
	assert.True(t, wk.Sensitive)

	alg := doc.GetDocFlag("algorithm")
	assert.False(t, alg.Sensitive)
}

func TestMarkSensitiveFlags(t *testing.T) {
	doc, err := ProcessDoc(`---
title: Test Command
command:
  name: test
  flags:
    - name: wrapping-key
      sensitive: true
      description: Sensitive
    - name: name
      description: Not sensitive
---

Body.
`)
	require.NoError(t, err)

	doc.Flags().String("wrapping-key", "", "Sensitive")
	doc.Flags().String("name", "", "Not sensitive")

	doc.MarkSensitiveFlags()

	wkFlag := doc.Flags().Lookup("wrapping-key")
	require.NotNil(t, wkFlag)
	assert.Equal(t, []string{"true"}, wkFlag.Annotations[SensitiveAnnotationKey])

	nameFlag := doc.Flags().Lookup("name")
	require.NotNil(t, nameFlag)
	assert.Nil(t, nameFlag.Annotations)
}

func TestMarkSensitiveFlagsPanicsOnUnregistered(t *testing.T) {
	doc := &Doc{
		Command: cobra.Command{Use: "test"},
		DocFlags: []DocFlag{
			{Name: "missing-flag", Sensitive: true},
		},
	}

	assert.Panics(t, func() {
		doc.MarkSensitiveFlags()
	})
}

func TestAddStringFlag(t *testing.T) {
	doc, err := ProcessDoc(`---
title: Test Command
command:
  name: test
  flags:
    - name: workspace
      shorthand: w
      default: default-ws
      description: ID of the workspace
---

Body.
`)
	require.NoError(t, err)

	cmd := &cobra.Command{Use: "test"}
	doc.AddStringFlag(cmd, "workspace")

	f := cmd.Flags().Lookup("workspace")
	require.NotNil(t, f)
	assert.Equal(t, "w", f.Shorthand)
	assert.Equal(t, "default-ws", f.DefValue)
	assert.Equal(t, "ID of the workspace", f.Usage)
}

func TestAddStringFlagPanicsOnUnknown(t *testing.T) {
	doc := &Doc{Command: cobra.Command{Use: "test"}}
	assert.Panics(t, func() {
		doc.AddStringFlag(&cobra.Command{Use: "test"}, "missing")
	})
}

func TestDocFlagRequiredParsing(t *testing.T) {
	doc, err := ProcessDoc(`---
title: Test Command
command:
  name: test
  flags:
    - name: id
      required: true
      description: A required flag
    - name: label
      description: An optional flag
---

Body.
`)
	require.NoError(t, err)
	require.Len(t, doc.DocFlags, 2)

	assert.True(t, doc.GetDocFlag("id").Required)
	assert.False(t, doc.GetDocFlag("label").Required)

	doc.Flags().String("id", "", "Required")
	idFlag := doc.Flags().Lookup("id")
	require.NotNil(t, idFlag)
	assert.Nil(t, idFlag.Annotations[cobra.BashCompOneRequiredFlag])
}
