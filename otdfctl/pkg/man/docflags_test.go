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

func TestMarkRequiredFlags(t *testing.T) {
	doc, err := ProcessDoc(`---
title: Test Command
command:
  name: test
  flags:
    - name: id
      required: true
      description: Required
    - name: label
      description: Optional
---

Body.
`)
	require.NoError(t, err)

	doc.Flags().String("id", "", "Required")
	doc.Flags().String("label", "", "Optional")

	doc.MarkRequiredFlags()

	idFlag := doc.Flags().Lookup("id")
	require.NotNil(t, idFlag)
	assert.Equal(t, []string{"true"}, idFlag.Annotations[cobra.BashCompOneRequiredFlag])

	labelFlag := doc.Flags().Lookup("label")
	require.NotNil(t, labelFlag)
	assert.Nil(t, labelFlag.Annotations[cobra.BashCompOneRequiredFlag])
}

// Unlike MarkSensitiveFlags, a required flag declared in the doc but not
// registered on the command is skipped rather than panicking, so the registry
// sweep can safely visit parent/index docs and unbuilt commands.
func TestMarkRequiredFlagsSkipsUnregistered(t *testing.T) {
	doc := &Doc{
		Command: cobra.Command{Use: "test"},
		DocFlags: []DocFlag{
			{Name: "missing-flag", Required: true},
		},
	}

	assert.NotPanics(t, func() {
		doc.MarkRequiredFlags()
	})
}

func TestManualMarkRequiredFlags(t *testing.T) {
	withReq, err := ProcessDoc(`---
title: With Required
command:
  name: with-required
  flags:
    - name: id
      required: true
      description: Required
---

Body.
`)
	require.NoError(t, err)
	withReq.Flags().String("id", "", "Required")

	withoutReq, err := ProcessDoc(`---
title: Without Required
command:
  name: without-required
  flags:
    - name: label
      description: Optional
---

Body.
`)
	require.NoError(t, err)
	withoutReq.Flags().String("label", "", "Optional")

	m := Manual{En: map[string]*Doc{
		"with-required":    withReq,
		"without-required": withoutReq,
	}}

	m.MarkRequiredFlags()

	idFlag := withReq.Flags().Lookup("id")
	require.NotNil(t, idFlag)
	assert.Equal(t, []string{"true"}, idFlag.Annotations[cobra.BashCompOneRequiredFlag])

	labelFlag := withoutReq.Flags().Lookup("label")
	require.NotNil(t, labelFlag)
	assert.Nil(t, labelFlag.Annotations[cobra.BashCompOneRequiredFlag])
}
