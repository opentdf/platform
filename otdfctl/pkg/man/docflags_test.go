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

func TestMarkSensitiveFlagsSkipsUnregistered(t *testing.T) {
	doc := &Doc{
		Command: cobra.Command{Use: "test"},
		DocFlags: []DocFlag{
			{Name: "missing-flag", Sensitive: true},
		},
	}

	// Should not panic even though the flag is not registered
	assert.NotPanics(t, func() {
		doc.MarkSensitiveFlags()
	})
}
