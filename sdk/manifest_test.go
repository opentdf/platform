package sdk

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEffectiveTDFVersionPriority(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{"schemaVersion wins", `{"schemaVersion":"4.3.0","tdf_spec_version":"9.9.9","payload":{"tdf_spec_version":"8.8.8"}}`, "4.3.0"},
		{"then top-level tdf_spec_version", `{"tdf_spec_version":"9.9.9","payload":{"tdf_spec_version":"8.8.8"}}`, "9.9.9"},
		{"then payload.tdf_spec_version", `{"payload":{"tdf_spec_version":"8.8.8"}}`, "8.8.8"},
		{"none is legacy", `{"payload":{}}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var m Manifest
			require.NoError(t, json.Unmarshal([]byte(c.json), &m))
			assert.Equal(t, c.want, m.EffectiveTDFVersion())
		})
	}
}

func TestTDFSpecVersionNeverWrittenByDefault(t *testing.T) {
	m := Manifest{TDFVersion: TDFSpecVersion}
	out, err := json.Marshal(m)
	require.NoError(t, err)
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(out, &raw))
	_, has := raw["tdf_spec_version"]
	assert.False(t, has)
	var payload map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw["payload"], &payload))
	_, has = payload["tdf_spec_version"]
	assert.False(t, has)
	assert.Contains(t, string(out), `"schemaVersion":"4.3.0"`)
}
