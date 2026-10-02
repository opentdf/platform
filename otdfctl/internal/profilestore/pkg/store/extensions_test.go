package store

import (
	"encoding/json"
	"errors"
	"testing"
)

type EmbeddedCore struct {
	Name string `json:"profile"`
	Info struct {
		Value string `json:"value,omitempty"`
	} `json:"info"`
}

type EmbeddedProfile struct {
	EmbeddedCore
	Other string `json:"other,omitempty"`
}

func TestMergeCoreEmbeddedFields(t *testing.T) {
	core := EmbeddedProfile{EmbeddedCore: EmbeddedCore{Name: "alpha"}}
	core.Info.Value = "new"
	old := map[string]json.RawMessage{
		"profile": json.RawMessage(`"old"`), "info": json.RawMessage(`{"value":"old","future":true}`),
		"other": json.RawMessage(`"omitted"`), "futureTop": json.RawMessage(`42`),
	}
	merged, err := MergeCore(old, core)
	if err != nil {
		t.Fatal(err)
	}
	if string(merged["profile"]) != `"alpha"` || string(merged["info"]) != `{"future":true,"value":"new"}` || string(merged["futureTop"]) != `42` {
		t.Fatalf("embedded core or unknown fields lost: %v", merged)
	}
	if _, present := merged["other"]; present {
		t.Fatal("omitted core field retained")
	}
	unknown := UnknownFields(merged, core)
	if len(unknown) != 1 || string(unknown["futureTop"]) != `42` {
		t.Fatalf("embedded core classified as unknown: %v", unknown)
	}
}

func TestCheckOpaqueConflicts(t *testing.T) {
	core := EmbeddedProfile{}
	for _, tc := range []struct {
		name        string
		source      map[string]json.RawMessage
		destination map[string]json.RawMessage
		conflict    bool
	}{
		{"unknown", map[string]json.RawMessage{"future": json.RawMessage(`1`)}, map[string]json.RawMessage{"future": json.RawMessage(`2`)}, true},
		{"namespace", map[string]json.RawMessage{"extensions": json.RawMessage(`{"owner":1}`)}, map[string]json.RawMessage{"extensions": json.RawMessage(`{"owner":2}`)}, true},
		{"same value", map[string]json.RawMessage{"future": json.RawMessage(`{"a": 1}`), "extensions": json.RawMessage(`{"owner":1}`)}, map[string]json.RawMessage{"future": json.RawMessage(`{"a":1}`), "extensions": json.RawMessage(`{"owner":1}`)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckOpaqueConflicts(tc.source, tc.destination, core)
			if errors.Is(err, ErrOpaqueConflict) != tc.conflict {
				t.Fatalf("conflict=%v: %v", tc.conflict, err)
			}
		})
	}
}
