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

type unexportedCore struct {
	Name   string `json:"profile"`
	Hidden string `json:"-"`
}

type pointerEmbeddedProfile struct {
	*unexportedCore
	private string
}

func TestUnexportedAnonymousPointerCoreFields(t *testing.T) {
	core := pointerEmbeddedProfile{unexportedCore: &unexportedCore{Name: "alpha", Hidden: "not stored"}, private: "private"}
	old := map[string]json.RawMessage{
		"profile":    json.RawMessage(`"old"`),
		core.private: json.RawMessage(`"opaque"`),
		"future":     json.RawMessage(`42`),
	}
	merged, err := MergeCore(old, core)
	if err != nil {
		t.Fatal(err)
	}
	if string(merged["profile"]) != `"alpha"` || string(merged["private"]) != `"opaque"` || string(merged["future"]) != `42` {
		t.Fatalf("pointer core or opaque fields lost: %v", merged)
	}
	unknown := UnknownFields(merged, core)
	if len(unknown) != 2 || string(unknown["private"]) != `"opaque"` || string(unknown["future"]) != `42` {
		t.Fatalf("wrong pointer core ownership: %v", unknown)
	}
	if err := CheckOpaqueConflicts(merged, map[string]json.RawMessage{"profile": json.RawMessage(`"destination"`), "private": json.RawMessage(`"opaque"`), "future": json.RawMessage(`42`)}, core); err != nil {
		t.Fatalf("migration treated pointer core as opaque: %v", err)
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

func TestMergeCoreCanonicalizesAliasesAndPreservesUnknown(t *testing.T) {
	core := EmbeddedProfile{EmbeddedCore: EmbeddedCore{Name: "alpha"}}
	core.Info.Value = "new"
	old, err := DecodeObject([]byte(`{"PROFILE":"old","INFO":{"VALUE":"old","future":true},"info":{"otherFuture":42},"OTHER":"omitted","futureTop":1}`))
	if err != nil {
		t.Fatal(err)
	}
	merged, err := MergeCore(old, core)
	if err != nil {
		t.Fatal(err)
	}
	if string(merged["profile"]) != `"alpha"` || string(merged["info"]) != `{"future":true,"otherFuture":42,"value":"new"}` {
		t.Fatalf("core update or unknown aliases lost: %v", merged)
	}
	for _, alias := range []string{"PROFILE", "INFO", "OTHER"} {
		if _, present := merged[alias]; present {
			t.Fatalf("core alias %q retained", alias)
		}
	}
	unknown := UnknownFields(old, core)
	if len(unknown) != 1 || string(unknown["futureTop"]) != `1` {
		t.Fatalf("aliases classified as unknown: %v", unknown)
	}
}

func TestMergeCoreRejectsConflictingUnknownAliasesWithoutMutation(t *testing.T) {
	old, err := DecodeObject([]byte(`{"info":{"future":1},"INFO":{"future":2}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MergeCore(old, EmbeddedProfile{}); !errors.Is(err, ErrOpaqueConflict) {
		t.Fatalf("conflicting aliases accepted: %v", err)
	}
	if string(old["info"]) != `{"future":1}` || string(old["INFO"]) != `{"future":2}` {
		t.Fatalf("source mutated: %v", old)
	}
}

func TestMergeUnknownNestedRecognizesCoreAliases(t *testing.T) {
	source := map[string]json.RawMessage{"INFO": json.RawMessage(`{"VALUE":"source","future":1}`)}
	destination := map[string]json.RawMessage{"info": json.RawMessage(`{"value":"destination"}`)}
	merged, err := MergeUnknownNested(source, destination, EmbeddedProfile{})
	if err != nil {
		t.Fatal(err)
	}
	if string(merged["info"]) != `{"future":1,"value":"destination"}` {
		t.Fatalf("unknown aliases lost or core overwritten: %v", merged)
	}
	destination["info"] = json.RawMessage(`{"value":"destination","future":2}`)
	if err := CheckOpaqueConflicts(source, destination, EmbeddedProfile{}); !errors.Is(err, ErrOpaqueConflict) {
		t.Fatalf("aliased nested conflict missed: %v", err)
	}
}
