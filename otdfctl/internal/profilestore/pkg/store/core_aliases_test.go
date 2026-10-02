package store

import (
	"encoding/json"
	"errors"
	"testing"
)

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
