package store

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestSameJSON(t *testing.T) {
	for _, tc := range []struct {
		name, a, b string
		equal      bool
	}{
		{"object order", `{"a":1,"b":{"x":2,"y":3}}`, `{"b":{"y":3,"x":2},"a":1}`, true},
		{"escaping", `{"text":"<a>&"}`, `{"text":"\u003ca\u003e\u0026"}`, true},
		{"large integer", `9007199254740993`, `9007199254740992`, false},
		{"numeric representation", `1`, `1.0`, false},
		{"array order", `[1,2]`, `[2,1]`, false},
		{"null", `null`, `null`, true},
		{"invalid", ``, `null`, false},
		{"trailing value", `{} {}`, `{}`, false},
		{"trailing garbage", `{}x`, `{}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameJSON(json.RawMessage(tc.a), json.RawMessage(tc.b)); got != tc.equal {
				t.Fatalf("sameJSON() = %v, want %v", got, tc.equal)
			}
		})
	}
}

func TestCheckOpaqueConflictsSemanticJSON(t *testing.T) {
	core := EmbeddedProfile{}
	source, err := DecodeObject([]byte(`{"future":{"a":1,"b":2},"extensions":{"owner":{"a":1,"b":2}},"info":{"future":{"text":"<a>&"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	destination, err := DecodeObject([]byte(`{"future":{"b":2,"a":1},"extensions":{"owner":{"b":2,"a":1}},"INFO":{"future":{"text":"\u003ca\u003e\u0026"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckOpaqueConflicts(source, destination, core); err != nil {
		t.Fatalf("equivalent opaque data rejected: %v", err)
	}
	old, err := DecodeObject([]byte(`{"info":{"future":{"text":"<a>&"}},"INFO":{"future":{"text":"\u003ca\u003e\u0026"}}}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := MergeCore(old, core); err != nil {
		t.Fatalf("equivalent aliases rejected: %v", err)
	}
	destination["future"] = json.RawMessage(`{"a":2,"b":2}`)
	if err := CheckOpaqueConflicts(source, destination, core); !errors.Is(err, ErrOpaqueConflict) {
		t.Fatalf("different opaque data accepted: %v", err)
	}
}
