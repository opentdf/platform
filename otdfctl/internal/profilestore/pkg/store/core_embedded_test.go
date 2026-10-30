package store

import (
	"encoding/json"
	"testing"
)

type embeddedCredentials struct {
	Secret string `json:"secret,omitempty"`
}

type taggedEmbeddedProfile struct {
	embeddedCredentials `json:"credentials"`
	Name                string `json:"profile"`
}

type recursiveEmbeddedProfile struct {
	*recursiveEmbeddedProfile
	Name string `json:"profile"`
	Auth struct {
		Secret string `json:"secret,omitempty"`
	} `json:"auth"`
}

func TestRecursiveAnonymousPointerCoreOwnership(t *testing.T) {
	core := recursiveEmbeddedProfile{recursiveEmbeddedProfile: &recursiveEmbeddedProfile{}, Name: "alpha"}
	old, err := DecodeObject([]byte(`{"PROFILE":"old","auth":{"secret":"old-secret","future":true},"futureTop":42}`))
	if err != nil {
		t.Fatal(err)
	}
	merged, err := MergeCore(old, core)
	if err != nil {
		t.Fatal(err)
	}
	if string(merged["profile"]) != `"alpha"` || string(merged["auth"]) != `{"future":true}` {
		t.Fatalf("recursive core not updated: %v", merged)
	}
	unknown := UnknownFields(old, core)
	if len(unknown) != 1 || string(unknown["futureTop"]) != `42` {
		t.Fatalf("recursive ownership incorrect: %v", unknown)
	}
	if err := CheckOpaqueConflicts(old, merged, core); err != nil {
		t.Fatalf("recursive conflict check failed: %v", err)
	}
	transferred, err := MergeUnknownNested(old, map[string]json.RawMessage{"auth": json.RawMessage(`{"secret":"destination"}`)}, core)
	if err != nil || string(transferred["auth"]) != `{"future":true,"secret":"destination"}` {
		t.Fatalf("recursive nested transfer failed: %v %v", transferred, err)
	}
}

func TestTaggedUnexportedEmbeddedCoreOwnership(t *testing.T) {
	old, err := DecodeObject([]byte(`{"profile":"old","CREDENTIALS":{"SECRET":"old-secret","future":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	core := taggedEmbeddedProfile{Name: "alpha"}
	merged, err := MergeCore(old, core)
	if err != nil {
		t.Fatal(err)
	}
	if string(merged["credentials"]) != `{"future":true}` {
		t.Fatalf("credential clearing or unknown preservation failed: %s", merged["credentials"])
	}
	if _, ok := merged["CREDENTIALS"]; ok {
		t.Fatal("old credential alias retained")
	}
	if unknown := UnknownFields(old, core); len(unknown) != 0 {
		t.Fatalf("core credentials classified as opaque: %v", unknown)
	}
	destination := map[string]json.RawMessage{"credentials": json.RawMessage(`{"secret":"destination"}`)}
	transferred, err := MergeUnknownNested(old, destination, core)
	if err != nil {
		t.Fatal(err)
	}
	if string(transferred["credentials"]) != `{"future":true,"secret":"destination"}` {
		t.Fatalf("nested opaque field not transferred: %s", transferred["credentials"])
	}
	core.Secret = "new-secret"
	merged, err = MergeCore(old, core)
	if err != nil || string(merged["credentials"]) != `{"future":true,"secret":"new-secret"}` {
		t.Fatalf("credential update or unknown preservation failed: %s %v", merged["credentials"], err)
	}
}
