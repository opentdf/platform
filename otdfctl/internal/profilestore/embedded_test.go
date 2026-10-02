package profilestore

import (
	"encoding/json"
	"testing"

	"github.com/zalando/go-keyring"
)

type embeddedProfileCore struct {
	Name string `json:"profile"`
	Info struct {
		Value string `json:"value"`
	} `json:"info"`
}

type embeddedNamedProfile struct {
	embeddedProfileCore
	Label string `json:"label,omitempty"`
}

func (p *embeddedNamedProfile) GetName() string { return p.Name }

func TestUnexportedEmbeddedNamedProfileCreateUpdateAndCopy(t *testing.T) {
	keyring.MockInit()
	const ns = "embedded_named_profile"
	source, err := New(ns, WithKeyringStore())
	if err != nil {
		t.Fatal(err)
	}
	initial := &embeddedNamedProfile{embeddedProfileCore: embeddedProfileCore{Name: "alpha"}}
	initial.Info.Value = "created"
	if err := source.AddProfile(initial, true); err != nil {
		t.Fatal(err)
	}
	stored, err := keyring.Get(ns, "profile-alpha")
	if err != nil || !json.Valid([]byte(stored)) {
		t.Fatalf("invalid created profile: %s %v", stored, err)
	}
	var created map[string]json.RawMessage
	if err := json.Unmarshal([]byte(stored), &created); err != nil {
		t.Fatal(err)
	}
	if string(created["profile"]) != `"alpha"` || string(created["info"]) != `{"value":"created"}` {
		t.Fatalf("embedded core missing at creation: %s", stored)
	}
	if err := keyring.Set(ns, "profile-alpha", `{"profile":"alpha","info":{"value":"created","futureNested":true},"futureTop":42}`); err != nil {
		t.Fatal(err)
	}
	profile, err := GetProfile[*embeddedNamedProfile](source, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if unknown := profile.UnknownFields(); len(unknown) != 1 || string(unknown["futureTop"]) != `42` {
		t.Fatalf("embedded fields treated as unknown: %v", unknown)
	}
	core, ok := profile.Profile.(*embeddedNamedProfile)
	if !ok {
		t.Fatal("incorrect profile type")
	}
	core.Info.Value = "updated"
	if err := profile.Save(); err != nil {
		t.Fatal(err)
	}
	updated, err := keyring.Get(ns, "profile-alpha")
	if err != nil {
		t.Fatal(err)
	}
	var updatedFields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(updated), &updatedFields); err != nil {
		t.Fatal(err)
	}
	if string(updatedFields["info"]) != `{"futureNested":true,"value":"updated"}` {
		t.Fatalf("embedded nested unknown field lost on update: %s", updated)
	}
	destination, err := New(ns, WithFileStore(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	if err := destination.AddProfile(profile.Profile, true); err != nil {
		t.Fatal(err)
	}
	copied, err := GetCurrentProfile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.CopyUnknownTo(copied); err != nil {
		t.Fatal(err)
	}
	loaded, err := GetProfile[*embeddedNamedProfile](destination, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	result, ok := loaded.Profile.(*embeddedNamedProfile)
	if !ok {
		t.Fatal("incorrect migrated profile type")
	}
	if result.Name != "alpha" || result.Info.Value != "updated" || string(loaded.UnknownFields()["futureTop"]) != `42` {
		t.Fatalf("embedded migration lost fields: %+v %v", result, loaded.UnknownFields())
	}
	if err := loaded.Save(); err != nil {
		t.Fatal(err)
	}
	final, err := GetProfile[*embeddedNamedProfile](destination, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	finalCore, ok := final.Profile.(*embeddedNamedProfile)
	if !ok || finalCore.Info.Value != "updated" || string(final.UnknownFields()["futureTop"]) != `42` {
		t.Fatal("embedded update lost unknown field")
	}
}
