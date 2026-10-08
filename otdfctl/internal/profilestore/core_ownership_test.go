package profilestore

import (
	"encoding/json"
	"testing"

	"github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/store"
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

type exactCaseFields struct {
	Lower string `json:"value"`
	Upper string `json:"VALUE"`
}

type exactCaseProfile struct {
	Name  string          `json:"profile"`
	Lower string          `json:"foo"`
	Upper string          `json:"FOO"`
	Info  exactCaseFields `json:"info"`
	INFO  exactCaseFields `json:"INFO"`
}

func (p *exactCaseProfile) GetName() string { return p.Name }

func TestExactCaseCoreFieldsCreateSaveAndCopyAcrossDrivers(t *testing.T) {
	for _, driver := range []string{"file", "keyring"} {
		t.Run(driver, func(t *testing.T) {
			keyring.MockInit()
			const namespace = "core_case_priority"
			option := WithKeyringStore()
			newStore := store.NewKeyringStore
			if driver == "file" {
				option = WithFileStore(t.TempDir())
				newStore = store.NewFileStore
			}
			profiler, err := New(namespace, option)
			if err != nil {
				t.Fatal(err)
			}
			initial := exactCaseProfile{
				Name: "alpha", Lower: "lower", Upper: "upper",
				Info: exactCaseFields{Lower: "info-lower", Upper: "info-upper"},
				INFO: exactCaseFields{Lower: "INFO-lower", Upper: "INFO-upper"},
			}
			if err := profiler.AddProfile(&initial, true); err != nil {
				t.Fatal(err)
			}
			profile, err := GetProfile[*exactCaseProfile](profiler, "alpha")
			if err != nil {
				t.Fatal(err)
			}
			core, ok := profile.Profile.(*exactCaseProfile)
			if !ok || *core != initial {
				t.Fatal("creation lost distinct exact-case core fields")
			}
			rawStore, err := newStore(namespace, "profile-alpha")
			if err != nil {
				t.Fatal(err)
			}
			// The same opaque name can hold different values under distinct exact
			// core parents. They are not aliases and must not conflict or mix.
			if err := rawStore.Set(json.RawMessage(`{"profile":"alpha","foo":"lower","FOO":"upper","FoO":"stale-alias","info":{"value":"info-lower","VALUE":"info-upper","future":1},"INFO":{"value":"INFO-lower","VALUE":"INFO-upper","future":2},"InFo":{"futureAlias":3}}`)); err != nil {
				t.Fatal(err)
			}
			core.Lower, core.Upper = "new-lower", "new-upper"
			core.Info.Lower, core.Info.Upper = "new-info-lower", "new-info-upper"
			core.INFO.Lower, core.INFO.Upper = "new-INFO-lower", "new-INFO-upper"
			expected := *core
			if err := profile.Save(); err != nil {
				t.Fatal(err)
			}
			reloaded, err := GetProfile[*exactCaseProfile](profiler, "alpha")
			if err != nil {
				t.Fatal(err)
			}
			updated, ok := reloaded.Profile.(*exactCaseProfile)
			if !ok || *updated != expected {
				t.Fatal("save lost distinct exact-case core fields")
			}
			destination, err := New(namespace+"_copy", WithFileStore(t.TempDir()))
			if err != nil {
				t.Fatal(err)
			}
			if err := destination.AddProfile(updated, true); err != nil {
				t.Fatal(err)
			}
			copied, err := GetProfile[*exactCaseProfile](destination, "alpha")
			if err != nil {
				t.Fatal(err)
			}
			if err := reloaded.CopyUnknownTo(copied); err != nil {
				t.Fatal(err)
			}
			for _, test := range []struct {
				name      string
				want      string
				wantAlias string
			}{{"info", `1`, `3`}, {"INFO", `2`, ""}} {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(copied.object[test.name], &fields); err != nil {
					t.Fatal(err)
				}
				if string(fields["future"]) != test.want || string(fields["futureAlias"]) != test.wantAlias {
					t.Fatalf("unknown fields crossed distinct exact parent %q", test.name)
				}
			}
		})
	}
}
