package profilestore

import (
	"encoding/json"
	"testing"

	"github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/store"
	"github.com/zalando/go-keyring"
)

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
