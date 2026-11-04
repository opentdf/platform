//nolint:testableexamples // Compile-only: running this example would write to the user's OS credential store.
package profilestore_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/opentdf/platform/otdfctl/pkg/profilestore"
)

type applicationProfile struct {
	Name         string `json:"profile"`
	RefreshToken string `json:"refreshToken"`
}

func (p *applicationProfile) GetName() string { return p.Name }

// This example is compiled but not run: the filesystem driver requires a real
// OS credential store. Unit tests use the keyring mock instead.
func ExampleNew() {
	configDir, err := os.UserConfigDir()
	if err != nil {
		log.Fatal(err)
	}
	p, err := profilestore.New("example_app", profilestore.WithFileStore(filepath.Join(configDir, "example_app")))
	if err != nil {
		log.Fatal(err)
	}
	const name = "personal"
	if !profilestore.GetGlobalConfig(p).ProfileExists(name) {
		if err := p.AddProfile(&applicationProfile{Name: name}, true); err != nil {
			log.Fatal(err)
		}
	}
	stored, err := profilestore.GetProfile[*applicationProfile](p, name)
	if err != nil {
		log.Fatal(err)
	}
	profile, err := profilestore.GetStoredProfile[*applicationProfile](stored)
	if err != nil {
		log.Fatal(err)
	}
	profile.RefreshToken = "replace-with-token-from-your-authentication-flow"
	if err := stored.Save(); err != nil {
		log.Fatal(err)
	}
	fmt.Println("Profile saved")
}
