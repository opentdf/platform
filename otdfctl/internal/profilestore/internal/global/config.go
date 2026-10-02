package global

import (
	"encoding/json"

	"github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/store"
)

// Define constants for the different storage drivers and store keys
const (
	PROFILE_DRIVER_KEYRING   ProfileDriver = "keyring"
	PROFILE_DRIVER_IN_MEMORY ProfileDriver = "in-memory"
	PROFILE_DRIVER_FILE      ProfileDriver = "file"
	// Experimental: enables definition of custom storage driver
	PROFILE_DRIVER_CUSTOM  ProfileDriver = "custom"
	PROFILE_DRIVER_DEFAULT               = PROFILE_DRIVER_FILE
	STORE_KEY_PROFILE                    = "profile"
	STORE_KEY_GLOBAL                     = "global"
)

type ProfileDriver string

// This variable is used to store the version of the profiles. Since the profiles structure might
// change in the future, this variable is used to keep track of the version of the profiles and will
// be used to determine how to handle migration of the profiles.
const PROFILES_VERSION_v1_0 = "1.0"

const PROFILES_VERSION_LATEST = PROFILES_VERSION_v1_0

type GlobalStore struct {
	store  store.StoreInterface
	config GlobalConfig
}

type GlobalConfig struct {
	ProfilesVersion string   `json:"version"`
	Profiles        []string `json:"profiles"`
	DefaultProfile  string   `json:"defaultProfile"`
}

// LoadGlobalConfig loads the global configuration from the store for the given name of the configuration being stored.
// (i.e. if storing a config for example_app, then the configName should be "example_app")
func LoadGlobalConfig(configName string, newStore store.NewStoreInterface, driverOpts ...store.DriverOpt) (*GlobalStore, error) {
	store, err := newStore(configName, STORE_KEY_GLOBAL, driverOpts...)
	if err != nil {
		return nil, err
	}

	p := &GlobalStore{
		store: store,

		config: GlobalConfig{
			Profiles:       make([]string, 0),
			DefaultProfile: "",
		},
	}

	if p.store.Exists() {
		data, err := p.store.Get()
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(data, &p.config)
		if err != nil {
			return nil, err
		}

		// check the version of the profiles
		if p.config.ProfilesVersion != PROFILES_VERSION_LATEST {
			// handle migration of the profiles
			// currently, there is no migration needed
			// so we just set the version to the latest version
			p.config.ProfilesVersion = PROFILES_VERSION_LATEST
			err = p.store.Set(p.config)
			if err != nil {
				return nil, err
			}
		}

		return p, err
	}

	// set the version of the profiles to the latest version
	p.config.ProfilesVersion = PROFILES_VERSION_LATEST
	err = p.store.Set(p.config)
	return p, err
}

func HasGlobalStore(configName string, newStore store.NewStoreInterface, driverOpts ...store.DriverOpt) (bool, error) {
	store, err := newStore(configName, STORE_KEY_GLOBAL, driverOpts...)
	if err != nil {
		return false, err
	}

	return store.Exists(), nil
}

func (p *GlobalStore) ProfileExists(profileName string) bool {
	for _, profile := range p.config.Profiles {
		if profile == profileName {
			return true
		}
	}
	return false
}

func (p *GlobalStore) AddProfile(profileName string) error {
	p.config.Profiles = append(p.config.Profiles, profileName)
	return p.store.Set(p.config)
}

func (p *GlobalStore) ListProfiles() []string {
	return p.config.Profiles
}

func (p *GlobalStore) RemoveProfile(profileName string) error {
	if profileName == p.config.DefaultProfile {
		return ErrDeletingDefaultProfile
	}
	return p.remove(profileName)
}

// RemoveProfileForce removes a profile from the global configuration without
// enforcing the default profile protection. This is intended for bulk delete operations
// where all profiles are being removed (e.g. DeleteAllProfiles).
func (p *GlobalStore) RemoveProfileForce(profileName string) error {
	if profileName == p.config.DefaultProfile {
		p.config.DefaultProfile = ""
	}

	return p.remove(profileName)
}

func (p *GlobalStore) remove(profileName string) error {
	for i, profile := range p.config.Profiles {
		if profile == profileName {
			p.config.Profiles = append(p.config.Profiles[:i], p.config.Profiles[i+1:]...)
			return p.store.Set(p.config)
		}
	}

	return nil
}

func (p *GlobalStore) SetDefaultProfile(profileName string) error {
	p.config.DefaultProfile = profileName
	return p.store.Set(p.config)
}

func (p *GlobalStore) GetDefaultProfile() string {
	return p.config.DefaultProfile
}

// DeleteStore removes the persisted global configuration from the underlying store.
func (p *GlobalStore) DeleteStore() error {
	return p.store.Delete()
}
