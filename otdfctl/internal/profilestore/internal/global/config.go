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

type Store struct {
	store  store.Interface
	config Config
	object map[string]json.RawMessage
}

type Config struct {
	ProfilesVersion string   `json:"version"`
	Profiles        []string `json:"profiles"`
	DefaultProfile  string   `json:"defaultProfile"`
}

// LoadGlobalConfig loads the global configuration from the store for the given name of the configuration being stored.
// (i.e. if storing a config for example_app, then the configName should be "example_app")
func LoadGlobalConfig(configName string, newStore store.NewStoreInterface, driverOpts ...store.DriverOpt) (*Store, error) {
	underlyingStore, err := newStore(configName, STORE_KEY_GLOBAL, driverOpts...)
	if err != nil {
		return nil, err
	}

	p := &Store{
		store: underlyingStore,

		config: Config{
			Profiles:       make([]string, 0),
			DefaultProfile: "",
		},
	}

	if !p.store.Exists() {
		// set the version of the profiles to the latest version
		p.config.ProfilesVersion = PROFILES_VERSION_LATEST
		err = p.save()
		return p, err
	}

	data, err := p.store.Get()
	if err != nil {
		return nil, err
	}
	p.object, err = store.DecodeObject(data)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &p.config); err != nil {
		return nil, err
	}

	// check the version of the profiles
	if p.config.ProfilesVersion != PROFILES_VERSION_LATEST {
		// handle migration of the profiles
		// currently, there is no migration needed
		// so we just set the version to the latest version
		p.config.ProfilesVersion = PROFILES_VERSION_LATEST
		err = p.save()
		if err != nil {
			return nil, err
		}
	}

	return p, err
}

func HasGlobalStore(configName string, newStore store.NewStoreInterface, driverOpts ...store.DriverOpt) (bool, error) {
	store, err := newStore(configName, STORE_KEY_GLOBAL, driverOpts...)
	if err != nil {
		return false, err
	}

	return store.Exists(), nil
}

// Extensions returns opaque payloads; a missing member yields an empty map.
func (p *Store) Extensions() (map[string]json.RawMessage, error) {
	return store.Extensions(p.object)
}

// Extension returns a payload and its presence (including JSON null).
func (p *Store) Extension(namespace string) (json.RawMessage, bool, error) {
	return store.Extension(p.object, namespace)
}

// UnknownFields returns opaque top-level fields other than extensions.
func (p *Store) UnknownFields() map[string]json.RawMessage {
	return store.UnknownFields(p.object, p.config)
}

// CheckUnknownTo reports opaque fields or namespaces that migration would overwrite.
func (p *Store) CheckUnknownTo(destination *Store) error {
	return store.CheckOpaqueConflicts(p.object, destination.object, p.config)
}

// CopyUnknownTo transfers opaque top-level fields without changing core fields.
func (p *Store) CopyUnknownTo(destination *Store) error {
	if err := p.CheckUnknownTo(destination); err != nil {
		return err
	}
	unknown := p.UnknownFields()
	if len(unknown) == 0 {
		return nil
	}
	object := make(map[string]json.RawMessage, len(destination.object))
	for key, value := range destination.object {
		object[key] = value
	}
	for key, value := range unknown {
		object[key] = value
	}
	if err := destination.store.Set(object); err != nil {
		return err
	}
	destination.object = object
	return nil
}

// SetExtension persists one namespace without changing the remaining configuration.
func (p *Store) SetExtension(namespace string, payload json.RawMessage) error {
	if namespace == "" || len(payload) == 0 || !json.Valid(payload) {
		return store.ErrInvalidExtensions
	}
	data, err := p.store.Get()
	if err != nil {
		return err
	}
	latest, err := store.DecodeObject(data)
	if err != nil {
		return err
	}
	object, err := store.PutExtension(latest, namespace, payload)
	if err != nil {
		return err
	}
	if err := p.store.Set(object); err != nil {
		return err
	}
	p.object = object
	return nil
}

func (p *Store) ProfileExists(profileName string) bool {
	for _, profile := range p.config.Profiles {
		if profile == profileName {
			return true
		}
	}
	return false
}

func (p *Store) AddProfile(profileName string) error {
	p.config.Profiles = append(p.config.Profiles, profileName)
	return p.save()
}

func (p *Store) ListProfiles() []string {
	return p.config.Profiles
}

func (p *Store) RemoveProfile(profileName string) error {
	if profileName == p.config.DefaultProfile {
		return ErrDeletingDefaultProfile
	}
	return p.remove(profileName)
}

// RemoveProfileForce removes a profile from the global configuration without
// enforcing the default profile protection. This is intended for bulk delete operations
// where all profiles are being removed (e.g. DeleteAllProfiles).
func (p *Store) RemoveProfileForce(profileName string) error {
	if profileName == p.config.DefaultProfile {
		p.config.DefaultProfile = ""
	}

	return p.remove(profileName)
}

func (p *Store) SetDefaultProfile(profileName string) error {
	p.config.DefaultProfile = profileName
	return p.save()
}

func (p *Store) GetDefaultProfile() string {
	return p.config.DefaultProfile
}

// DeleteStore removes the persisted global configuration from the underlying store.
func (p *Store) DeleteStore() error {
	return p.store.Delete()
}

func (p *Store) remove(profileName string) error {
	for i, profile := range p.config.Profiles {
		if profile == profileName {
			p.config.Profiles = append(p.config.Profiles[:i], p.config.Profiles[i+1:]...)
			return p.save()
		}
	}

	return nil
}

func (p *Store) save() error {
	object, err := store.MergeCore(p.object, p.config)
	if err != nil {
		return err
	}
	if err := p.store.Set(object); err != nil {
		return err
	}
	p.object = object
	return nil
}
