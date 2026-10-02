package profilestore

import (
	"encoding/json"

	"github.com/opentdf/platform/otdfctl/internal/profilestore/internal/global"
	"github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/store"
)

type ProfileStore struct {
	// Store is the specific initialized driver that satisfies the Interface.
	store store.Interface
	// Profile is the struct that holds the profile data and satisfies the NamedProfile interface.
	// Exported to allow write/read access to the profile data being stored.
	Profile NamedProfile
	object  map[string]json.RawMessage
}

// NamedProfile is the holder of a profile containing a name and all stored profile data.
// It is marshaled on Get and unmarshaled on Set, so an interface is used to allow
// for any struct to be stored. The struct satisfying the interface must have JSON tags
// for each stored field.
//
// Example:
//
//	type MyProfile struct {
//		 Name string `json:"name"`
//		 Email string `json:"email"`
//	}
//
//	func (p *MyProfile) GetName() string {
//	 return p.Name
//	}
type NamedProfile interface {
	GetName() string
}

func NewProfileStore(serviceNamespace string, newStore store.NewStoreInterface, profile NamedProfile) (*ProfileStore, error) {
	profileName := profile.GetName()

	if err := validateProfileName(profileName); err != nil {
		return nil, err
	}

	store, err := newStore(serviceNamespace, getStoreKey(profileName))
	if err != nil {
		return nil, err
	}

	p := &ProfileStore{
		store:   store,
		Profile: profile,
	}
	return p, nil
}

func LoadProfileStore[T NamedProfile](serviceNamespace string, newStore store.NewStoreInterface, profileName string) (*ProfileStore, error) {
	if err := validateProfileName(profileName); err != nil {
		return nil, err
	}

	store, err := newStore(serviceNamespace, getStoreKey(profileName))
	if err != nil {
		return nil, err
	}

	p := &ProfileStore{
		store: store,
	}
	_, err = GetStoredProfile[T](p)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Generic wrapper for working with specific types
func GetStoredProfile[T NamedProfile](profileStore *ProfileStore) (T, error) {
	var profile T
	data, err := profileStore.store.Get()
	if err != nil {
		return profile, err
	}
	object, err := store.DecodeObject(data)
	if err != nil {
		return profile, err
	}
	if err := json.Unmarshal(data, &profile); err != nil {
		return profile, err
	}
	profileStore.object = object
	profileStore.Profile = profile
	return profile, nil
}

// Save the current profile data to the store
func (p *ProfileStore) Save() error {
	object, err := store.MergeCore(p.object, p.Profile)
	if err != nil {
		return err
	}
	if err := p.store.Set(object); err != nil {
		return err
	}
	p.object = object
	return nil
}

// Extensions returns opaque payloads; missing extensions are represented by an empty map.
func (p *ProfileStore) Extensions() (map[string]json.RawMessage, error) {
	return store.Extensions(p.object)
}

func (p *ProfileStore) Extension(namespace string) (json.RawMessage, bool, error) {
	return store.Extension(p.object, namespace)
}

// UnknownFields returns opaque top-level fields other than extensions.
func (p *ProfileStore) UnknownFields() map[string]json.RawMessage {
	return store.UnknownFields(p.object, p.Profile)
}

// CheckUnknownTo reports opaque fields or namespaces that migration would overwrite.
func (p *ProfileStore) CheckUnknownTo(destination *ProfileStore) error {
	return store.CheckOpaqueConflicts(p.object, destination.object, p.Profile)
}

// CopyUnknownTo transfers opaque top-level members without changing core fields.
func (p *ProfileStore) CopyUnknownTo(destination *ProfileStore) error {
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

func (p *ProfileStore) SetExtension(namespace string, payload json.RawMessage) error {
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

// Delete the current profile from the store
func (p *ProfileStore) Delete() error {
	return p.store.Delete()
}

// Profile Name
func (p *ProfileStore) GetProfileName() string {
	return p.Profile.GetName()
}

// utility functions

func getStoreKey(n string) string {
	return global.STORE_KEY_PROFILE + "-" + n
}
