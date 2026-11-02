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
func GetStoredProfile[T NamedProfile](store *ProfileStore) (T, error) {
	var profile T
	data, err := store.store.Get()
	if err != nil {
		return profile, err
	}
	err = json.Unmarshal(data, &profile)
	store.Profile = profile
	return profile, err
}

// Save the current profile data to the store
func (p *ProfileStore) Save() error {
	return p.store.Set(p.Profile)
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
