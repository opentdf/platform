package profiles

import (
	osprofiles "github.com/opentdf/platform/otdfctl/internal/profilestore"
	"github.com/opentdf/platform/otdfctl/pkg/utils"
)

// Profiler names the existing engine returned by CreateProfiler and NewProfiler.
// Consumers can retain it in typed fields without importing the internal engine.
// Constructors initialize missing global configuration and may upgrade its version;
// they are not read-only inspection APIs. These facade operations never migrate drivers.
type Profiler = osprofiles.Profiler

var (
	ErrInvalidProfiler     = osprofiles.ErrInvalidProfiler
	ErrProfileNameConflict = osprofiles.ErrProfileNameConflict
	ErrMissingProfileName  = osprofiles.ErrMissingProfileName
)

func checkProfiler(profiler *Profiler) error {
	if profiler == nil || osprofiles.GetGlobalConfig(profiler) == nil {
		return ErrInvalidProfiler
	}
	return nil
}

// ListProfiles returns a detached inventory from an initialized profiler's cached
// global configuration. It does not write or refresh configuration from storage.
func ListProfiles(profiler *Profiler) ([]string, error) {
	if err := checkProfiler(profiler); err != nil {
		return nil, err
	}
	return append([]string{}, osprofiles.ListProfiles(profiler)...), nil
}

// GetDefault returns the cached default name, including an intentionally empty
// default, without selecting a profile or writing configuration.
func GetDefault(profiler *Profiler) (string, error) {
	if err := checkProfiler(profiler); err != nil {
		return "", err
	}
	return osprofiles.GetGlobalConfig(profiler).GetDefaultProfile(), nil
}

// SetDefault explicitly selects a registered profile. Missing names and storage
// errors leave the cached default unchanged. The engine retains opaque data.
func SetDefault(profiler *Profiler, name string) error {
	if err := checkProfiler(profiler); err != nil {
		return err
	}
	return osprofiles.SetDefaultProfile(profiler, name)
}

// LoadProfile loads an existing profile using the supplied engine without
// selecting it or changing the default. Core setters retain opaque data.
func LoadProfile(profiler *Profiler, name string) (*OtdfctlProfileStore, error) {
	if err := checkProfiler(profiler); err != nil {
		return nil, err
	}
	store, err := osprofiles.GetProfile[*ProfileConfig](profiler, name)
	if err != nil {
		return nil, err
	}
	pc, ok := store.Profile.(*ProfileConfig)
	if !ok || pc == nil {
		return nil, ErrProfileIncorrectType
	}
	return newProfileStore(profiler, store, pc), nil
}

// RegisterProfile saves a new configuration without implicitly choosing a
// default, even when no default exists. Unlike the legacy convenience constructor,
// it preserves supplied authentication. Name collisions (including unregistered
// stored records) are rejected. Registration is not a multi-record transaction:
// a storage failure can leave an unregistered record, but never selects a default.
func RegisterProfile(profiler *Profiler, cfg *ProfileConfig) (*OtdfctlProfileStore, error) {
	if err := checkProfiler(profiler); err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, ErrProfileConfigEmpty
	}
	u, err := utils.NormalizeEndpoint(cfg.Endpoint)
	if err != nil {
		// Parse errors retain the entire supplied URL, possibly including secrets.
		return nil, ErrProfileEndpointInvalid
	}
	pc := *cfg
	pc.Endpoint = u.String()
	pc.OutputFormat = NormalizeOutputFormat(pc.OutputFormat)
	store, err := osprofiles.RegisterProfile(profiler, &pc)
	if err != nil {
		return nil, err
	}
	return newProfileStore(profiler, store, &pc), nil
}
