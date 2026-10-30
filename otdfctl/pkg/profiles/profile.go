package profiles

import (
	"errors"
	"log/slog"
	"runtime"
	"strings"

	osprofiles "github.com/opentdf/platform/otdfctl/internal/profilestore"
	osplatform "github.com/opentdf/platform/otdfctl/internal/profilestore/pkg/platform"
	"github.com/opentdf/platform/otdfctl/pkg/config"
)

type ProfileDriver string

const (
	ProfileDriverKeyring    ProfileDriver = "keyring"
	ProfileDriverMemory     ProfileDriver = "in-memory"
	ProfileDriverFileSystem ProfileDriver = "filesystem"
	ProfileDriverUnknown    ProfileDriver = "unknown"
	ProfileDriverDefault                  = ProfileDriverFileSystem
)

func NewProfiler(store string) (*Profiler, error) {
	driverType, err := ToProfileDriver(store)
	if err != nil {
		return nil, err
	}

	return CreateProfiler(driverType)
}

func ToProfileDriver(driverType string) (ProfileDriver, error) {
	normalizedType := strings.ToLower(strings.TrimSpace(driverType))
	switch normalizedType {
	case string(ProfileDriverMemory):
		return ProfileDriverMemory, nil
	case string(ProfileDriverKeyring):
		return ProfileDriverKeyring, nil
	case string(ProfileDriverFileSystem):
		return ProfileDriverFileSystem, nil
	case string(ProfileDriverUnknown):
		fallthrough
	default:
		return ProfileDriverUnknown, ErrUnknownProfileDriverType
	}
}

func CreateProfiler(driverType ProfileDriver) (*Profiler, error) {
	return createProfiler(driverType, false)
}

func createProfiler(driverType ProfileDriver, readOnly bool) (*Profiler, error) {
	// Keep initialization and preflight using the same driver options.
	newProfiler := osprofiles.New
	if readOnly {
		newProfiler = osprofiles.Open
	}
	switch driverType {
	case ProfileDriverMemory:
		return newProfiler(config.AppName, osprofiles.WithInMemoryStore())
	case ProfileDriverKeyring:
		return newProfiler(config.AppName, osprofiles.WithKeyringStore())
	case ProfileDriverFileSystem:
		platform, err := osplatform.NewPlatform(config.ServicePublisher, config.AppName, runtime.GOOS)
		if err != nil {
			return nil, errors.Join(ErrCreatingPlatform, err)
		}
		profiler, err := newProfiler(config.AppName, osprofiles.WithFileStore(platform.UserAppConfigDirectory()))
		if err != nil {
			return nil, errors.Join(ErrCreatingNewProfile, err)
		}
		return profiler, nil
	case ProfileDriverUnknown:
		fallthrough
	default:
		return nil, ErrUnknownProfileDriverType
	}
}

func Migrate(to ProfileDriver, from ProfileDriver) error {
	switch to {
	case ProfileDriverFileSystem, ProfileDriverKeyring, ProfileDriverMemory:
	case ProfileDriverUnknown:
		fallthrough
	default:
		return ErrUnknownProfileDriverType
	}

	fromProfiler, err := createProfiler(from, true)
	if err != nil {
		return err
	}

	profilesToMigrate := osprofiles.ListProfiles(fromProfiler)
	// Preserve the previous no-op for an empty store when both drivers are identical.
	if to == from && len(profilesToMigrate) == 0 {
		return nil
	}
	sourceGlobal := osprofiles.GetGlobalConfig(fromProfiler)
	globalExtensions, err := sourceGlobal.Extensions()
	if err != nil {
		return err
	}
	if len(profilesToMigrate) == 0 && len(globalExtensions) == 0 && len(sourceGlobal.UnknownFields()) == 0 {
		return nil
	}

	// Migrate returns only an error, so an in-memory destination would be
	// discarded on return before the source is deleted.
	if to == ProfileDriverMemory {
		return ErrMigrationDestinationNotPersistent
	}

	defaultProfileBeingMigrated := sourceGlobal.GetDefaultProfile()
	// Read and validate every source entry before writing to the destination.
	profileStores := make([]*osprofiles.ProfileStore, 0, len(profilesToMigrate))
	for _, name := range profilesToMigrate {
		profileStore, err := osprofiles.GetProfile[*ProfileConfig](fromProfiler, name)
		if err != nil {
			return err
		}
		// Check aliases within the source even when the destination has no profile.
		if err := profileStore.CheckUnknownTo(profileStore); err != nil {
			return err
		}
		profileStores = append(profileStores, profileStore)
	}
	toProfiler, err := createProfiler(to, true)
	if err != nil {
		return err
	}
	if err := sourceGlobal.CheckUnknownTo(osprofiles.GetGlobalConfig(toProfiler)); err != nil {
		return err
	}
	for i, name := range profilesToMigrate {
		if osprofiles.GetGlobalConfig(toProfiler).ProfileExists(name) {
			destination, err := osprofiles.GetProfile[*ProfileConfig](toProfiler, name)
			if err != nil {
				return err
			}
			if err := profileStores[i].CheckUnknownTo(destination); err != nil {
				return err
			}
			// AddProfile cannot register an already indexed name. Reject the
			// collision now, before any earlier profile has been written.
			return osprofiles.ErrProfileNameConflict
		}
		exists, err := osprofiles.HasProfileStore(toProfiler, name)
		if err != nil {
			return err
		}
		if exists {
			return osprofiles.ErrProfileNameConflict
		}
	}

	// Initialization/version writes are safe only after all preflight checks.
	toProfiler, err = CreateProfiler(to)
	if err != nil {
		return err
	}

	slog.Debug("migrating profiles",
		slog.Any("count", len(profilesToMigrate)),
		slog.Any("from", string(from)),
		slog.Any("to", string(to)),
	)

	for i, profileName := range profilesToMigrate {
		store := profileStores[i]

		p, ok := store.Profile.(*ProfileConfig)
		if !ok || p == nil {
			return ErrProfileIncorrectType
		}

		setDefault := profileName == defaultProfileBeingMigrated

		// Create-only registration repeats the presence check to avoid merging
		// into an orphan observed after preflight. Drivers still provide no CAS.
		destination, err := osprofiles.RegisterProfile(toProfiler, p)
		if err != nil {
			return err
		}
		if err := store.CopyUnknownTo(destination); err != nil {
			return err
		}
		values, err := store.Extensions()
		if err != nil {
			return err
		}
		for namespace, payload := range values {
			if err := destination.SetExtension(namespace, payload); err != nil {
				return err
			}
		}
		if setDefault {
			if err := osprofiles.SetDefaultProfile(toProfiler, profileName); err != nil {
				return err
			}
		}

		slog.Debug("migrated profile",
			slog.String("profile", profileName),
			slog.Bool("set_default", setDefault),
		)
	}

	if err := sourceGlobal.CopyUnknownTo(osprofiles.GetGlobalConfig(toProfiler)); err != nil {
		return err
	}
	for namespace, payload := range globalExtensions {
		if err := osprofiles.GetGlobalConfig(toProfiler).SetExtension(namespace, payload); err != nil {
			return err
		}
	}

	slog.Debug("removing profiles",
		slog.String("from", string(from)),
		slog.Any("count", len(profilesToMigrate)),
	)
	if err = fromProfiler.Cleanup(false); err != nil {
		return errors.Join(ErrCleaningUpProfiles, err)
	}

	slog.Debug("migration complete")
	return nil
}
