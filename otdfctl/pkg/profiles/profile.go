package profiles

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"strings"

	osprofiles "github.com/jrschumacher/go-osprofiles"
	osplatform "github.com/jrschumacher/go-osprofiles/pkg/platform"
	"github.com/opentdf/otdfctl/pkg/config"
)

type ProfileDriver string

const (
	ProfileDriverKeyring    ProfileDriver = "keyring"
	ProfileDriverMemory     ProfileDriver = "in-memory"
	ProfileDriverFileSystem ProfileDriver = "filesystem"
	ProfileDriverUnknown    ProfileDriver = "unknown"
	ProfileDriverDefault                  = ProfileDriverFileSystem
)

func newFileStoreProfiler() (*osprofiles.Profiler, error) {
	platform, err := osplatform.NewPlatform(config.ServicePublisher, config.AppName, runtime.GOOS)
	if err != nil {
		return nil, errors.Join(ErrCreatingPlatform, err)
	}
	profiler, err := osprofiles.New(config.AppName, osprofiles.WithFileStore(platform.UserAppConfigDirectory()))
	if err != nil {
		return nil, errors.Join(ErrCreatingNewProfile, err)
	}
	return profiler, nil
}

func NewProfiler(store string) (*osprofiles.Profiler, error) {
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

func CreateProfiler(driverType ProfileDriver) (*osprofiles.Profiler, error) {
	switch driverType {
	case ProfileDriverMemory:
		return osprofiles.New(config.AppName, osprofiles.WithInMemoryStore())
	case ProfileDriverKeyring:
		return osprofiles.New(config.AppName, osprofiles.WithKeyringStore())
	case ProfileDriverFileSystem:
		return newFileStoreProfiler()
	case ProfileDriverUnknown:
		fallthrough
	default:
		return nil, ErrUnknownProfileDriverType
	}
}

func Migrate(to ProfileDriver, from ProfileDriver) error {
	fromProfiler, err := CreateProfiler(from)
	if err != nil {
		return err
	}

	toProfiler, err := CreateProfiler(to)
	if err != nil {
		return err
	}

	profilesToMigrate := osprofiles.ListProfiles(fromProfiler)
	if len(profilesToMigrate) == 0 {
		return nil
	}

	defaultProfileBeingMigrated := osprofiles.GetGlobalConfig(fromProfiler).GetDefaultProfile()

	slog.Debug("Migrating profiles", slog.Any("count", len(profilesToMigrate)), slog.Any("from", string(from)), slog.Any("to", string(to)))

	for _, profileName := range profilesToMigrate {
		store, err := osprofiles.GetProfile[*ProfileConfig](fromProfiler, profileName)
		if err != nil {
			return err
		}

		p, ok := store.Profile.(*ProfileConfig)
		if !ok || p == nil {
			return ErrProfileIncorrectType
		}

		setDefault := profileName == defaultProfileBeingMigrated

		if err := toProfiler.AddProfile(p, setDefault); err != nil {
			return err
		}

		slog.Debug("Migrated profile", "profile", profileName, "setDefault", setDefault)
	}

	slog.Debug(fmt.Sprintf("Removing profiles from %s", string(from)), slog.Any("count", len(profilesToMigrate)))
	if err = fromProfiler.Cleanup(false); err != nil {
		return errors.Join(ErrCleaningUpProfiles, err)
	}

	slog.Debug("Migration complete.")
	return nil
}
