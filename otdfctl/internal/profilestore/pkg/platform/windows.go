package platform

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
)

type PlatformWindows struct {
	username         string
	serviceNamespace string
	servicePublisher string
	userHomeDir      string
	programFiles     string
	programData      string
	localAppData     string
}

const (
	envKeyLocalAppData = "LOCALAPPDATA"
	envKeyProgramData  = "PROGRAMDATA"
	envKeyProgramFiles = "PROGRAMFILES"
	envKeyUsername     = "USERNAME"
)

func NewPlatformWindows(servicePublisher, serviceNamespace string) (*PlatformWindows, error) {
	// On Windows, use user.Current() if available, else fallback to environment variable
	usr, err := user.Current()
	if err != nil {
		usr = &user.User{Username: os.Getenv(envKeyUsername)}
		if usr.Username == "" {
			return nil, ErrGettingUserOS
		}
	}
	usrHomeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, ErrGettingUserOS
	}

	programFiles := os.Getenv(envKeyProgramFiles)
	if programFiles == "" {
		return nil, fmt.Errorf("failed to detect %%%s%% in environment: %w", envKeyProgramFiles, ErrGettingUserOS)
	}

	programData := os.Getenv(envKeyProgramData)
	if programData == "" {
		return nil, fmt.Errorf("failed to detect %%%s%% in environment: %w", envKeyProgramData, ErrGettingUserOS)
	}

	localAppData := os.Getenv(envKeyLocalAppData)
	if localAppData == "" {
		return nil, fmt.Errorf("failed to detect %%%s%% in environment: %w", envKeyLocalAppData, ErrGettingUserOS)
	}

	return &PlatformWindows{
		username:         usr.Username,
		serviceNamespace: serviceNamespace,
		servicePublisher: servicePublisher,
		userHomeDir:      usrHomeDir,
		programFiles:     programFiles,
		programData:      programData,
		localAppData:     localAppData,
	}, nil
}

// GetUsername returns the username for Windows.
func (p PlatformWindows) GetUsername() string {
	return p.username
}

// UserHomeDir returns the user's home directory on Windows.
func (p PlatformWindows) UserHomeDir() string {
	return p.userHomeDir
}

// UserAppDataDirectory returns the namespaced user-level data directory for Windows.
// %LocalAppData%\<servicePublisher>\<serviceNamespace>
// %LocalAppData%\<serviceNamespace> (if no publisher)
func (p PlatformWindows) UserAppDataDirectory() string {
	path := p.localAppData
	if p.servicePublisher != "" {
		path = filepath.Join(path, p.servicePublisher)
	}
	return filepath.Join(path, p.serviceNamespace)
}

// UserAppConfigDirectory returns the namespaced user-level config directory for Windows.
// %LocalAppData%\<servicePublisher>\<serviceNamespace>
// %LocalAppData%\<serviceNamespace> (if no publisher)
func (p PlatformWindows) UserAppConfigDirectory() string {
	path := p.localAppData
	if p.servicePublisher != "" {
		path = filepath.Join(path, p.servicePublisher)
	}
	return filepath.Join(path, p.serviceNamespace)
}

// SystemAppDataDirectory returns the namespaced system-level data directory for Windows.
// %ProgramData%\<servicePublisher>\<serviceNamespace>
// %ProgramData%\<serviceNamespace> (if no publisher)
func (p PlatformWindows) SystemAppDataDirectory() string {
	path := p.programData
	if p.servicePublisher != "" {
		path = filepath.Join(path, p.servicePublisher)
	}
	return filepath.Join(path, p.serviceNamespace)
}

// SystemAppConfigDirectory returns the namespaced system-level config directory for Windows.
// %ProgramFiles%\<servicePublisher>\<serviceNamespace>
// %ProgramFiles%\<serviceNamespace> (if no publisher)
func (p PlatformWindows) SystemAppConfigDirectory() string {
	path := p.programFiles
	if p.servicePublisher != "" {
		path = filepath.Join(path, p.servicePublisher)
	}
	return filepath.Join(path, p.serviceNamespace)
}
