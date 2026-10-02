package platform

import (
	"os"
	"os/user"
	"path/filepath"
)

type PlatformDarwin struct {
	username         string
	serviceNamespace string
	servicePublisher string
	userHomeDir      string
}

const (
	darwinLibrary    = "Library"
	darwinAppSupport = "Application Support"
)

func NewPlatformDarwin(servicePublisher, serviceNamespace string) (*PlatformDarwin, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, ErrGettingUserOS
	}

	usrHomeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, ErrGettingUserOS
	}

	return &PlatformDarwin{usr.Username, serviceNamespace, servicePublisher, usrHomeDir}, nil
}

// GetUsername returns the username for macOS.
func (p PlatformDarwin) GetUsername() string {
	return p.username
}

// UserHomeDir returns the user's home directory on macOS.
func (p PlatformDarwin) UserHomeDir() string {
	return p.userHomeDir
}

// UserAppDataDirectory returns the namespaced user-level data directory for macOS.
// ~/Library/Application Support/<servicePublisher>/<serviceNamespace>
// ~/Library/Application Support/<serviceNamespace> (if no pubisher)
func (p PlatformDarwin) UserAppDataDirectory() string {
	path := filepath.Join(p.userHomeDir, darwinLibrary, darwinAppSupport)
	if p.servicePublisher != "" {
		path = filepath.Join(path, p.servicePublisher)
	}
	return filepath.Join(path, p.serviceNamespace)
}

// UserAppConfigDirectory returns the namespaced user-level config directory for macOS.
// ~/Library/Application Support/<servicePublisher>/<serviceNamespace>
// ~/Library/Application Support/<serviceNamespace> (if no publisher)
func (p PlatformDarwin) UserAppConfigDirectory() string {
	path := filepath.Join(p.userHomeDir, darwinLibrary, darwinAppSupport)
	if p.servicePublisher != "" {
		path = filepath.Join(path, p.servicePublisher)
	}
	return filepath.Join(path, p.serviceNamespace)
}

// SystemAppDataDirectory returns the namespaced system-level data directory for macOS.
// /Library/Application Support/<servicePublisher>/<serviceNamespace>
// /Library/Application Support/<serviceNamespace> (if no publisher)
func (p PlatformDarwin) SystemAppDataDirectory() string {
	path := filepath.Join("/", darwinLibrary, darwinAppSupport)
	if p.servicePublisher != "" {
		path = filepath.Join(path, p.servicePublisher)
	}
	return filepath.Join(path, p.serviceNamespace)
}

// SystemAppConfigDirectory returns the namespaced system-level config directory for macOS.
// /Library/Application Support/<servicePublisher>/<serviceNamespace>
// /Library/Application Support/<serviceNamespace> (if no publisher)
func (p PlatformDarwin) SystemAppConfigDirectory() string {
	path := filepath.Join("/", darwinLibrary, darwinAppSupport)
	if p.servicePublisher != "" {
		path = filepath.Join(path, p.servicePublisher)
	}
	return filepath.Join(path, p.serviceNamespace)
}
