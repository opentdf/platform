package platform

import (
	"os"
	"os/user"
	"path/filepath"
)

type Darwin struct {
	username         string
	serviceNamespace string
	servicePublisher string
	userHomeDir      string
}

const (
	darwinLibrary    = "Library"
	darwinAppSupport = "Application Support"
)

func NewPlatformDarwin(servicePublisher, serviceNamespace string) (*Darwin, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, ErrGettingUserOS
	}

	usrHomeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, ErrGettingUserOS
	}

	return &Darwin{usr.Username, serviceNamespace, servicePublisher, usrHomeDir}, nil
}

// GetUsername returns the username for macOS.
func (p Darwin) GetUsername() string {
	return p.username
}

// UserHomeDir returns the user's home directory on macOS.
func (p Darwin) UserHomeDir() string {
	return p.userHomeDir
}

// UserAppDataDirectory returns the namespaced user-level data directory for macOS.
// ~/Library/Application Support/<servicePublisher>/<serviceNamespace>
// ~/Library/Application Support/<serviceNamespace> (if no pubisher)
func (p Darwin) UserAppDataDirectory() string {
	path := filepath.Join(p.userHomeDir, darwinLibrary, darwinAppSupport)
	if p.servicePublisher != "" {
		path = filepath.Join(path, p.servicePublisher)
	}
	return filepath.Join(path, p.serviceNamespace)
}

// UserAppConfigDirectory returns the namespaced user-level config directory for macOS.
// ~/Library/Application Support/<servicePublisher>/<serviceNamespace>
// ~/Library/Application Support/<serviceNamespace> (if no publisher)
func (p Darwin) UserAppConfigDirectory() string {
	path := filepath.Join(p.userHomeDir, darwinLibrary, darwinAppSupport)
	if p.servicePublisher != "" {
		path = filepath.Join(path, p.servicePublisher)
	}
	return filepath.Join(path, p.serviceNamespace)
}

// SystemAppDataDirectory returns the namespaced system-level data directory for macOS.
// /Library/Application Support/<servicePublisher>/<serviceNamespace>
// /Library/Application Support/<serviceNamespace> (if no publisher)
func (p Darwin) SystemAppDataDirectory() string {
	path := filepath.Join("/", darwinLibrary, darwinAppSupport)
	if p.servicePublisher != "" {
		path = filepath.Join(path, p.servicePublisher)
	}
	return filepath.Join(path, p.serviceNamespace)
}

// SystemAppConfigDirectory returns the namespaced system-level config directory for macOS.
// /Library/Application Support/<servicePublisher>/<serviceNamespace>
// /Library/Application Support/<serviceNamespace> (if no publisher)
func (p Darwin) SystemAppConfigDirectory() string {
	path := filepath.Join("/", darwinLibrary, darwinAppSupport)
	if p.servicePublisher != "" {
		path = filepath.Join(path, p.servicePublisher)
	}
	return filepath.Join(path, p.serviceNamespace)
}
