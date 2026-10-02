package platform

import (
	"os"
	"os/user"
	"path/filepath"
)

type PlatformLinux struct {
	username         string
	serviceNamespace string
	servicePublisher string
	userHomeDir      string
}

func NewPlatformLinux(servicePublisher, serviceNamespace string) (*PlatformLinux, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, ErrGettingUserOS
	}

	usrHomeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, ErrGettingUserOS
	}

	return &PlatformLinux{usr.Username, serviceNamespace, servicePublisher, usrHomeDir}, nil
}

// GetUsername returns the username for the Linux OS.
func (p PlatformLinux) GetUsername() string {
	return p.username
}

// UserHomeDir returns the user's home directory on the Linux OS.
func (p PlatformLinux) UserHomeDir() string {
	return p.userHomeDir
}

// UserAppDataDirectory returns the data directory for Linux.
// ~/.local/share/<servicePublisher>/<serviceNamespace>
// ~/.local/share/<serviceNamespace> (if no publisher)
func (p PlatformLinux) UserAppDataDirectory() string {
	path := filepath.Join(p.userHomeDir, ".local", "share")
	if p.servicePublisher != "" {
		path = filepath.Join(path, p.servicePublisher)
	}
	return filepath.Join(path, p.serviceNamespace)
}

// UserAppConfigDirectory returns the config directory for Linux.
// ~/.config/<servicePublisher>/<serviceNamespace>
// ~/.config/<serviceNamespace>
func (p PlatformLinux) UserAppConfigDirectory() string {
	path := filepath.Join(p.userHomeDir, ".config")
	if p.servicePublisher != "" {
		path = filepath.Join(path, p.servicePublisher)
	}
	return filepath.Join(path, p.serviceNamespace)
}

// SystemAppDataDirectory returns the system-level data directory for Linux.
// /usr/local/<servicePublisher>/<serviceNamespace>
// /usr/local/<serviceNamespace> (if no publisher)
func (p PlatformLinux) SystemAppDataDirectory() string {
	path := filepath.Join("/", "usr", "local")
	if p.servicePublisher != "" {
		path = filepath.Join(path, p.servicePublisher)
	}
	return filepath.Join(path, p.serviceNamespace)
}

// SystemAppConfigDirectory returns the system-level config directory for Linux.
// /etc/<servicePublisher>/<serviceNamespace>
// /etc/<serviceNamespace> (if no publisher)
func (p PlatformLinux) SystemAppConfigDirectory() string {
	path := filepath.Join("/", "etc")
	if p.servicePublisher != "" {
		path = filepath.Join(path, p.servicePublisher)
	}
	return filepath.Join(path, p.serviceNamespace)
}
