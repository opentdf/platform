package platform

type Platform interface {
	// Get the username as known to the operating system
	GetUsername() string
	// Get the user's home directory
	UserHomeDir() string
	// Get the namespaced user-level data directory for the platform
	UserAppDataDirectory() string
	// Get the namespaced user-level config directory for the platform
	UserAppConfigDirectory() string
	// Get the namespaced system-level data directory for the platform
	SystemAppDataDirectory() string
	// Get the namespaced system-level config directory for the platform
	SystemAppConfigDirectory() string
}

// NewPlatform creates a new platform object based on the current operating system
func NewPlatform(servicePublisher, serviceNamespace, GOOS string) (Platform, error) {
	switch GOOS {
	case "linux":
		return NewPlatformLinux(servicePublisher, serviceNamespace)
	case "windows":
		return NewPlatformWindows(servicePublisher, serviceNamespace)
	case "darwin":
		return NewPlatformDarwin(servicePublisher, serviceNamespace)
	default:
		return nil, ErrGettingUserOS
	}
}
