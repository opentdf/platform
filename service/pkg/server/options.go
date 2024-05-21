package server

type StartOptions func(StartConfig) StartConfig

type StartConfig struct {
	ConfigKey             string
	ConfigFile            string
	WaitForShutdownSignal bool
	PublicRoutes          []string
}

// Deprecated: Use WithConfigKey
func WithConfigName(name string) StartOptions {
	return func(c StartConfig) StartConfig {
		c.ConfigKey = name
		return c
	}
}

func WithConfigFile(file string) StartOptions {
	return func(c StartConfig) StartConfig {
		c.ConfigFile = file
		return c
	}
}

func WithConfigKey(key string) StartOptions {
	return func(c StartConfig) StartConfig {
		c.ConfigKey = key
		return c
	}
}

func WithWaitForShutdownSignal() StartOptions {
	return func(c StartConfig) StartConfig {
		c.WaitForShutdownSignal = true
		return c
	}
}

func WithPublicRoutes(routes []string) StartOptions {
	return func(c StartConfig) StartConfig {
		c.PublicRoutes = routes
		return c
	}
}
