package server

import (
	"github.com/opentdf/platform/service/pkg/serviceregistry"
)

type StartOptions func(StartConfig) StartConfig

type StartConfig struct {
	ConfigKey                   string
	ConfigFile                  string
	WaitForShutdownSignal       bool
	PublicRoutes                []string
	authzDefaultPolicyExtension [][]string
	extraCoreServices           []serviceregistry.Registration
	extraServices               []serviceregistry.Registration
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

func WithAuthZDefaultPolicyExtension(policies [][]string) StartOptions {
	return func(c StartConfig) StartConfig {
		c.authzDefaultPolicyExtension = policies
		return c
	}
}

func WithCoreServices(services ...serviceregistry.Registration) StartOptions {
	return func(c StartConfig) StartConfig {
		c.extraCoreServices = append(c.extraCoreServices, services...)
		return c
	}
}

func WithServices(services ...serviceregistry.Registration) StartOptions {
	return func(c StartConfig) StartConfig {
		c.extraServices = append(c.extraServices, services...)
		return c
	}
}
