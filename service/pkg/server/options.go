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

// WithConfigFile option sets the configuration file path.
func WithConfigFile(file string) StartOptions {
	return func(c StartConfig) StartConfig {
		c.ConfigFile = file
		return c
	}
}

// WithConfigKey option sets the viper configuration key(filename).
func WithConfigKey(key string) StartOptions {
	return func(c StartConfig) StartConfig {
		c.ConfigKey = key
		return c
	}
}

// WithWaitForShutdownSignal option allows the server to wait for a shutdown signal before exiting.
func WithWaitForShutdownSignal() StartOptions {
	return func(c StartConfig) StartConfig {
		c.WaitForShutdownSignal = true
		return c
	}
}

// WithPublicRoutes option sets the public routes for the server.
// It allows bypassing the authorization middleware for the specified routes.
// *** This should be used with caution as it can expose sensitive data. ***
func WithPublicRoutes(routes []string) StartOptions {
	return func(c StartConfig) StartConfig {
		c.PublicRoutes = routes
		return c
	}
}

// WithAuthZDefaultPolicyExtension option allows for extending the default casbin poliy
// Example:
//
//	opentdf.WithAuthZDefaultPolicyExtension([][]string{
//				{"p","role:org-admin", "pep*", "*","allow"),
//			}),
func WithAuthZDefaultPolicyExtension(policies [][]string) StartOptions {
	return func(c StartConfig) StartConfig {
		c.authzDefaultPolicyExtension = policies
		return c
	}
}

// WithCoreServices option adds additional core services to the platform
// It takes a variadic parameter of type serviceregistry.Registration, which represents the core services to be added.
func WithCoreServices(services ...serviceregistry.Registration) StartOptions {
	return func(c StartConfig) StartConfig {
		c.extraCoreServices = append(c.extraCoreServices, services...)
		return c
	}
}

// WithServices option adds additional services to the platform.
// This will set the mode for these services to the namespace name.
// It takes a variadic parameter of type serviceregistry.Registration, which represents the services to be added.
func WithServices(services ...serviceregistry.Registration) StartOptions {
	return func(c StartConfig) StartConfig {
		c.extraServices = append(c.extraServices, services...)
		return c
	}
}
