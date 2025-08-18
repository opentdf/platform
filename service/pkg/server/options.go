package server

import (
	"github.com/casbin/casbin/v2/persist"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/opentdf/platform/service/trust"
)

type StartOptions func(StartConfig) StartConfig

// ModeAwareService allows specifying which modes a service should run in
type ModeAwareService struct {
	Service serviceregistry.IService
	Modes   []string // Modes this service should run in (e.g., ["kas", "core", "all"])
}

type StartConfig struct {
	ConfigKey             string
	ConfigFile            string
	WaitForShutdownSignal bool
	PublicRoutes          []string
	IPCReauthRoutes       []string
	builtinPolicyOverride string
	extraCoreServices     []serviceregistry.IService
	extraServices         []serviceregistry.IService
	modeAwareServices     []ModeAwareService // New mode-aware services
	casbinAdapter         persist.Adapter
	configLoaders         []config.Loader

	trustKeyManagers []trust.NamedKeyManagerFactory
}

// Deprecated: Use WithConfigKey
// WithConfigName option sets the configuration name.
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

// WithIPCReauthRoutes option sets the IPC reauthorization routes for the server.
// It enables the server to reauthorize IPC routes and embed the token on the context.
func WithIPCReauthRoutes(routes []string) StartOptions {
	return func(c StartConfig) StartConfig {
		c.IPCReauthRoutes = routes
		return c
	}
}

// WithAuthZPolicy option sets the default casbin policy to be used.
// Example:
//
//	  opentdf.WithAuthZPolicy(strings.Join([]string{
//		   "p, role:admin, pep*, *, allow",
//		   "p, role:standard, pep*, read, allow",
//		 }, "\n")),
func WithBuiltinAuthZPolicy(policy string) StartOptions {
	return func(c StartConfig) StartConfig {
		c.builtinPolicyOverride = policy
		return c
	}
}

// WithCoreServices option adds additional core services to the platform
// It takes a variadic parameter of type serviceregistry.IService, which represents the core services to be added.
func WithCoreServices(services ...serviceregistry.IService) StartOptions {
	return func(c StartConfig) StartConfig {
		c.extraCoreServices = append(c.extraCoreServices, services...)
		return c
	}
}

// WithServices option adds additional services to the platform.
// It takes a variadic parameter of type serviceregistry.IService, which represents the services to be added.
//
// This will set the mode for these services to the Namespace name. To understand the registration of these
// services more fully, including the service "mode", follow the usage of the extraServices field in StartConfig.
func WithServices(services ...serviceregistry.IService) StartOptions {
	return func(c StartConfig) StartConfig {
		c.extraServices = append(c.extraServices, services...)
		return c
	}
}

// WithCasbinAdapter option sets the casbin adapter to be used for the casbin enforcer.
func WithCasbinAdapter(adapter persist.Adapter) StartOptions {
	return func(c StartConfig) StartConfig {
		c.casbinAdapter = adapter
		return c
	}
}

// WithAdditionalConfigLoader option adds an additional configuration loader to the server.
func WithAdditionalConfigLoader(loader config.Loader) StartOptions {
	return func(c StartConfig) StartConfig {
		c.configLoaders = append(c.configLoaders, loader)
		return c
	}
}

// WithServicesForModes option adds services that should run in specific modes.
// This allows fine-grained control over when services are enabled.
// Example: WithServicesForModes([]ModeAwareService{
//   {Service: myService, Modes: []string{"kas", "core"}},
//   {Service: otherService, Modes: []string{"all"}},
// })
func WithServicesForModes(services ...ModeAwareService) StartOptions {
	return func(c StartConfig) StartConfig {
		c.modeAwareServices = append(c.modeAwareServices, services...)
		return c
	}
}

// WithServiceForModes is a convenience function for adding a single service with specific modes
func WithServiceForModes(service serviceregistry.IService, modes ...string) StartOptions {
	return WithServicesForModes(ModeAwareService{
		Service: service,
		Modes:   modes,
	})
}

// WithTrustKeyManagerFactories option provides factories for creating trust key managers.
func WithTrustKeyManagerFactories(factories ...trust.NamedKeyManagerFactory) StartOptions {
	return func(c StartConfig) StartConfig {
		c.trustKeyManagers = append(c.trustKeyManagers, factories...)
		return c
	}
}
