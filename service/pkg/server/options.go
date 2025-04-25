package server

import (
	"github.com/casbin/casbin/v2/persist"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"github.com/opentdf/platform/service/trust"
)

type StartOptions func(StartConfig) StartConfig

type StartConfig struct {
	ConfigKey             string
	ConfigFile            string
	WaitForShutdownSignal bool
	PublicRoutes          []string
	IPCReauthRoutes       []string
	bultinPolicyOverride  string
	extraCoreServices     []serviceregistry.IService
	extraServices         []serviceregistry.IService
	casbinAdapter         persist.Adapter
	configLoaders         []config.Loader

	trustKeyIndex         trust.KeyIndex
	trustKeyManager       trust.KeyManager
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
		c.bultinPolicyOverride = policy
		return c
	}
}

// WithCoreServices option adds additional core services to the platform
// It takes a variadic parameter of type serviceregistry.Registration, which represents the core services to be added.
func WithCoreServices(services ...serviceregistry.IService) StartOptions {
	return func(c StartConfig) StartConfig {
		c.extraCoreServices = append(c.extraCoreServices, services...)
		return c
	}
}

// WithServices option adds additional services to the platform.
// This will set the mode for these services to the namespace name.
// It takes a variadic parameter of type serviceregistry.Registration, which represents the services to be added.
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

// WithTrustKeyIndex option sets the trust index to be used for the server.
func WithTrustKeyIndex(index trust.KeyIndex) StartOptions {
	return func(c StartConfig) StartConfig {
		c.trustKeyIndex = index
		return c
	}
}

// WithTrustKeyManager option sets the trust key manager to be used for the server.
func WithTrustKeyManager(manager trust.KeyManager) StartOptions {
	return func(c StartConfig) StartConfig {
		c.trustKeyManager = manager
		return c
	}
}

// WithTrustKeyService option sets both the index and manager for the trust key service.
func WithTrustKeyService(index trust.KeyIndex, manager trust.KeyManager) StartOptions {
	return func(c StartConfig) StartConfig {
		c.trustKeyIndex = index
		c.trustKeyManager = manager
		return c
	}
}
