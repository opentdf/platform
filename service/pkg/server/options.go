package server

import (
	"context"

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
	builtinPolicyOverride string
	extraCoreServices     []serviceregistry.IService
	extraServices         []serviceregistry.IService
	casbinAdapter         string
	configLoaders         []config.Loader
	configLoaderOrder     []string

	trustKeyManagerCtxs []trust.NamedKeyManagerCtxFactory

	// CORS additive configuration - appended to YAML/env config values
	additionalCORSHeaders        []string
	additionalCORSMethods        []string
	additionalCORSExposedHeaders []string
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
func WithCasbinAdapter(adapter string) StartOptions {
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

// WithConfigLoaderOrder option is a slice of config.Loader names and is used as the priority of the loaders.
func WithConfigLoaderOrder(loaderOrder []string) StartOptions {
	return func(c StartConfig) StartConfig {
		c.configLoaderOrder = loaderOrder
		return c
	}
}

// WithTrustKeyManagerFactories option provides factories for creating trust key managers.
// Use WithTrustKeyManagerCtxFactories instead.
// EXPERIMENTAL
func WithTrustKeyManagerFactories(factories ...trust.NamedKeyManagerFactory) StartOptions {
	return func(c StartConfig) StartConfig {
		for _, factory := range factories {
			c.trustKeyManagerCtxs = append(c.trustKeyManagerCtxs, trust.NamedKeyManagerCtxFactory{
				Name: factory.Name,
				Factory: func(_ context.Context, opts *trust.KeyManagerFactoryOptions) (trust.KeyManager, error) {
					return factory.Factory(opts)
				},
			})
		}
		return c
	}
}

// WithTrustKeyManagerCtxFactories option provides factories for creating trust key managers.
func WithTrustKeyManagerCtxFactories(factories ...trust.NamedKeyManagerCtxFactory) StartOptions {
	return func(c StartConfig) StartConfig {
		c.trustKeyManagerCtxs = append(c.trustKeyManagerCtxs, factories...)
		return c
	}
}

// WithAdditionalCORSHeaders appends additional request headers to allow via CORS.
// These are merged with headers from YAML config (server.cors.allowedheaders and
// server.cors.additionalheaders). Deduplication is handled automatically with
// case-insensitive comparison per RFC 7230.
//
// Example:
//
//	server.Start(
//	    server.WithAdditionalCORSHeaders("X-Custom-Header", "X-Another-Header"),
//	)
func WithAdditionalCORSHeaders(headers ...string) StartOptions {
	return func(c StartConfig) StartConfig {
		c.additionalCORSHeaders = append(c.additionalCORSHeaders, headers...)
		return c
	}
}

// WithAdditionalCORSMethods appends additional HTTP methods to allow via CORS.
// These are merged with methods from YAML config (server.cors.allowedmethods and
// server.cors.additionalmethods). Deduplication is handled automatically.
//
// Example:
//
//	server.Start(
//	    server.WithAdditionalCORSMethods("CUSTOM", "SPECIAL"),
//	)
func WithAdditionalCORSMethods(methods ...string) StartOptions {
	return func(c StartConfig) StartConfig {
		c.additionalCORSMethods = append(c.additionalCORSMethods, methods...)
		return c
	}
}

// WithAdditionalCORSExposedHeaders appends additional response headers to expose via CORS.
// These are merged with headers from YAML config (server.cors.exposedheaders and
// server.cors.additionalexposedheaders). Deduplication is handled automatically with
// case-insensitive comparison per RFC 7230.
//
// Example:
//
//	server.Start(
//	    server.WithAdditionalCORSExposedHeaders("X-Request-Id", "X-Trace-Id"),
//	)
func WithAdditionalCORSExposedHeaders(headers ...string) StartOptions {
	return func(c StartConfig) StartConfig {
		c.additionalCORSExposedHeaders = append(c.additionalCORSExposedHeaders, headers...)
		return c
	}
}
