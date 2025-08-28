package serviceregistry

import (
	"fmt"
	"log/slog"
	"strings"
)

// ServiceFactory represents a function that creates service registrations
type ServiceFactory func() []IService

// ServiceDefinition defines how to create a service
type ServiceDefinition struct {
	Name          ServiceName
	CreateFunc    ServiceFactory
	CoreNamespace string // namespace when part of "all" or "core" modes
	OwnNamespace  string // namespace when registered individually
}

// serviceInfo represents a service with its registration functions
type serviceInfo struct {
	name         ServiceName
	registration []IService
	namespace    string
}

// ServiceManager manages service registration with negation support.
// It provides thread-safe access to service definitions and mode mappings,
// and supports parsing service modes with exclusion syntax (e.g., "all", "-kas").
//
// ServiceManager encapsulates the logic for:
//   - Parsing mode strings with negation syntax
//   - Building complete service sets from included modes  
//   - Removing excluded services from service sets
//   - Registering services with proper namespace handling
//   - Thread-safe access to service configuration data
type ServiceManager struct {
	definitions map[ServiceName]ServiceDefinition
	modeMap     map[ModeName][]ServiceName
}

// NewServiceManager creates a new ServiceManager with the provided service configurations.
// The returned ServiceManager provides thread-safe access to service definitions
// and mode mappings.
//
// Parameters:
//   - definitions: Map of service definitions with their creation functions
//   - modeMap: Map of modes to their constituent services
//
// Returns:
//   - *ServiceManager: A new instance with the provided configurations
func NewServiceManager(definitions map[ServiceName]ServiceDefinition, modeMap map[ModeName][]ServiceName) *ServiceManager {
	// Create deep copies for isolation
	defsCopy := make(map[ServiceName]ServiceDefinition, len(definitions))
	for k, v := range definitions {
		defsCopy[k] = v
	}
	
	modesCopy := make(map[ModeName][]ServiceName, len(modeMap))
	for k, v := range modeMap {
		servicesCopy := make([]ServiceName, len(v))
		copy(servicesCopy, v)
		modesCopy[k] = servicesCopy
	}

	return &ServiceManager{
		definitions: defsCopy,
		modeMap:     modesCopy,
	}
}

// NewDefaultServiceManager creates a ServiceManager with default OpenTDF service configurations.
// This function requires service factories to be provided to avoid import cycles.
// The server package should provide the actual service creation functions.
//
// Parameters:
//   - serviceFactories: Map of service names to their factory functions
//
// Returns:
//   - *ServiceManager: A new instance with default OpenTDF service configurations
//   - error: Configuration error if service definitions are invalid
func NewDefaultServiceManager(serviceFactories map[ServiceName]ServiceFactory) (*ServiceManager, error) {
	definitions := map[ServiceName]ServiceDefinition{
		ServicePolicy: {
			Name:          ServicePolicy,
			CreateFunc:    serviceFactories[ServicePolicy],
			CoreNamespace: string(ModeCore),
			OwnNamespace:  string(ModeCore),
		},
		ServiceAuthorization: {
			Name:          ServiceAuthorization,
			CreateFunc:    serviceFactories[ServiceAuthorization],
			CoreNamespace: string(ModeCore),
			OwnNamespace:  string(ModeCore),
		},
		ServiceKAS: {
			Name:          ServiceKAS,
			CreateFunc:    serviceFactories[ServiceKAS],
			CoreNamespace: string(ModeCore),
			OwnNamespace:  string(ModeKAS),
		},
		ServiceWellKnown: {
			Name:          ServiceWellKnown,
			CreateFunc:    serviceFactories[ServiceWellKnown],
			CoreNamespace: string(ModeCore),
			OwnNamespace:  string(ModeCore),
		},
		ServiceEntityResolution: {
			Name:          ServiceEntityResolution,
			CreateFunc:    serviceFactories[ServiceEntityResolution],
			CoreNamespace: string(ModeCore),
			OwnNamespace:  string(ModeERS),
		},
	}

	modeMap := map[ModeName][]ServiceName{
		ModeALL:  {ServicePolicy, ServiceAuthorization, ServiceKAS, ServiceWellKnown, ServiceEntityResolution},
		ModeCore: {ServicePolicy, ServiceAuthorization, ServiceWellKnown},
		ModeKAS:  {ServiceKAS},
		ModeERS:  {ServiceEntityResolution},
	}

	// Validate service definitions
	if err := validateServiceDefinitions(definitions, modeMap); err != nil {
		return nil, err
	}

	return NewServiceManager(definitions, modeMap), nil
}

// validateServiceDefinitions validates the service definitions and mode mappings
func validateServiceDefinitions(definitions map[ServiceName]ServiceDefinition, modeMap map[ModeName][]ServiceName) error {
	// Validate that all service definitions are properly configured
	for serviceName, def := range definitions {
		if def.CreateFunc == nil {
			return &ServiceConfigError{
				Type:    "startup",
				Service: serviceName.String(),
				Message: "CreateFunc cannot be nil",
			}
		}
		if def.CoreNamespace == "" {
			return &ServiceConfigError{
				Type:    "startup",
				Service: serviceName.String(),
				Message: "CoreNamespace cannot be empty",
			}
		}
		if def.OwnNamespace == "" {
			return &ServiceConfigError{
				Type:    "startup",
				Service: serviceName.String(),
				Message: "OwnNamespace cannot be empty",
			}
		}
		if def.Name != serviceName {
			return &ServiceConfigError{
				Type:    "startup",
				Service: serviceName.String(),
				Message: fmt.Sprintf("service name mismatch: expected %s, got %s", serviceName, def.Name),
			}
		}
	}

	// Validate that mode service mappings reference valid services
	for mode, services := range modeMap {
		for _, serviceName := range services {
			if _, exists := definitions[serviceName]; !exists {
				return &ServiceConfigError{
					Type:    "startup",
					Mode:    mode.String(),
					Service: serviceName.String(),
					Message: "mode references undefined service",
				}
			}
		}
	}

	return nil
}

// ParseModes separates included and excluded modes from a mode list.
// It supports negation syntax where modes prefixed with "-" are treated as exclusions.
//
// Examples:
//   - []string{"all", "-kas"} -> included: ["all"], excluded: ["kas"]  
//   - []string{"core", "kas"} -> included: ["core", "kas"], excluded: []
//   - []string{"-kas"} -> error (exclusions require at least one inclusion)
//
// Parameters:
//   - modes: Slice of mode strings, supporting negation with "-" prefix
//
// Returns:
//   - []string: Included mode names (without "-" prefix)
//   - []string: Excluded mode names (without "-" prefix)  
//   - error: Validation error if input is invalid
func (sm *ServiceManager) ParseModes(modes []string) ([]string, []string, error) {
	if len(modes) == 0 {
		return nil, nil, &ServiceConfigError{
			Type:    "validation",
			Message: "no modes provided",
		}
	}
	return parseModeWithNegation(modes)
}

// BuildServiceSet creates a complete service set from included modes.
// It resolves mode names to their constituent services and handles namespace assignment.
// Services included in multiple modes are deduplicated automatically.
//
// Namespace assignment logic:
//   - Services in "all" or "core" modes use their CoreNamespace  
//   - Services in individual modes use their OwnNamespace
//   - Unknown modes are silently ignored for backward compatibility
//
// Parameters:
//   - included: Slice of mode names to include (e.g., ["all", "core", "kas"])
//
// Returns:
//   - map[ServiceName]serviceInfo: Map of services with registration functions and namespaces
//   - error: Error if service definitions are inconsistent (should not happen in normal operation)
func (sm *ServiceManager) BuildServiceSet(included []string) (map[ServiceName]serviceInfo, error) {
	serviceSet := make(map[ServiceName]serviceInfo)

	for _, modeStr := range included {
		mode := ModeName(modeStr)
		serviceNames, exists := sm.modeMap[mode]
		if !exists {
			// Unknown modes are ignored (existing behavior)
			continue
		}

		for _, serviceName := range serviceNames {
			if _, alreadyAdded := serviceSet[serviceName]; alreadyAdded {
				continue // Skip if already added by another mode
			}

			serviceDef, exists := sm.definitions[serviceName]
			if !exists {
				continue // Should never happen, but defensive programming
			}

			// Determine namespace: use CoreNamespace for "all"/"core", OwnNamespace for individual modes
			namespace := serviceDef.OwnNamespace
			if mode == ModeALL || mode == ModeCore {
				namespace = serviceDef.CoreNamespace
			}

			serviceSet[serviceName] = serviceInfo{
				name:         serviceName,
				registration: serviceDef.CreateFunc(),
				namespace:    namespace,
			}
		}
	}

	return serviceSet, nil
}

// RemoveExcludedServices removes excluded services from the service set.
// This method modifies the provided service set in-place by deleting entries
// that match the excluded service names.
//
// Parameters:
//   - serviceSet: Map of services to modify in-place  
//   - excluded: Slice of service names to remove (e.g., ["kas", "entityresolution"])
//
// The method is idempotent - removing non-existent services has no effect.
func (sm *ServiceManager) RemoveExcludedServices(serviceSet map[ServiceName]serviceInfo, excluded []string) {
	for _, exclude := range excluded {
		delete(serviceSet, ServiceName(exclude))
	}
}

// RegisterServiceSet registers all services in the service set with appropriate namespaces.
// It handles different registration strategies based on service namespace:
//   - Core services (namespace "core") are registered using RegisterCoreService
//   - Other services (e.g., "kas", "entityresolution") are registered using RegisterService
//
// The method provides comprehensive logging for service registration operations
// and maintains detailed metrics about registration progress.
//
// Parameters:
//   - reg: Service registry to register services with
//   - serviceSet: Map of services with their namespace assignments  
//
// Returns:
//   - []string: List of registered service names for logging/tracking
//   - error: Registration error if any service fails to register
func (sm *ServiceManager) RegisterServiceSet(reg Registry, serviceSet map[ServiceName]serviceInfo) ([]string, error) {
	registeredServices := make([]string, 0, len(serviceSet))

	// Log service registration start
	slog.Info("starting service registration",
		slog.Int("service_count", len(serviceSet)),
		slog.Any("services", func() []string {
			names := make([]string, 0, len(serviceSet))
			for name := range serviceSet {
				names = append(names, name.String())
			}
			return names
		}()),
	)

	// Separate services that need special namespace handling
	var coreServices []IService
	coreServiceCount := 0

	for serviceName, info := range serviceSet {
		registeredServices = append(registeredServices, serviceName.String())

		if info.namespace == string(ModeCore) {
			// Core services are registered together
			coreServices = append(coreServices, info.registration...)
			coreServiceCount += len(info.registration)
			slog.Debug("queued core service",
				slog.String("service", serviceName.String()),
				slog.Int("sub_services", len(info.registration)),
			)
		} else {
			// Services with special namespaces (kas, entityresolution) are registered separately
			slog.Debug("registering service with special namespace",
				slog.String("service", serviceName.String()),
				slog.String("namespace", info.namespace),
				slog.Int("sub_services", len(info.registration)),
			)
			for _, service := range info.registration {
				if err := reg.RegisterService(service, ModeName(info.namespace)); err != nil {
					slog.Error("failed to register service",
						slog.String("service", serviceName.String()),
						slog.String("namespace", info.namespace),
						slog.String("error", err.Error()),
					)
					return nil, err //nolint:wrapcheck // We are all friends here
				}
			}
		}
	}

	// Register core services together
	if len(coreServices) > 0 {
		slog.Debug("registering core services",
			slog.Int("core_service_count", coreServiceCount),
		)
		for _, service := range coreServices {
			if err := reg.RegisterCoreService(service); err != nil {
				slog.Error("failed to register core service",
					slog.String("error", err.Error()),
				)
				return nil, err //nolint:wrapcheck // We are all friends here
			}
		}
	}

	slog.Info("completed service registration",
		slog.Int("registered_services", len(registeredServices)),
		slog.Int("core_services", coreServiceCount),
		slog.Any("registered", registeredServices),
	)

	return registeredServices, nil
}

// RegisterEssentialServices registers the essential services to the given service registry.
// Essential services are critical infrastructure services required for basic platform operation.
//
// Parameters:
//   - reg: Service registry to register essential services with
//   - essentialServices: Slice of essential service registrations
//
// Returns:
//   - error: Registration error if any essential service fails to register
func (sm *ServiceManager) RegisterEssentialServices(reg Registry, essentialServices []IService) error {
	if len(essentialServices) == 0 {
		return &ServiceConfigError{
			Type:    "validation",
			Message: "no essential services provided",
		}
	}

	// Register the essential services
	for _, s := range essentialServices {
		if err := reg.RegisterService(s, ModeEssential); err != nil {
			return err //nolint:wrapcheck // We are all friends here
		}
	}
	return nil
}

// RegisterCoreServices registers core services based on the provided modes with support for negation.
// This is the main entry point for service registration with negation support.
//
// Parameters:
//   - reg: Service registry to register services with
//   - modes: Slice of mode names, supporting negation syntax (e.g., ["all", "-kas"])
//
// Returns:
//   - []string: List of registered service names
//   - error: Registration or parsing error
func (sm *ServiceManager) RegisterCoreServices(reg Registry, modes []ModeName) ([]string, error) {
	// Convert ModeName slice to string slice
	modeStrings := make([]string, len(modes))
	for i, m := range modes {
		modeStrings[i] = string(m)
	}

	// Check if any modes use negation syntax
	hasNegation := false
	for _, modeStr := range modeStrings {
		if strings.HasPrefix(modeStr, "-") {
			hasNegation = true
			break
		}
	}

	// If negation is used, use the new logic with ServiceManager
	if hasNegation {
		slog.Info("using service negation mode",
			slog.Any("modes", modes),
		)

		included, excluded, err := sm.ParseModes(modeStrings)
		if err != nil {
			slog.Error("failed to parse modes with negation",
				slog.Any("modes", modes),
				slog.String("error", err.Error()),
			)
			return nil, err
		}

		slog.Debug("parsed modes",
			slog.Any("included", included),
			slog.Any("excluded", excluded),
		)

		serviceSet, err := sm.BuildServiceSet(included)
		if err != nil {
			slog.Error("failed to build service set",
				slog.Any("included", included),
				slog.String("error", err.Error()),
			)
			return nil, err
		}

		sm.RemoveExcludedServices(serviceSet, excluded)

		slog.Debug("service set after exclusions",
			slog.Int("final_service_count", len(serviceSet)),
		)

		return sm.RegisterServiceSet(reg, serviceSet)
	}

	// Original logic for backward compatibility (without negation)
	return sm.registerCoreServicesLegacy(reg, modeStrings)
}

// registerCoreServicesLegacy handles the original service registration logic for backward compatibility
func (sm *ServiceManager) registerCoreServicesLegacy(reg Registry, modes []string) ([]string, error) {
	var (
		services           []IService
		registeredServices []string
	)

	for _, m := range modes {
		switch m {
		case "all":
			registeredServices = append(registeredServices, []string{string(ServicePolicy), string(ServiceAuthorization), string(ServiceKAS), string(ServiceWellKnown), string(ServiceEntityResolution)}...)
			
			// Get services from definitions
			if def, exists := sm.definitions[ServiceAuthorization]; exists {
				services = append(services, def.CreateFunc()...)
			}
			if def, exists := sm.definitions[ServiceKAS]; exists {
				services = append(services, def.CreateFunc()...)
			}
			if def, exists := sm.definitions[ServiceWellKnown]; exists {
				services = append(services, def.CreateFunc()...)
			}
			if def, exists := sm.definitions[ServiceEntityResolution]; exists {
				services = append(services, def.CreateFunc()...)
			}
			if def, exists := sm.definitions[ServicePolicy]; exists {
				services = append(services, def.CreateFunc()...)
			}
		case "core":
			registeredServices = append(registeredServices, []string{string(ServicePolicy), string(ServiceAuthorization), string(ServiceWellKnown)}...)
			
			if def, exists := sm.definitions[ServiceAuthorization]; exists {
				services = append(services, def.CreateFunc()...)
			}
			if def, exists := sm.definitions[ServiceWellKnown]; exists {
				services = append(services, def.CreateFunc()...)
			}
			if def, exists := sm.definitions[ServicePolicy]; exists {
				services = append(services, def.CreateFunc()...)
			}
		case "kas":
			// If the mode is "kas", register only the KAS service
			registeredServices = append(registeredServices, string(ServiceKAS))
			if def, exists := sm.definitions[ServiceKAS]; exists {
				for _, service := range def.CreateFunc() {
					if err := reg.RegisterService(service, ModeKAS); err != nil {
						return nil, err //nolint:wrapcheck // We are all friends here
					}
				}
			}
		case "entityresolution":
			// If the mode is "entityresolution", register only the ERS service (v1 and v2)
			registeredServices = append(registeredServices, string(ServiceEntityResolution))
			if def, exists := sm.definitions[ServiceEntityResolution]; exists {
				for _, service := range def.CreateFunc() {
					if err := reg.RegisterService(service, ModeERS); err != nil {
						return nil, err //nolint:wrapcheck // We are all friends here
					}
				}
			}
		default:
			slog.Warn("unknown service mode", slog.String("mode", m))
		}
	}

	// Register core services together
	for _, service := range services {
		if err := reg.RegisterCoreService(service); err != nil {
			return nil, err //nolint:wrapcheck // We are all friends here
		}
	}

	return registeredServices, nil
}

// parseModeWithNegation separates included and excluded modes from a mode list.
// This function implements the core negation logic for service mode parsing.
// Modes prefixed with "-" are treated as exclusions (e.g., "-kas", "-entityresolution").
//
// Validation rules:
//   - Empty mode strings are rejected
//   - Empty service names after "-" are rejected  
//   - Exclusions without inclusions are rejected
//   - Service and mode names are validated for existence
//
// Parameters:
//   - modes: Slice of mode strings with optional "-" prefixes for exclusions
//
// Returns:
//   - []string: Included mode names (without "-" prefix)
//   - []string: Excluded service names (without "-" prefix)
//   - error: Validation error for invalid input
func parseModeWithNegation(modes []string) ([]string, []string, error) {
	// Pre-allocate slices for better memory efficiency
	included := make([]string, 0, len(modes))
	excluded := make([]string, 0, len(modes))

	for _, mode := range modes {
		// Validate mode is not empty
		if mode == "" {
			return nil, nil, &ServiceConfigError{
				Type:    "validation",
				Message: "empty mode name",
			}
		}

		// Use strings.CutPrefix for better performance (Go 1.20+)
		if excludeMode, found := strings.CutPrefix(mode, "-"); found {
			if excludeMode == "" {
				return nil, nil, &ServiceConfigError{
					Type:    "validation",
					Message: "empty service name after '-'",
				}
			}
			// Validate the service name format
			if err := validateServiceName(excludeMode); err != nil {
				return nil, nil, err
			}
			excluded = append(excluded, excludeMode)
		} else {
			// Validate the mode name format
			if err := validateModeName(mode); err != nil {
				return nil, nil, err
			}
			included = append(included, mode)
		}
	}

	// Validate that we have something to include if we have exclusions
	if len(excluded) > 0 && len(included) == 0 {
		return nil, nil, &ServiceConfigError{
			Type:    "validation",
			Message: "cannot exclude services without including base modes",
		}
	}

	return included, excluded, nil
}

// validateModeName validates that a mode name is properly formatted
func validateModeName(mode string) error {
	if mode == "" {
		return &ServiceConfigError{
			Type:    "validation",
			Mode:    mode,
			Message: "mode name cannot be empty",
		}
	}
	// Add additional validation rules as needed
	return nil
}

// validateServiceName validates that a service name is properly formatted
func validateServiceName(service string) error {
	if service == "" {
		return &ServiceConfigError{
			Type:    "validation",
			Service: service,
			Message: "service name cannot be empty",
		}
	}
	// Add additional validation rules as needed
	return nil
}

// IsNamespaceEnabled checks if a namespace should be enabled based on configured modes.
// This method handles the logic for determining if a service namespace should be active
// based on the configured service modes and the namespace's own mode.
//
// Mode matching rules:
//   - ModeALL: Enables all namespaces regardless of their mode
//   - ModeEssential: Always enabled (essential services)
//   - Specific modes: Enabled if the namespace mode matches any configured mode
//   - Case-insensitive matching for all mode comparisons
//
// Parameters:
//   - configuredModes: Slice of mode names from configuration (e.g., ["all", "core"])
//   - namespaceMode: The mode of the specific namespace being checked
//
// Returns:
//   - bool: True if the namespace should be enabled, false otherwise
func (sm *ServiceManager) IsNamespaceEnabled(configuredModes []string, namespaceMode string) bool {
	for _, configMode := range configuredModes {
		// Case-insensitive comparison for mode matching
		if strings.EqualFold(configMode, string(ModeALL)) || 
		   strings.EqualFold(namespaceMode, string(ModeEssential)) ||
		   strings.EqualFold(configMode, namespaceMode) {
			return true
		}
	}
	return false
}