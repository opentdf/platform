package extensions

import (
	"encoding/json"
	"errors"
	"reflect"
	"regexp"

	osprofiles "github.com/opentdf/platform/otdfctl/internal/profilestore"
	"github.com/opentdf/platform/otdfctl/pkg/profiles"
)

var (
	ErrInvalidExtensionNamespace = errors.New("invalid extension namespace")
	ErrDuplicateExtension        = errors.New("duplicate extension registration")
	ErrExtensionNotRegistered    = errors.New("extension not registered for scope")
	ErrExtensionTypeMismatch     = errors.New("extension type does not match registration")
	ErrExtensionDecode           = errors.New("cannot decode extension")
	ErrExtensionEncode           = errors.New("cannot encode extension")
)

var extensionNamespace = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*$`)

type extensionScope uint8

const (
	globalExtension extensionScope = iota
	profileExtension
)

type extensionKey struct {
	scope     extensionScope
	namespace string
}

// Option registers one consumer shape for a namespace and scope.
// Registrations belong to one Config, never to a package-wide registry.
type Option func(*Config) error

func registerExtension[T any](scope extensionScope, namespace string) Option {
	return func(config *Config) error {
		if !extensionNamespace.MatchString(namespace) {
			return ErrInvalidExtensionNamespace
		}
		key := extensionKey{scope, namespace}
		if _, exists := config.registry[key]; exists {
			return ErrDuplicateExtension
		}
		config.registry[key] = reflect.TypeFor[T]()
		return nil
	}
}

// WithGlobal declares the JSON shape owned by namespace in global settings.
// The extender owns compatibility, unknown-field retention, validation, and versioning
// for its payload; typed writes replace this namespace without retaining omitted fields.
func WithGlobal[T any](namespace string) Option {
	return registerExtension[T](globalExtension, namespace)
}

// WithProfile declares the JSON shape owned by namespace in each profile.
// The extender owns compatibility, unknown-field retention, validation, and versioning
// for its payload; typed writes replace this namespace without retaining omitted fields.
func WithProfile[T any](namespace string) Option {
	return registerExtension[T](profileExtension, namespace)
}

// Config binds registrations to an existing profiler/driver invocation.
// It does not automatically expose payloads through CLI output or diagnostics.
type Config struct {
	profiler *osprofiles.Profiler
	registry map[extensionKey]reflect.Type
}

// NewConfig accepts an existing profiler from profiles.CreateProfiler or profiles.NewProfiler.
// A global registration does not require any profile to exist.
func NewConfig(profiler *osprofiles.Profiler, opts ...Option) (*Config, error) {
	if profiler == nil {
		return nil, errors.New("extension profiler is nil")
	}
	config := &Config{profiler: profiler, registry: make(map[extensionKey]reflect.Type, len(opts))}
	for _, opt := range opts {
		if opt == nil {
			return nil, errors.New("extension option is nil")
		}
		if err := opt(config); err != nil {
			return nil, err
		}
	}
	return config, nil
}

func checkExtensionType[T any](config *Config, scope extensionScope, namespace string) error {
	if config == nil {
		return ErrExtensionNotRegistered
	}
	shape, ok := config.registry[extensionKey{scope, namespace}]
	if !ok {
		return ErrExtensionNotRegistered
	}
	if shape != reflect.TypeFor[T]() {
		return ErrExtensionTypeMismatch
	}
	return nil
}

func decodeExtension[T any](raw json.RawMessage) (T, error) {
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		// Do not return a partial value or raw error: an extension may contain credentials.
		var zero T
		return zero, ErrExtensionDecode
	}
	return value, nil
}

// ReadGlobal reports absence separately from a stored JSON null or decoding error.
func ReadGlobal[T any](config *Config, namespace string) (T, bool, error) {
	var zero T
	if err := checkExtensionType[T](config, globalExtension, namespace); err != nil {
		return zero, false, err
	}
	raw, present, err := osprofiles.GetGlobalConfig(config.profiler).Extension(namespace)
	if err != nil || !present {
		return zero, present, err
	}
	value, err := decodeExtension[T](raw)
	return value, true, err
}

// ReadProfile reads one named profile without selecting or changing the default.
func ReadProfile[T any](config *Config, profileName, namespace string) (T, bool, error) {
	var zero T
	if err := checkExtensionType[T](config, profileExtension, namespace); err != nil {
		return zero, false, err
	}
	profile, err := osprofiles.GetProfile[*profiles.ProfileConfig](config.profiler, profileName)
	if err != nil {
		return zero, false, err
	}
	raw, present, err := profile.Extension(namespace)
	if err != nil || !present {
		return zero, present, err
	}
	value, err := decodeExtension[T](raw)
	return value, true, err
}

func prepareExtensionWrite[T any](config *Config, scope extensionScope, namespace string, value T) (json.RawMessage, error) {
	if err := checkExtensionType[T](config, scope, namespace); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(value)
	if err != nil {
		// MarshalJSON errors can contain secrets from the value being encoded.
		return nil, ErrExtensionEncode
	}
	return payload, nil
}

// WriteGlobal fully replaces one global namespace with value, without
// retaining omitted payload fields. The extender owns compatibility, unknown-field
// retention, validation, and versioning for its replacement payload.
func WriteGlobal[T any](config *Config, namespace string, value T) error {
	payload, err := prepareExtensionWrite(config, globalExtension, namespace, value)
	if err != nil {
		return err
	}
	return osprofiles.GetGlobalConfig(config.profiler).SetExtension(namespace, payload)
}

// WriteProfile fully replaces one namespace in an existing named profile,
// without retaining omitted payload fields. The extender owns compatibility,
// unknown-field retention, validation, and versioning for its replacement payload.
func WriteProfile[T any](config *Config, profileName, namespace string, value T) error {
	payload, err := prepareExtensionWrite(config, profileExtension, namespace, value)
	if err != nil {
		return err
	}
	profile, err := osprofiles.GetProfile[*profiles.ProfileConfig](config.profiler, profileName)
	if err != nil {
		return err
	}
	return profile.SetExtension(namespace, payload)
}
