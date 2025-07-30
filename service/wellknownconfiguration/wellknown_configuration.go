package wellknownconfiguration

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"

	"connectrpc.com/connect"
	wellknown "github.com/opentdf/platform/protocol/go/wellknownconfiguration"
	"github.com/opentdf/platform/protocol/go/wellknownconfiguration/wellknownconfigurationconnect"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"google.golang.org/protobuf/types/known/structpb"
)

type WellKnownService struct {
	logger *logger.Logger
}

var (
	wellKnownConfiguration = make(map[string]any)
	rwMutex                sync.RWMutex
	baseKeyWellKnown       = "base_key"
)

func RegisterConfiguration(namespace string, config any) error {
	rwMutex.Lock()
	defer rwMutex.Unlock()
	if _, ok := wellKnownConfiguration[namespace]; ok {
		return fmt.Errorf("namespace %s configuration already registered", namespace)
	}
	wellKnownConfiguration[namespace] = config
	return nil
}

func UpdateConfigurationBaseKey(config any) {
	rwMutex.Lock()
	defer rwMutex.Unlock()
	wellKnownConfiguration[baseKeyWellKnown] = config
}

func NewRegistration() *serviceregistry.Service[wellknownconfigurationconnect.WellKnownServiceHandler] {
	return &serviceregistry.Service[wellknownconfigurationconnect.WellKnownServiceHandler]{
		ServiceOptions: serviceregistry.ServiceOptions[wellknownconfigurationconnect.WellKnownServiceHandler]{
			Namespace:       "wellknown",
			ServiceDesc:     &wellknown.WellKnownService_ServiceDesc,
			ConnectRPCFunc:  wellknownconfigurationconnect.NewWellKnownServiceHandler,
			GRPCGatewayFunc: wellknown.RegisterWellKnownServiceHandler,
			RegisterFunc: func(srp serviceregistry.RegistrationParams) (wellknownconfigurationconnect.WellKnownServiceHandler, serviceregistry.HandlerServer) {
				wk := &WellKnownService{logger: srp.Logger}
				return wk, nil
			},
		},
	}
}

func (s WellKnownService) GetWellKnownConfiguration(_ context.Context, _ *connect.Request[wellknown.GetWellKnownConfigurationRequest]) (*connect.Response[wellknown.GetWellKnownConfigurationResponse], error) {
	rwMutex.RLock()
	// Convert configuration to structpb-compatible format
	convertedConfig := convertToSerializable(wellKnownConfiguration)
	cfg, err := structpb.NewStruct(convertedConfig.(map[string]interface{}))
	rwMutex.RUnlock()
	if err != nil {
		s.logger.Error("failed to create struct for wellknown configuration", slog.String("error", err.Error()))
		return nil, connect.NewError(connect.CodeInternal, errors.New("failed to create struct for wellknown configuration"))
	}

	rsp := &wellknown.GetWellKnownConfigurationResponse{
		Configuration: cfg,
	}
	return connect.NewResponse(rsp), nil
}

// convertToSerializable converts any value to a format that structpb.NewStruct can handle
func convertToSerializable(value interface{}) interface{} {
	if value == nil {
		return nil
	}
	converted := convertValue(reflect.ValueOf(value))
	if !converted.IsValid() {
		return nil
	}
	return converted.Interface()
}

// convertValue recursively converts reflection values to structpb-compatible types
func convertValue(v reflect.Value) reflect.Value {
	if !v.IsValid() {
		return reflect.ValueOf(nil)
	}

	switch v.Kind() {
	case reflect.Struct:
		return convertStruct(v)
	case reflect.Slice:
		return convertSlice(v)
	case reflect.Map:
		return convertMap(v)
	case reflect.Ptr:
		if v.IsNil() {
			return reflect.ValueOf(nil)
		}
		return convertValue(v.Elem())
	case reflect.Interface:
		if v.IsNil() {
			return reflect.ValueOf(nil)
		}
		return convertValue(v.Elem())
	default:
		// Basic types (bool, int, float, string) are handled as-is
		return v
	}
}

// convertStruct converts a struct to a map[string]interface{}
func convertStruct(v reflect.Value) reflect.Value {
	t := v.Type()
	result := make(map[string]interface{})

	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}

		// Check json tag for exclusion
		jsonTag := field.Tag.Get("json")
		if jsonTag == "-" {
			continue
		}

		// Use json tag if available, otherwise use field name
		name := field.Name
		if jsonTag != "" {
			tagParts := strings.Split(jsonTag, ",")
			if tagParts[0] != "" {
				name = tagParts[0]
			}
		}

		fieldValue := convertValue(v.Field(i))
		if fieldValue.IsValid() {
			result[name] = fieldValue.Interface()
		} else {
			result[name] = nil
		}
	}

	return reflect.ValueOf(result)
}

// convertSlice converts slices to []interface{}
func convertSlice(v reflect.Value) reflect.Value {
	result := make([]interface{}, v.Len())
	for i := 0; i < v.Len(); i++ {
		converted := convertValue(v.Index(i))
		result[i] = converted.Interface()
	}
	return reflect.ValueOf(result)
}

// convertMap converts maps to map[string]interface{}
func convertMap(v reflect.Value) reflect.Value {
	result := make(map[string]interface{})
	for _, key := range v.MapKeys() {
		keyStr := fmt.Sprintf("%v", key.Interface())
		value := convertValue(v.MapIndex(key))
		result[keyStr] = value.Interface()
	}
	return reflect.ValueOf(result)
}
