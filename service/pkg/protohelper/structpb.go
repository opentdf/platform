package protohelper

// StructPBCompatibleValue normalizes Go values into shapes accepted by structpb.NewStruct.
// In particular, it recursively converts typed slices into []interface{} while preserving
// nested []interface{} and map[string]interface{} values.
func StructPBCompatibleValue(value interface{}) interface{} {
	switch v := value.(type) {
	case []string:
		return structPBSlice(v)
	case []float64:
		return structPBSlice(v)
	case []bool:
		return structPBSlice(v)
	case []int:
		return structPBSlice(v)
	case []interface{}:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = StructPBCompatibleValue(item)
		}
		return result
	case map[string]interface{}:
		result := make(map[string]interface{}, len(v))
		for key, item := range v {
			result[key] = StructPBCompatibleValue(item)
		}
		return result
	default:
		return value
	}
}

func structPBSlice[T any](values []T) []interface{} {
	result := make([]interface{}, len(values))
	for i, value := range values {
		result[i] = StructPBCompatibleValue(value)
	}
	return result
}
