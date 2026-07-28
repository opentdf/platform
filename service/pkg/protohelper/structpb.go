package protohelper

// StructPBCompatibleValue normalizes Go values into shapes accepted by structpb.NewStruct.
// In particular, it recursively converts []string into []interface{} while preserving
// nested []interface{} and map[string]interface{} values.
func StructPBCompatibleValue(value interface{}) interface{} {
	switch v := value.(type) {
	case []string:
		result := make([]interface{}, len(v))
		for i, item := range v {
			result[i] = item
		}
		return result
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
