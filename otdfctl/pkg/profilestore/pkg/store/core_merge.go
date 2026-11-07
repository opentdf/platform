package store

import "encoding/json"

// MergeCore replaces the core configuration using its normal JSON representation,
// retaining only the latest namespaced extensions. Unknown core fields are not an
// extension mechanism; consumers must put their properties in a namespace.
func MergeCore(object map[string]json.RawMessage, core any) (map[string]json.RawMessage, error) {
	data, err := json.Marshal(core)
	if err != nil {
		return nil, err
	}
	fields, err := DecodeObject(data)
	if err != nil {
		return nil, err
	}
	if extensions, ok := object["extensions"]; ok {
		fields["extensions"] = extensions
	}
	return fields, nil
}
