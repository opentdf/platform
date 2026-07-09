package profiles

import (
	"encoding/json"
	"sort"
)

// GetExtension decodes the extension stored under name into a value of type T.
// A missing extension returns (zero, false, nil); a decode failure returns (zero, true, err).
func GetExtension[T any](p *OtdfctlProfileStore, name string) (T, bool, error) {
	var v T
	raw, ok := p.getRawExtension(name)
	if !ok {
		return v, false, nil
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return v, true, err
	}
	return v, true, nil
}

// SetExtension marshals v to JSON and stores it under name, then persists the profile.
func SetExtension[T any](p *OtdfctlProfileStore, name string, v T) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return p.setRawExtension(name, raw)
}

// HasExtension reports whether an extension is stored under name.
func (p *OtdfctlProfileStore) HasExtension(name string) bool {
	_, ok := p.getRawExtension(name)
	return ok
}

// DeleteExtension removes the extension stored under name and persists the profile.
// It is a no-op if no such extension exists.
func (p *OtdfctlProfileStore) DeleteExtension(name string) error {
	if p.config.Extensions == nil {
		return nil
	}
	if _, ok := p.config.Extensions[name]; !ok {
		return nil
	}
	delete(p.config.Extensions, name)
	return p.store.Save()
}

// ExtensionNames returns the sorted names of all extensions stored on the profile.
func (p *OtdfctlProfileStore) ExtensionNames() []string {
	if len(p.config.Extensions) == 0 {
		return nil
	}
	names := make([]string, 0, len(p.config.Extensions))
	for name := range p.config.Extensions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// getRawExtension returns the raw JSON stored for an extension name.
func (p *OtdfctlProfileStore) getRawExtension(name string) (json.RawMessage, bool) {
	if p.config.Extensions == nil {
		return nil, false
	}
	raw, ok := p.config.Extensions[name]
	return raw, ok
}

// setRawExtension stores raw JSON under name (lazily initializing the map) and persists.
func (p *OtdfctlProfileStore) setRawExtension(name string, raw json.RawMessage) error {
	if p.config.Extensions == nil {
		p.config.Extensions = make(map[string]json.RawMessage)
	}
	p.config.Extensions[name] = raw
	return p.store.Save()
}
