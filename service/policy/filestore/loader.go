package filestore

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadSchema reads the snapshot at path and unmarshals it into a Schema. The
// file extension selects the codec (.yaml/.yml → YAML, .json → JSON).
func LoadSchema(path string) (*Schema, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("filestore: read %q: %w", path, err)
	}
	var s Schema
	switch ext := strings.ToLower(filepath.Ext(path)); ext {
	case ".json":
		if err := json.Unmarshal(data, &s); err != nil {
			return nil, fmt.Errorf("filestore: parse json %q: %w", path, err)
		}
	case ".yaml", ".yml", "":
		if err := yaml.Unmarshal(data, &s); err != nil {
			return nil, fmt.Errorf("filestore: parse yaml %q: %w", path, err)
		}
	default:
		return nil, fmt.Errorf("filestore: unsupported extension %q", ext)
	}
	return &s, nil
}
