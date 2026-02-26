package sdk

import (
	"encoding/json"
	"maps"
)

func buildResourceMetadata(cfg *TDFConfig, totalPlaintextSize int64) map[string]any {
	resourceMetadata := make(map[string]any)

	if cfg.resourceMetadataSet {
		maps.Copy(resourceMetadata, cfg.resourceMetadata)
	} else {
		resourceMetadata[encMetadataKeyByteSize] = totalPlaintextSize
	}

	if len(resourceMetadata) == 0 {
		return nil
	}
	return resourceMetadata
}

func mergeEncryptedMetadata(base string, resourceMetadata map[string]any) (string, error) {
	if len(resourceMetadata) == 0 {
		return base, nil
	}

	if base != "" {
		var baseObject map[string]any
		if err := json.Unmarshal([]byte(base), &baseObject); err == nil {
			baseObject["resourceMetadata"] = mergeResourceMetadata(baseObject["resourceMetadata"], resourceMetadata)
			merged, err := json.Marshal(baseObject)
			if err != nil {
				return "", err
			}
			return string(merged), nil
		}
	}

	envelope := map[string]any{
		"resourceMetadata": resourceMetadata,
	}
	if base != "" {
		envelope["metadata"] = base
	}

	merged, err := json.Marshal(envelope)
	if err != nil {
		return "", err
	}
	return string(merged), nil
}

func mergeResourceMetadata(existing any, additions map[string]any) map[string]any {
	existingMap, ok := existing.(map[string]any)
	if !ok {
		existingMap = make(map[string]any)
	}
	for k, v := range additions {
		existingMap[k] = v
	}
	return existingMap
}
