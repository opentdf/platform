package flattening

import (
	"errors"
	"fmt"
)

// indexThreshold is the minimum number of items before we build an index.
// For smaller structures, linear scan is faster than map overhead.
const indexThreshold = 8

type Flattened struct {
	Items []Item `json:"flattened"`
	// index provides O(1) selector lookups; populated by Flatten for structures >= indexThreshold
	index map[string][]interface{}
}

type Item struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

func GetFromFlattened(flat Flattened, selector string) []interface{} {
	// Fast-path: use prebuilt index for O(1) lookup
	if flat.index != nil {
		if vals, ok := flat.index[selector]; ok {
			return vals
		}
		return nil
	}
	// Fallback: linear scan for small structures or backwards compatibility
	var itemsToReturn []interface{}
	for _, item := range flat.Items {
		if item.Key == selector {
			itemsToReturn = append(itemsToReturn, item.Value)
		}
	}
	return itemsToReturn
}

// Flatten returns a Flattened struct with an index for O(1) lookups via GetFromFlattened.
// For small structures (< indexThreshold items), the index is skipped and lookups use linear scan.
func Flatten(m map[string]interface{}) (Flattened, error) {
	items, err := flattenInterface(m)
	if err != nil {
		return Flattened{}, err
	}

	// Build index in a separate pass, only for larger structures
	idx := buildIndex(items)

	return Flattened{
		Items: items,
		index: idx,
	}, nil
}

// buildIndex constructs the selector index from flattened items.
// Returns nil for small structures where linear scan is faster.
func buildIndex(items []Item) map[string][]interface{} {
	if len(items) < indexThreshold {
		return nil
	}

	idx := make(map[string][]interface{}, len(items))
	for _, it := range items {
		idx[it.Key] = append(idx[it.Key], it.Value)
	}
	return idx
}

func flattenInterface(i interface{}) ([]Item, error) {
	var o []Item
	switch child := i.(type) {
	case map[string]interface{}:
		for k, v := range child {
			nm, err := flattenInterface(v)
			if err != nil {
				return nil, err
			}
			for _, item := range nm {
				key := "." + k + item.Key
				o = append(o, Item{Key: key, Value: item.Value})
			}
		}
	case []interface{}:
		for index, item := range child {
			kIdx := fmt.Sprintf("[%v]", index)
			kAny := "[]"
			flattenedItem, err := flattenInterface(item)
			if err != nil {
				return nil, err
			}
			for _, it := range flattenedItem {
				keyIdx := kIdx + it.Key
				keyAny := kAny + it.Key
				o = append(o, Item{Key: keyIdx, Value: it.Value})
				o = append(o, Item{Key: keyAny, Value: it.Value})
			}
		}
	case bool, int, string, float64, float32:
		o = append(o, Item{Key: "", Value: child})
	default:
		return nil, errors.New("unrecognized item in json")
	}
	return o, nil
}
