package flattening

import (
	"errors"
	"fmt"
)

type Flattened struct {
	Items []Item `json:"flattened"`
	// index provides O(1) selector lookups; populated by Flatten
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
	// Fallback for backwards compatibility (e.g., if Flattened was created without Flatten)
	itemsToReturn := []interface{}{}
	for _, item := range flat.Items {
		if item.Key == selector {
			itemsToReturn = append(itemsToReturn, item.Value)
		}
	}
	return itemsToReturn
}

// Flatten returns a Flattened struct with an index for O(1) lookups via GetFromFlattened.
// Use this when you will perform lookups by selector.
func Flatten(m map[string]interface{}) (Flattened, error) {
	idx := make(map[string][]interface{})
	items, err := flattenInterface(m, idx)
	if err != nil {
		return Flattened{}, err
	}
	return Flattened{
		Items: items,
		index: idx,
	}, nil
}

func flattenInterface(i interface{}, idx map[string][]interface{}) ([]Item, error) {
	o := []Item{}
	switch child := i.(type) {
	case map[string]interface{}:
		for k, v := range child {
			nm, err := flattenInterface(v, idx)
			if err != nil {
				return nil, err
			}
			for _, item := range nm {
				key := "." + k + item.Key
				o = append(o, Item{Key: key, Value: item.Value})
				if idx != nil {
					idx[key] = append(idx[key], item.Value)
				}
			}
		}
	case []interface{}:
		for index, item := range child {
			kIdx := fmt.Sprintf("[%v]", index)
			kAny := "[]"
			flattenedItem, err := flattenInterface(item, idx)
			if err != nil {
				return nil, err
			}
			for _, it := range flattenedItem {
				keyIdx := kIdx + it.Key
				keyAny := kAny + it.Key
				o = append(o, Item{Key: keyIdx, Value: it.Value})
				o = append(o, Item{Key: keyAny, Value: it.Value})
				if idx != nil {
					idx[keyIdx] = append(idx[keyIdx], it.Value)
					idx[keyAny] = append(idx[keyAny], it.Value)
				}
			}
		}
	case bool, int, string, float64, float32:
		o = append(o, Item{Key: "", Value: child})
		if idx != nil {
			idx[""] = append(idx[""], child)
		}
	default:
		return nil, errors.New("unrecognized item in json")
	}
	return o, nil
}
