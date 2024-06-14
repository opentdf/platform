package flattening

import (
	"errors"
	"fmt"
)

type Flattened struct {
	Items []Item `json:"flattened"`
}

type Item struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

func GetFromFlattened(flat Flattened, selector string) ([]interface{}, error) {
	itemsToReturn := []interface{}{}
	for _, item := range flat.Items {
		if item.Key == selector {
			itemsToReturn = append(itemsToReturn, item.Value)
		}
	}
	return itemsToReturn, nil
}

func Flatten(m map[string]interface{}) (Flattened, error) {
	flattened := Flattened{}
	items, err := flattenInterface(m)
	if err != nil {
		return Flattened{}, err
	}
	flattened.Items = items
	return flattened, nil
}

func flattenInterface(i interface{}) ([]Item, error) {
	o := []Item{}
	switch child := i.(type) {
	case map[string]interface{}:
		for k, v := range child {
			nm, err := flattenInterface(v)
			if err != nil {
				return nil, err
			}
			for _, item := range nm {
				o = append(o, Item{Key: "." + k + item.Key, Value: item.Value})
			}
		}
	case []interface{}:
		for idx, item := range child {
			k := fmt.Sprintf("[%v]", idx)
			k2 := "[]"
			flattenedItem, err := flattenInterface(item)
			if err != nil {
				return nil, err
			}
			for _, item := range flattenedItem {
				o = append(o, Item{Key: k + item.Key, Value: item.Value})
				o = append(o, Item{Key: k2 + item.Key, Value: item.Value})
			}
		}
	case bool, int, string, float64, float32:
		o = append(o, Item{Key: "", Value: child})
	default:
		return nil, errors.New("unrecognozed item in json")
	}
	return o, nil
}
