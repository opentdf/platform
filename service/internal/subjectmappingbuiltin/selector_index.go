package subjectmappingbuiltin

import "github.com/opentdf/platform/lib/flattening"

type selectorIndex map[string][]interface{}

func indexSelectors(entity flattening.Flattened) selectorIndex {
	index := make(selectorIndex, len(entity.Items))
	for _, item := range entity.Items {
		index[item.Key] = append(index[item.Key], item.Value)
	}
	return index
}

func (i selectorIndex) lookup(selector string) []interface{} { return i[selector] }
