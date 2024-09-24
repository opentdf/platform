package tdflog

import (
	"log/slog"
)

func isEncryptAttr(attr slog.Attr) bool {
	_, ok := attr.Value.Any().(AttributeValue)
	return ok
}

func isAddAttr(attr slog.Attr) bool {
	_, ok := attr.Value.Any().(AddAttributeValue)
	return ok
}

func cleanEncryptAttr(attr *slog.Attr) []string {
	attrValue, ok := attr.Value.Any().(AttributeValue)
	if !ok {
		return []string{} 
	}
	attr.Value = attrValue.Value
	return attrValue.Attributes
}

func getAttributes(attr *slog.Attr) []string {
	attrValue := attr.Value.Any().(AddAttributeValue)
	return attrValue.Attributes
}


