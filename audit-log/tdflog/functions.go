package tdflog

import (
	"log/slog"
)


type AttributeValue struct {
	slog.Value
	Attributes []string
}

type AddAttributeValue struct {
	Attributes []string
}

func Protect(attr string, val any, attrs ...string) slog.Attr {
	return slog.Any(attr, slog.AnyValue(AttributeValue{Value: slog.AnyValue(val), Attributes: attrs}))
}

func AddAttributes(attrs ...string) slog.Attr {
	return slog.Any("", slog.AnyValue(AddAttributeValue{Attributes: attrs}))
}

