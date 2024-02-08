package main

import (
	"context"
	"log/slog"
	"os"
	"strconv"

	"github.com/opentdf/opentdf-v2-poc/sdk"
	"github.com/opentdf/opentdf-v2-poc/sdk/attributes"
)

func main() {
	s, err := sdk.New("localhost:9000", sdk.WithInsecureConn())
	if err != nil {
		slog.Error("could not connect", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer s.Close()

	_, err = s.Attributes.CreateAttribute(context.Background(), &attributes.CreateAttributeRequest{
		Attribute: &attributes.AttributeCreateUpdate{
			Name:        "relto",
			NamespaceId: "",
			Rule:        *attributes.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF.Enum(),
		},
	})
	if err != nil {
		slog.Error("could not create attribute", slog.String("error", err.Error()))
		os.Exit(1)
	}

	slog.Info("attribute created")

	allAttr, err := s.Attributes.ListAttributes(context.Background(), &attributes.ListAttributesRequest{})
	if err != nil {
		slog.Error("could not list attributes", slog.String("error", err.Error()))
		os.Exit(1)
	}
	for _, attr := range allAttr.Attributes {
		slog.Info("attribute", slog.String("id", attr.Id))
		slog.Info("attribute", slog.String("name", attr.Name))
		slog.Info("attribute", slog.String("rule", attr.Rule.String()))
		slog.Info("attribute", slog.Any("metadata", attr.Metadata))
		for i, val := range attr.Values {
			slog.Info("attribute: "+strconv.Itoa(i), slog.String("id", val.Id))
			slog.Info("attribute: "+strconv.Itoa(i), slog.String("value", val.Value))
			slog.Info("attribute: "+strconv.Itoa(i), slog.Any("members", val.Members))
			slog.Info("attribute: "+strconv.Itoa(i), slog.Any("metadata", val.Metadata))
		}
	}

}
