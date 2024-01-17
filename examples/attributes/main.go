package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/opentdf/opentdf-v2-poc/sdk"
	"github.com/opentdf/opentdf-v2-poc/sdk/attributes"
	"github.com/opentdf/opentdf-v2-poc/sdk/common"
)

func main() {
	definition := attributes.AttributeDefinition{
		Name: "relto",
		Rule: attributes.AttributeDefinition_ATTRIBUTE_RULE_TYPE_ANY_OF,
		Values: []*attributes.AttributeDefinitionValue{
			{
				Value: "USA",
			},
			{
				Value: "GBR",
			},
		},
		Descriptor_: &common.ResourceDescriptor{
			Version:     1,
			Namespace:   "demo.com",
			Fqn:         "http://demo.com/attr/relto",
			Description: "The relto attribute is used to describe the relationship of the resource to the country of origin. ",
			Labels:      map[string]string{"origin": "Country of Origin"},
			Type:        common.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION,
		},
	}

	s, err := sdk.New("localhost:9000", sdk.WithInsecureConn())
	if err != nil {
		slog.Error("could not connect", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer s.Close()

	_, err = s.Attributes.CreateAttribute(context.Background(), &attributes.CreateAttributeRequest{
		Definition: &definition,
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
	for _, attr := range allAttr.Definitions {
		slog.Info("attribute", slog.String("name", attr.Name))
		slog.Info("attribute", slog.String("rule", attr.Rule.String()))
		for _, val := range attr.Values {
			slog.Info("attribute", slog.String("name", attr.Name), slog.String("value", val.Value))
		}
	}

}
