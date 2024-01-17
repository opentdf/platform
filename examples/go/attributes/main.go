package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/opentdf/opentdf-v2-poc/gen/attributes"
	"github.com/opentdf/opentdf-v2-poc/gen/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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

	conn, err := grpc.Dial("localhost:9000", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		slog.Error("could not connect", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer conn.Close()

	attrClient := attributes.NewAttributesServiceClient(conn)

	_, err = attrClient.CreateAttribute(context.Background(), &attributes.CreateAttributeRequest{
		Definition: &definition,
	})
	if err != nil {
		slog.Error("could not create attribute", slog.String("error", err.Error()))
		os.Exit(1)
	}

	slog.Info("attribute created")

	allAttr, err := attrClient.ListAttributes(context.Background(), &attributes.ListAttributesRequest{})
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
