package main

import (
	"context"
	"log/slog"
	"os"

	attributesv1 "github.com/opentdf/opentdf-v2-poc/gen/attributes/v1"
	commonv1 "github.com/opentdf/opentdf-v2-poc/gen/common/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	definition := attributesv1.AttributeDefinition{
		Name: "relto",
		Rule: attributesv1.AttributeDefinition_ATTRIBUTE_RULE_TYPE_ANY_OF,
		Values: []*attributesv1.AttributeDefinitionValue{
			{
				Value: "USA",
			},
			{
				Value: "GBR",
			},
		},
		Descriptor_: &commonv1.ResourceDescriptor{
			Version:     1,
			Namespace:   "demo.com",
			Fqn:         "http://demo.com/attr/relto",
			Description: "The relto attribute is used to describe the relationship of the resource to the country of origin. ",
			Labels:      map[string]string{"origin": "Country of Origin"},
			Type:        commonv1.PolicyResourceType_POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION,
		},
	}

	conn, err := grpc.Dial("localhost:9000", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		slog.Error("could not connect", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer conn.Close()

	attrClient := attributesv1.NewAttributesServiceClient(conn)

	_, err = attrClient.CreateAttribute(context.Background(), &attributesv1.CreateAttributeRequest{
		Definition: &definition,
	})
	if err != nil {
		slog.Error("could not create attribute", slog.String("error", err.Error()))
		os.Exit(1)
	}

	slog.Info("attribute created")

	allAttr, err := attrClient.ListAttributes(context.Background(), &attributesv1.ListAttributesRequest{})
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
