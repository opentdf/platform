package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/spf13/cobra"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
)

var (
	ns string
)

func init() {
	attributes := &cobra.Command{
		Use:   "attributes",
		Short: "attributes service actions",
	}

	add := &cobra.Command{
		Use:  "add",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return addAttributes(cmd, args...)
		},
	}
	list := &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "list available policy attributes",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listAttributes(cmd)
		},
	}
	add.Flags().StringVarP(&ns, "namespace", "N", "https://example.com/", "space separated namespace uris to search")

	attributes.AddCommand(add)
	attributes.AddCommand(list)

	ExamplesCmd.AddCommand(attributes)

}

func listAttributes(cmd *cobra.Command) error {
	s, err := newSDK()
	if err != nil {
		slog.Error("could not connect", slog.String("error", err.Error()))
		return err
	}
	defer s.Close()

	ctx := cmd.Context()

	var nsuris []string
	if ns == "" {
		slog.Info("listing namespaces")
		listResp, err := s.Namespaces.ListNamespaces(ctx, &namespaces.ListNamespacesRequest{})
		if err != nil {
			return err
		}
		slog.Info(fmt.Sprintf("found %d namespaces", len(listResp.Namespaces)))
		for _, n := range listResp.GetNamespaces() {
			nsuris = append(nsuris, n.GetFqn())
		}
	} else {
		nsuris = strings.Split(ns, " ")
	}
	for _, n := range nsuris {
		lsr, err := s.Attributes.ListAttributes(ctx, &attributes.ListAttributesRequest{
			Namespace: n,
		})
		if err != nil {
			return err
		}
		slog.Info(fmt.Sprintf("found %d attributes in namespace", len(lsr.GetAttributes())), "ns", n)
		for _, a := range lsr.GetAttributes() {
			fmt.Println("%v", a)
		}
	}
	return nil
}

func addAttributes(cmd *cobra.Command, fqns ...string) error {
	s, err := sdk.New(platformEndpoint, sdk.WithInsecurePlaintextConn())
	if err != nil {
		slog.Error("could not connect", slog.String("error", err.Error()))
		return err
	}
	defer s.Close()

	var exampleNamespace *policy.Namespace
	slog.Info("listing namespaces")
	listResp, err := s.Namespaces.ListNamespaces(context.Background(), &namespaces.ListNamespacesRequest{})
	if err != nil {
		return err
	}
	slog.Info(fmt.Sprintf("found %d namespaces", len(listResp.Namespaces)))
	for _, ns := range listResp.GetNamespaces() {
		slog.Info(fmt.Sprintf("existing namespace; name: %s, id: %s", ns.Name, ns.Id))
		if ns.Name == "example" {
			exampleNamespace = ns
		}
	}

	if exampleNamespace == nil {
		slog.Info("creating new namespace")
		resp, err := s.Namespaces.CreateNamespace(context.Background(), &namespaces.CreateNamespaceRequest{
			Name: "example.io",
		})
		if err != nil {
			return err
		}
		exampleNamespace = resp.Namespace
	}

	slog.Info("creating new attribute with hierarchy rule")
	_, err = s.Attributes.CreateAttribute(context.Background(), &attributes.CreateAttributeRequest{
		Name:        "IntellectualProperty",
		NamespaceId: exampleNamespace.Id,
		Rule:        *policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY.Enum(),
		// Values: []*attributes.ValueCreateUpdate{
		// 	{Value: "TradeSecret"},
		// 	{Value: "Proprietary"},
		// 	{Value: "BusinessSensitive"},
		// 	{Value: "Open"},
		// },
	})
	if err != nil {
		if returnStatus, ok := status.FromError(err); ok && returnStatus.Code() == codes.AlreadyExists {
			slog.Info("attribute already exists")
		} else {
			slog.Error("could not create attribute", slog.String("error", err.Error()))
			return err
		}
	} else {
		slog.Info("attribute created")
	}

	allAttr, err := s.Attributes.ListAttributes(context.Background(), &attributes.ListAttributesRequest{})
	if err != nil {
		slog.Error("could not list attributes", slog.String("error", err.Error()))
		return err
	}
	slog.Info(fmt.Sprintf("list attributes response: %s", protojson.Format(allAttr)))
	return nil
}
