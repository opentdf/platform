package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

var (
	ns     string
	attr   string
	rule   string
	values string
)

func init() {
	attributes := &cobra.Command{
		Use:   "attributes",
		Short: "attributes service actions",
	}

	add := &cobra.Command{
		Use:  "add",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return addAttribute(cmd)
		},
	}
	add.Flags().StringVarP(&attr, "attr", "a", "", "attribute prefix, e.g. http://name.space/attr/name")
	add.Flags().StringVarP(&rule, "rule", "", "allof", "attribute type, either allof, anyof, or hierarchy")
	add.Flags().StringVarP(&values, "values", "v", "", "list of attribute values")
	attributes.AddCommand(add)

	list := &cobra.Command{
		Use:     "list",
		Args:    cobra.NoArgs,
		Aliases: []string{"ls"},
		Short:   "list available policy attributes",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listAttributes(cmd)
		},
	}

	list.Flags().StringVarP(&ns, "namespace", "N", "", "space separated namespace uris to search")
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
		u, err := url.Parse(n)
		if err != nil {
			return err
		}
		lsr, err := s.Attributes.ListAttributes(ctx, &attributes.ListAttributesRequest{
			// namespace here must be the namespace name
			Namespace: u.Host,
		})
		if err != nil {
			return err
		}
		slog.Info(fmt.Sprintf("found %d attributes in namespace", len(lsr.GetAttributes())), "ns", n)
		for _, a := range lsr.GetAttributes() {
			fmt.Printf("%s\n", a.GetFqn())
			for _, v := range a.GetValues() {
				fmt.Printf("\t%s\n", v.GetFqn())
			}
		}
	}
	return nil
}

func addAttribute(cmd *cobra.Command) error {
	s, err := newSDK()
	if err != nil {
		slog.Error("could not connect", slog.String("error", err.Error()))
		return err
	}
	defer s.Close()

	are := regexp.MustCompile(`^(https?://[\w./]+)/attr/([^/\s]*)$`)
	if m := are.FindStringSubmatch(attr); len(m) == 3 && len(m[0]) > 0 {
		auth := m[1]
		authuri, err := url.Parse(auth)
		if err != nil {
			return err
		}
		attr, err := url.PathUnescape(m[2])
		nsname := authuri.Host
		if err != nil {
			return err
		}
		aid, err := upsertAttr(cmd.Context(), s, nsname, attr, strings.Split(values, " "))
		if err != nil {
			return err
		}
		slog.Info("created attribute", "passedin", attr, "id", aid)
	} else {
		return fmt.Errorf("not a valid attribute fqn [%s]", attr)
	}
	return nil
}

func ruler() policy.AttributeRuleTypeEnum {
	switch strings.ToLower(rule) {
	case "allof":
		return policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF
	case "anyof":
		return policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF
	case "hierarchy":
		return policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF
	default:
		return policy.AttributeRuleTypeEnum_ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF
	}
}

func upsertAttr(ctx context.Context, s *sdk.SDK, auth, name string, values []string) (string, error) {
	av, err :=
		s.Attributes.CreateAttribute(ctx, &attributes.CreateAttributeRequest{
			NamespaceId: auth,
			Name:        name,
			Rule:        ruler(),
			Values:      values,
		})
	if err != nil {
		return "", err
	}
	return av.Attribute.GetId(), nil
}
