package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"strings"

	"github.com/opentdf/platform/protocol/go/common"
	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/attributes"
	"github.com/opentdf/platform/protocol/go/policy/namespaces"
	"github.com/opentdf/platform/protocol/go/policy/unsafe"
	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

var (
	ns         string
	attr       string
	kas        string
	rule       string
	values     string
	unsafeBool bool
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

	remove := &cobra.Command{
		Use:     "remove",
		Aliases: []string{"rm"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return removeAttribute(cmd)
		},
	}
	remove.Flags().StringVarP(&attr, "attr", "a", "", "attribute prefix, e.g. http://name.space/attr/name")
	remove.Flags().StringVarP(&values, "values", "v", "", "list of attribute values to remove; if absent, removes all")
	remove.Flags().BoolVarP(&unsafeBool, "unsafe", "f", false, "delete for real; otherwise deactivate (soft delete)")
	attributes.AddCommand(remove)

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

func nsuuid(ctx context.Context, s *sdk.SDK, u string) (string, error) {
	url, err := url.Parse(u)
	if err != nil {
		slog.Error("namespace url.Parse", "err", err, "url", u)
		return "", errors.Join(err, ErrInvalidArgument)
	}
	listResp, err := s.Namespaces.ListNamespaces(ctx, &namespaces.ListNamespacesRequest{})
	if err != nil {
		slog.Error("ListNamespaces", "err", err)
		return "", errors.Join(err, ErrInvalidArgument)
	}
	for _, n := range listResp.GetNamespaces() {
		if n.GetName() == url.Hostname() {
			return n.GetId(), nil
		}
	}
	return "", fmt.Errorf("%w: unable to find namespace with name [%s] from [%s]", ErrNotFound, url.Hostname(), u)
}

func attruuid(ctx context.Context, s *sdk.SDK, nsu, fqn string) (string, error) {
	resp, err := s.Attributes.ListAttributes(ctx, &attributes.ListAttributesRequest{
		Namespace: nsu,
		State:     common.ActiveStateEnum_ACTIVE_STATE_ENUM_ANY,
	})
	if err != nil {
		slog.Error("ListAttributes", "err", err)
		return "", errors.Join(err, ErrInvalidArgument)
	}
	for _, a := range resp.GetAttributes() {
		if strings.ToLower(a.GetFqn()) == strings.ToLower(fqn) {
			return a.GetId(), nil
		}
	}
	return "", fmt.Errorf("%w: unable to find attibute [%s]", ErrNotFound, fqn)
}

func avuuid(ctx context.Context, s *sdk.SDK, auuid, vs string) (string, error) {
	resp, err := s.Attributes.GetAttribute(ctx, &attributes.GetAttributeRequest{Id: auuid})
	if err != nil {
		slog.Error("GetAttribute", "err", err)
		return "", errors.Join(err, ErrInvalidArgument)
	}
	for _, v := range resp.GetAttribute().GetValues() {
		if strings.ToLower(v.GetValue()) == strings.ToLower(vs) {
			return v.GetId(), nil
		}
	}
	return "", fmt.Errorf("%w: unable to find attibute value [%s]", ErrNotFound, vs)
}

func addNamespace(ctx context.Context, s *sdk.SDK, u string) (string, error) {
	url, err := url.Parse(u)
	if err != nil {
		slog.Error("url.Parse", "err", err)
		return "", errors.Join(err, ErrInvalidArgument)
	}
	resp, err := s.Namespaces.CreateNamespace(ctx, &namespaces.CreateNamespaceRequest{Name: url.Hostname()})
	if err != nil {
		slog.Error("CreateNamespace", "err", err)
		return "", errors.Join(err, ErrInvalidArgument)
	}
	return resp.Namespace.GetId(), nil
}

func addAttribute(cmd *cobra.Command) error {
	s, err := newSDK()
	if err != nil {
		slog.Error("newSDK", slog.String("error", err.Error()))
		return err
	}
	defer s.Close()

	are := regexp.MustCompile(`^(https?://[\w./]+)/attr/([^/\s]*)$`)
	m := are.FindStringSubmatch(attr)
	if len(m) < 3 || len(m[0]) == 0 {
		return fmt.Errorf("not a valid attribute fqn [%s]", attr)
	}
	auth := m[1]
	nsu, err := nsuuid(cmd.Context(), s, auth)
	if errors.Is(err, ErrNotFound) {
		nsu, err = addNamespace(cmd.Context(), s, auth)
	}
	if err != nil {
		slog.Error("upsertNamespace", "err", err)
		return err
	}
	attr, err := url.PathUnescape(m[2])
	if err != nil {
		slog.Error("url.PathUnescape(attr)", "err", err, "attr", m[2])
		return err
	}
	aid, err := upsertAttr(cmd.Context(), s, nsu, attr, strings.Split(values, " "))
	if err != nil {
		return err
	}
	slog.Info("created attribute", "passedin", attr, "id", aid)
	return nil
}

func removeAttribute(cmd *cobra.Command) error {
	s, err := newSDK()
	if err != nil {
		slog.Error("could not connect", slog.String("error", err.Error()))
		return err
	}
	defer s.Close()

	are := regexp.MustCompile(`^(https?://[\w./]+)/attr/([^/\s]*)$`)
	m := are.FindStringSubmatch(attr)
	if len(m) < 3 || len(m[0]) == 0 {
		return fmt.Errorf("not a valid attribute fqn [%s]", attr)
	}
	auth := m[1]
	nsu, err := nsuuid(cmd.Context(), s, auth)
	if err != nil {
		return err
	}
	auuid, err := attruuid(cmd.Context(), s, nsu, attr)
	if err != nil {
		return err
	}
	if values == "" {
		if unsafeBool {
			resp, err := s.Unsafe.UnsafeDeleteAttribute(cmd.Context(), &unsafe.UnsafeDeleteAttributeRequest{
				Id:  auuid,
				Fqn: strings.ToLower(attr),
			})
			if err != nil {
				slog.Error("UnsafeDeleteAttribute", "err", err, "id", auuid)
				return err
			}
			slog.Info("deleted attribute", "attr", attr, "resp", resp)
			return nil
		}
		resp, err := s.Attributes.DeactivateAttribute(cmd.Context(), &attributes.DeactivateAttributeRequest{
			Id: auuid,
		})
		if err != nil {
			slog.Error("DeactivateAttribute", "err", err, "id", auuid)
			return err
		}
		slog.Info("deactivated attribute", "attr", attr, "resp", resp)
		return nil
	} else {
		for _, v := range strings.Split(values, " ") {
			avu, err := avuuid(cmd.Context(), s, auuid, v)
			if err != nil {
				return err
			}
			if unsafeBool {
				r, err := s.Unsafe.UnsafeDeleteAttributeValue(cmd.Context(), &unsafe.UnsafeDeleteAttributeValueRequest{
					Id:  avu,
					Fqn: strings.ToLower(attr + "/value/" + url.PathEscape(v)),
				})
				if err != nil {
					slog.Error("UnsafeDeleteAttributeValue", "err", err, "id", avu)
					return err
				}
				slog.Info("deactivated attribute value", "attr", attr, "value", v, "resp", r)
			} else {
				r, err := s.Attributes.DeactivateAttributeValue(cmd.Context(), &attributes.DeactivateAttributeValueRequest{
					Id: avu,
				})
				if err != nil {
					slog.Error("DeactivateAttributeValue", "err", err, "id", avu)
					return err
				}
				slog.Info("deactivated attribute value", "attr", attr, "value", v, "resp", r)
			}
		}
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
		slog.Error("CreateAttribute", "err", err, "auth", auth, "name", name, "values", values, "rule", ruler())
		return "", err
	}
	return av.Attribute.GetId(), nil
}
