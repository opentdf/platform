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
		Args:    cobra.NoArgs,
		Aliases: []string{"ls"},
		Short:   "list available policy attributes",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listAttributes(cmd)
		},
	}
	attributes.AddCommand(add)

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

func addAttributes(cmd *cobra.Command, fqns ...string) error {
	s, err := newSDK()
	if err != nil {
		slog.Error("could not connect", slog.String("error", err.Error()))
		return err
	}
	defer s.Close()

	vre := regexp.MustCompile(`^(https?://[\w./]+)/attr/(\S*)/value/(\S*)$`)
	are := regexp.MustCompile(`^(https?://[\w./]+)/attr/([^/\s]*)$`)
	nre := regexp.MustCompile(`^(https?://[\w./]+)/?$`)
	for _, u := range fqns {
		e := fmt.Errorf("not a valid attribute fqn [%s]", u)
		if m := vre.FindStringSubmatch(u); len(m) == 4 && len(m[0]) > 0 {
			auth := m[1]
			attr, err := url.PathUnescape(m[2])
			if err != nil {
				return e
			}
			val, err := url.PathUnescape(m[3])
			if err != nil {
				return e
			}
			aid, err := upsertAttr(cmd.Context(), s, auth, attr)
			if err != nil {
				return err
			}
			cavr, err := s.Attributes.CreateAttributeValue(cmd.Context(), &attributes.CreateAttributeValueRequest{
				AttributeId: aid,
				Value:       val,
			})
			if err != nil {
				return err
			}
			slog.Info("created attribute value", "passedin", u, "computed", cavr.GetValue().GetFqn())
		} else if m := are.FindStringSubmatch(u); len(m) == 3 && len(m[0]) > 0 {
			auth := m[1]
			attr, err := url.PathUnescape(m[2])
			if err != nil {
				return err
			}
			aid, err := upsertAttr(cmd.Context(), s, auth, attr)
			if err != nil {
				return err
			}
			slog.Info("created attribute", "passedin", u, "id", aid)
		} else if m := nre.FindStringSubmatch(u); len(m) == 2 && len(m[0]) > 0 {
			slog.Error("unimplemented: create namespace")
			return e
		} else {
			return e
		}
	}
	return nil
}

func upsertAttr(ctx context.Context, s *sdk.SDK, auth, attr string) (string, error) {
	fqn := fmt.Sprintf("%s/attr/%s", auth, url.PathEscape(attr))
	av, err :=
		s.Attributes.GetAttributeValuesByFqns(ctx, &attributes.GetAttributeValuesByFqnsRequest{
			Fqns: []string{fqn},
			WithValue: &policy.AttributeValueSelector{
				WithKeyAccessGrants: true,
			},
		})
	if err != nil {
		return "", err
	}
	if len(av.GetFqnAttributeValues()) == 1 {
		return av.GetFqnAttributeValues()[fqn].GetAttribute().GetId(), nil
	}
	u, err := url.Parse(auth)
	if err != nil {
		return "", err
	}
	a, err := s.Attributes.CreateAttribute(ctx, &attributes.CreateAttributeRequest{
		Name: u.Host,
	})
	if err != nil {
		return "", err
	}

	return a.Attribute.GetId(), nil
}
