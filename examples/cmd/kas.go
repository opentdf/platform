package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

var key string

func init() {
	kasc := &cobra.Command{
		Use:   "kas",
		Short: "manage kas registry",
	}

	update := &cobra.Command{
		Use:     "update",
		Aliases: []string{"add"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return updateKas(cmd)
		},
	}
	update.Flags().StringVarP(&kas, "kas", "k", "", "kas uri")
	update.Flags().StringVarP(&key, "public-key", "", "", "public key value, e.g. $(<my-key.pem)")
	kasc.AddCommand(update)

	list := &cobra.Command{
		Use:     "list",
		Args:    cobra.NoArgs,
		Aliases: []string{"ls"},
		Short:   "list stored kas information",
		RunE: func(cmd *cobra.Command, args []string) error {
			return listKases(cmd)
		},
	}
	list.Flags().BoolVarP(&longformat, "long", "l", false, "include details")
	kasc.AddCommand(list)

	rm := &cobra.Command{
		Use:     "remove",
		Args:    cobra.NoArgs,
		Aliases: []string{"rm"},
		Short:   "remove kas by uri",
		RunE: func(cmd *cobra.Command, args []string) error {
			return removeKas(cmd)
		},
	}
	rm.Flags().StringVarP(&kas, "kas", "k", "", "kas uri")
	kasc.AddCommand(rm)

	ExamplesCmd.AddCommand(kasc)
}

func listKases(cmd *cobra.Command) error {
	s, err := newSDK()
	if err != nil {
		slog.Error("could not connect", "err", err)
		return err
	}
	defer s.Close()

	r, err := s.KeyAccessServerRegistry.ListKeyAccessServers(cmd.Context(), &kasregistry.ListKeyAccessServersRequest{})
	if err != nil {
		slog.Error("ListKeyAccessServers", "error", err)
		return err
	}

	slog.Info("listing kas registry")

	if len(r.GetKeyAccessServers()) == 0 {
		cmd.Println("no key access servers registered")
		return nil
	}

	for _, k := range r.GetKeyAccessServers() {
		if longformat {
			fmt.Printf("%s\t%s\t%s\n", k.GetUri(), k.GetId(), k.GetPublicKey())
		} else {
			fmt.Printf("%s\n", k.GetUri())
		}
	}
	return nil
}

func upsertKAS(ctx context.Context, s *sdk.SDK, uri string, pk *policy.PublicKey) (string, error) {
	r, err := s.KeyAccessServerRegistry.ListKeyAccessServers(ctx, &kasregistry.ListKeyAccessServersRequest{})
	if err != nil {
		slog.Error("ListKeyAccessServers", "err", err)
		return "", err
	}
	for _, ki := range r.GetKeyAccessServers() {
		if strings.ToLower(uri) == strings.ToLower(ki.GetUri()) {
			oldpk := ki.GetPublicKey()
			recreate := false
			switch {
			case pk != nil && pk.GetLocal() == "" && oldpk.GetLocal() == "":
				recreate = pk.GetRemote() != oldpk.GetRemote()
			case pk != nil:
				// previously remote, now local, or local and changed
				recreate = pk.GetLocal() != oldpk.GetLocal()
			}
			if !recreate {
				return ki.GetId(), nil
			}
			_, err := s.KeyAccessServerRegistry.DeleteKeyAccessServer(ctx, &kasregistry.DeleteKeyAccessServerRequest{Id: ki.GetId()})
			if err != nil {
				slog.Error("DeleteKeyAccessServer", "err", err)
				return "", err
			}
			// Do we have a unique constraint on kas uri?
			// if not, this needs to be a continue (and we need to clean up some other stuff)
			break
		}
	}
	if pk == nil {
		pk = new(policy.PublicKey)
		pk.PublicKey = &policy.PublicKey_Remote{
			Remote: uri + "/v2/kas_public_key",
		}
	}
	ur, err := s.KeyAccessServerRegistry.CreateKeyAccessServer(ctx, &kasregistry.CreateKeyAccessServerRequest{
		Uri:       uri,
		PublicKey: pk,
	})
	if err != nil {
		slog.Error("CreateKeyAccessServer", "uri", uri, "publicKey", uri+"/v2/kas_public_key")
		return "", err
	}
	return ur.KeyAccessServer.GetId(), nil
}

func updateKas(cmd *cobra.Command) error {
	s, err := newSDK()
	if err != nil {
		slog.Error("could not connect", "err", err)
		return err
	}
	defer s.Close()

	var pk *policy.PublicKey
	if key != "" {
		pk = new(policy.PublicKey)
		pk.PublicKey = &policy.PublicKey_Local{
			Local: key,
		}
	}

	kasid, err := upsertKAS(cmd.Context(), s, kas, pk)
	if err != nil {
		return err
	}
	slog.Info("registered kas", "passedin", attr, "id", kasid, "kas", kas)
	return nil
}

func removeKas(cmd *cobra.Command) error {
	s, err := newSDK()
	if err != nil {
		slog.Error("could not connect", "err", err)
		return err
	}
	defer s.Close()

	r, err := s.KeyAccessServerRegistry.ListKeyAccessServers(cmd.Context(), &kasregistry.ListKeyAccessServersRequest{})
	if err != nil {
		slog.Error("ListKeyAccessServers", "err", err)
		return err
	}
	deletedSomething := false
	for _, ki := range r.GetKeyAccessServers() {
		if strings.ToLower(kas) == strings.ToLower(ki.GetUri()) {
			_, err := s.KeyAccessServerRegistry.DeleteKeyAccessServer(cmd.Context(), &kasregistry.DeleteKeyAccessServerRequest{Id: ki.GetId()})
			if err != nil {
				slog.Error("DeleteKeyAccessServer", "err", err)
				return err
			}
			deletedSomething = true
		}
	}
	if !deletedSomething {
		return fmt.Errorf("nothing deleted; [%s] not found", kas)
	} else {
		slog.Info("deleted kas registration", "kas", kas)
	}
	return nil
}
