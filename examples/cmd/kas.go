//nolint:forbidigo // Sample code
package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/opentdf/platform/protocol/go/policy"
	"github.com/opentdf/platform/protocol/go/policy/kasregistry"
	"github.com/opentdf/platform/sdk"
	"github.com/spf13/cobra"
)

var algorithm, kas, key, keyIdentifier string

func init() {
	kasc := &cobra.Command{
		Use:   "kas",
		Short: "manage kas registry",
	}

	update := &cobra.Command{
		Use:     "update",
		Aliases: []string{"add"},
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return updateKas(cmd)
		},
	}
	// Note we currently only store one pk at a time.
	update.Flags().StringVarP(&algorithm, "algorithm", "", "", "algorithm used with the public key")
	update.Flags().StringVarP(&kas, "kas", "k", "", "kas uri")
	update.Flags().StringVarP(&key, "public-key", "", "", "public key value, e.g. $(<my-key.pem)")
	update.Flags().StringVarP(&keyIdentifier, "kid", "", "", "key identifier used to uniquely identify a key across rotations")

	kasc.AddCommand(update)

	list := &cobra.Command{
		Use:     "list",
		Args:    cobra.NoArgs,
		Aliases: []string{"ls"},
		Short:   "list stored kas information",
		RunE: func(cmd *cobra.Command, _ []string) error {
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
		RunE: func(cmd *cobra.Command, _ []string) error {
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
		slog.Error("could not connect", slog.Any("error", err))
		return err
	}
	defer s.Close()

	r, err := s.KeyAccessServerRegistry.ListKeyAccessServers(cmd.Context(), &kasregistry.ListKeyAccessServersRequest{})
	if err != nil {
		slog.Error("failed to ListKeyAccessServers", slog.Any("error", err))
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

func upsertKasRegistration(ctx context.Context, s *sdk.SDK, uri string, pk *policy.PublicKey) (string, error) {
	r, err := s.KeyAccessServerRegistry.ListKeyAccessServers(ctx, &kasregistry.ListKeyAccessServersRequest{})
	if err != nil {
		slog.Error("failed to ListKeyAccessServers", slog.Any("error", err))
		return "", err
	}
	for _, ki := range r.GetKeyAccessServers() {
		if strings.EqualFold(uri, ki.GetUri()) {
			oldpk := ki.GetPublicKey()
			recreate := false
			switch {
			case pk != nil && len(pk.GetCached().GetKeys()) == 0 && len(oldpk.GetCached().GetKeys()) == 0:
				recreate = pk.GetRemote() != oldpk.GetRemote()
			case pk != nil:
				// previously remote, now local, or local and changed
				recreate = pk.GetCached() != oldpk.GetCached()
			}
			if !recreate {
				return ki.GetId(), nil
			}
			_, err := s.KeyAccessServerRegistry.DeleteKeyAccessServer(ctx, &kasregistry.DeleteKeyAccessServerRequest{Id: ki.GetId()})
			if err != nil {
				slog.Error("failed to DeleteKeyAccessServer", slog.Any("error", err))
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
		slog.Error("failed to CreateKeyAccessServer",
			slog.String("uri", uri),
			slog.String("public_key", uri+"/v2/kas_public_key"),
			slog.Any("error", err),
		)
		return "", err
	}
	return ur.GetKeyAccessServer().GetId(), nil
}

func algString2Proto(a string) policy.KasPublicKeyAlgEnum {
	switch strings.ToLower(a) {
	case "ec:secp256r1":
		return policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_EC_SECP256R1
	case "rsa:2048":
		return policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_RSA_2048
	}
	return policy.KasPublicKeyAlgEnum_KAS_PUBLIC_KEY_ALG_ENUM_UNSPECIFIED
}

func updateKas(cmd *cobra.Command) error {
	s, err := newSDK()
	if err != nil {
		slog.Error("could not connect", slog.Any("error", err))
		return err
	}
	defer s.Close()

	var pk *policy.PublicKey
	switch {
	case keyIdentifier != "":
		if key == "" || algorithm == "" {
			err := errors.New("if --kid is found, --public-key and --algorithm must also be specified")
			return err
		}
		pk = new(policy.PublicKey)
		pk.PublicKey = &policy.PublicKey_Cached{
			Cached: &policy.KasPublicKeySet{
				Keys: []*policy.KasPublicKey{
					{
						Pem: key,
						Kid: keyIdentifier,
						Alg: algString2Proto(algorithm),
					},
				},
			},
		}
	case key != "":
		pk = new(policy.PublicKey)
		pk.PublicKey = &policy.PublicKey_Cached{
			Cached: &policy.KasPublicKeySet{
				Keys: []*policy.KasPublicKey{
					{
						Pem: key,
						Alg: algString2Proto(algorithm),
					},
				},
			},
		}
	}

	kasid, err := upsertKasRegistration(cmd.Context(), s, kas, pk)
	if err != nil {
		return err
	}
	slog.Info("registered kas",
		slog.String("passedin", attr),
		slog.String("id", kasid),
		slog.String("kas", kas),
	)
	return nil
}

func removeKas(cmd *cobra.Command) error {
	s, err := newSDK()
	if err != nil {
		slog.Error("could not connect", slog.Any("error", err))
		return err
	}
	defer s.Close()

	r, err := s.KeyAccessServerRegistry.ListKeyAccessServers(cmd.Context(), &kasregistry.ListKeyAccessServersRequest{})
	if err != nil {
		slog.Error("failed to ListKeyAccessServers", slog.Any("error", err))
		return err
	}
	deletedSomething := false
	for _, ki := range r.GetKeyAccessServers() {
		if strings.EqualFold(kas, ki.GetUri()) {
			_, err := s.KeyAccessServerRegistry.DeleteKeyAccessServer(cmd.Context(), &kasregistry.DeleteKeyAccessServerRequest{Id: ki.GetId()})
			if err != nil {
				slog.Error("failed to DeleteKeyAccessServer", slog.Any("error", err))
				return err
			}
			deletedSomething = true
		}
	}
	if !deletedSomething {
		return fmt.Errorf("nothing deleted; [%s] not found", kas)
	}

	slog.Info("deleted kas registration", slog.String("kas", kas))
	return nil
}
