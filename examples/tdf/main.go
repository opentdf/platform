package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/opentdf/opentdf-v2-poc/internal/crypto"
	"github.com/opentdf/opentdf-v2-poc/sdk"
)

type DelegatedKey struct {
	Key         []byte `json:"key"`
	FingerPrint string `json:"fingerprint"`
}

func main() {

	server, _, _, err := sdk.RunKAS()
	if err != nil {
		panic(err)
	}
	defer server.Close()

	cfg, err := sdk.NewTDFConfig()
	if err != nil {
		panic(err)
	}

	// mock hsm public key
	hsmKeys, err := crypto.NewRSAKeyPair(2048)
	if err != nil {
		panic(err)
	}

	cfg.OnEncryptedMetaDataCreate = func(kao *sdk.KeyAccess) ([]byte, error) {
		slog.Info("HSM OnEncryptedMetaDataCreate")
		pk, err := crypto.RandomBytes(32)
		if err != nil {
			return nil, err
		}

		fingerPrint, err := hsmKeys.PublicKeyFingerPrint()

		delgatedKey := DelegatedKey{
			Key:         pk,
			FingerPrint: fingerPrint,
		}

		return json.Marshal(delgatedKey)
	}

	cfg.OnSplitKeyBuild = func(kao *sdk.KeyAccess) ([]byte, error) {
		slog.Info("HSM OnSplitKeyBuild")

		delgatedKey := DelegatedKey{}
		err := json.Unmarshal([]byte(kao.EncryptedMetadata), &delgatedKey)
		if err != nil {
			return nil, err
		}

		// Now we wrap the delegated key with the HSM public key
		// and return it.
		key := delgatedKey.Key

		pubKey, err := hsmKeys.PublicKeyInPemFormat()
		if err != nil {
			return nil, err
		}

		asym, err := crypto.NewAsymEncryption(pubKey)
		if err != nil {
			return nil, err
		}

		// Save the wrapped key in the delegated key.
		delgatedKey.Key, err = asym.Encrypt(key)
		if err != nil {
			return nil, err
		}

		dk, err := json.Marshal(delgatedKey)
		if err != nil {
			return nil, err
		}

		kao.EncryptedMetadata = string(dk)

		return key, nil
	}

	fs, err := os.Open("sensitive.txt")
	if err != nil {
		panic(err)
	}

	fsWriter, err := os.Create("sensitive.txt.zip")
	if err != nil {
		panic(err)
	}

	cfg.AddKasInformation([]sdk.KASInfo{
		{
			URL:       server.URL,
			PublicKey: "",
		},
	})

	tdf, err := sdk.Create(*cfg, fs, fsWriter)
	if err != nil {
		panic(err)
	}

	fsWriter.Close()

	manifest, err := json.MarshalIndent(tdf.Manifest, "", "  ")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(manifest))

	// We should not be able to decrypt normally
	// sdk.GetPayload(sdk.AuthConfig{

	// },,)
}
