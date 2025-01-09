package security

import (
	"fmt"

	"github.com/mitchellh/mapstructure"
)

// Copied from service/kas/access to avoid dep loop. To be removed.
type CurrentKeyFor struct {
	Algorithm   string `mapstructure:"alg"`
	KID         string `mapstructure:"kid"`
	Private     string `mapstructure:"private"`
	Certificate string `mapstructure:"cert"`
	Active      bool   `mapstructure:"active"`
	Legacy      bool   `mapstructure:"legacy"`
}

// locate finds the index of the key in the Keyring slice.
func (k *KASConfigDupe) locate(kid string) (int, bool) {
	for i, key := range k.Keyring {
		if key.KID == kid {
			return i, true
		}
	}
	return -1, false
}

// For entries in keyring that appear with the same value for their KID field,
// consolidate them into a single entry. If one of the copies has 'Legacy' set, let the consolidated entry have 'Legacy' set.
// If one of the entries does not have `Legacy` set, set the value of `Active`.
func (k *KASConfigDupe) consolidate() {
	seen := make(map[string]int)
	consolidated := make([]CurrentKeyFor, 0, len(k.Keyring)/2) //nolint:mnd // There are at most two of each of the new kind of keys.
	for _, key := range k.Keyring {
		if j, ok := seen[key.KID]; ok {
			if key.Legacy {
				consolidated[j].Legacy = true
			} else {
				consolidated[j].Active = key.Active
			}
		} else {
			seen[key.KID] = len(consolidated)
			consolidated = append(consolidated, key)
		}
	}
	k.Keyring = consolidated
}

// Deprecated
type KeyPairInfo struct {
	// Valid algorithm. May be able to be derived from Private but it is better to just say it.
	Algorithm string `mapstructure:"alg" json:"alg"`
	// Key identifier. Should be short
	KID string `mapstructure:"kid" json:"kid"`
	// Implementation specific locator for private key;
	// for 'standard' crypto service this is the path to a PEM file
	Private string `mapstructure:"private" json:"private"`
	// Optional locator for the corresponding certificate.
	// If not found, only public key (derivable from Private) is available.
	Certificate string `mapstructure:"cert" json:"cert"`
	// Optional enumeration of intended usages of keypair
	Usage string `mapstructure:"usage" json:"usage"`
	// Optional long form description of key pair including purpose and life cycle information
	Purpose string `mapstructure:"purpose" json:"purpose"`
}

// Deprecated
type StandardKeyInfo struct {
	PrivateKeyPath string `mapstructure:"private_key_path" json:"private_key_path"`
	PublicKeyPath  string `mapstructure:"public_key_path" json:"public_key_path"`
}

// Deprecated
type CryptoConfig2024 struct {
	Type     string `mapstructure:"type"`
	Standard `mapstructure:"standard"`
}

type Standard struct {
	Keys []KeyPairInfo `mapstructure:"keys" json:"keys"`
	// Deprecated
	RSAKeys map[string]StandardKeyInfo `mapstructure:"rsa,omitempty" json:"rsa,omitempty"`
	// Deprecated
	ECKeys map[string]StandardKeyInfo `mapstructure:"ec,omitempty" json:"ec,omitempty"`
}

type KASConfigDupe struct {
	// Which keys are currently the default.
	Keyring []CurrentKeyFor `mapstructure:"keyring" json:"keyring"`
	// Deprecated
	ECCertID string `mapstructure:"eccertid" json:"eccertid"`
	// Deprecated
	RSACertID string `mapstructure:"rsacertid" json:"rsacertid"`
}

func (c CryptoConfig2024) MarshalTo(within map[string]any) error {
	var kasCfg KASConfigDupe
	if err := mapstructure.Decode(within, &kasCfg); err != nil {
		return fmt.Errorf("invalid kas cfg [%v] %w", within, err)
	}
	if len(kasCfg.Keyring) > 0 && (kasCfg.ECCertID != "" || kasCfg.RSACertID != "") {
		return fmt.Errorf("invalid kas cfg [%v]", within)
	}
	kasCfg.consolidate()
	for kid, stdKeyInfo := range c.RSAKeys {
		if i, ok := kasCfg.locate(kid); ok {
			kasCfg.Keyring[i].Private = stdKeyInfo.PrivateKeyPath
			kasCfg.Keyring[i].Certificate = stdKeyInfo.PublicKeyPath
			continue
		}
		k := CurrentKeyFor{
			Algorithm:   "rsa:2048",
			KID:         kid,
			Private:     stdKeyInfo.PrivateKeyPath,
			Certificate: stdKeyInfo.PublicKeyPath,
			Active:      kasCfg.RSACertID == "" || kasCfg.RSACertID == kid,
			Legacy:      true,
		}
		kasCfg.Keyring = append(kasCfg.Keyring, k)
	}
	for kid, stdKeyInfo := range c.ECKeys {
		if i, ok := kasCfg.locate(kid); ok {
			kasCfg.Keyring[i].Private = stdKeyInfo.PrivateKeyPath
			kasCfg.Keyring[i].Certificate = stdKeyInfo.PublicKeyPath
			continue
		}
		k := CurrentKeyFor{
			Algorithm:   "ec:secp256r1",
			KID:         kid,
			Private:     stdKeyInfo.PrivateKeyPath,
			Certificate: stdKeyInfo.PublicKeyPath,
			Active:      kasCfg.ECCertID == "" || kasCfg.ECCertID == kid,
			Legacy:      true,
		}
		kasCfg.Keyring = append(kasCfg.Keyring, k)
	}
	for _, k := range c.Keys {
		if i, ok := kasCfg.locate(k.KID); ok {
			kasCfg.Keyring[i].Private = k.Private
			kasCfg.Keyring[i].Certificate = k.Certificate
			continue
		}
		kasCfg.Keyring = append(kasCfg.Keyring, CurrentKeyFor{
			Algorithm:   k.Algorithm,
			KID:         k.KID,
			Private:     k.Private,
			Certificate: k.Certificate,
		})
	}
	kasCfg.ECCertID = ""
	kasCfg.RSACertID = ""
	delete(within, "rsacertid")
	delete(within, "eccertid")
	if err := mapstructure.Decode(kasCfg, &within); err != nil {
		return fmt.Errorf("failed serializing kas cfg [%v] %w", kasCfg, err)
	}
	return nil
}
