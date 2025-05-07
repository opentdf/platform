package sdk

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/opentdf/platform/lib/ocrypto"
)

// ============================================================================================================
// Support for nanoTDF policy operations
//
// ============================================================================================================

type policyType uint8

const (
	NanoTDFPolicyModeRemote                   policyType = 0
	NanoTDFPolicyModePlainText                policyType = 1
	NanoTDFPolicyModeEncrypted                policyType = 2
	NanoTDFPolicyModeEncryptedPolicyKeyAccess policyType = 3
)

type PolicyBody struct {
	mode policyType
	rp   remotePolicy
	ep   embeddedPolicy
}

// getLength - size in bytes of the serialized content of this object
// func (pb *PolicyBody) getLength() uint16 { // nolint:unused future use
//	var result uint16
//
//	result = 1 /* policy mode byte */
//
//	if pb.mode == policyTypeRemotePolicy {
//		result += pb.rp.getLength()
//	} else {
//		// If it's not remote, assume embedded policy
//		result += pb.ep.getLength()
//	}
//
//	return result
// }

// readPolicyBody - helper function to decode input data into a PolicyBody object
func (pb *PolicyBody) readPolicyBody(reader io.Reader) error {
	var mode policyType
	if err := binary.Read(reader, binary.BigEndian, &mode); err != nil {
		return err
	}
	switch mode {
	case NanoTDFPolicyModeRemote:
		var rl ResourceLocator
		if err := rl.readResourceLocator(reader); err != nil {
			return errors.Join(ErrNanoTDFHeaderRead, err)
		}
		pb.rp = remotePolicy{url: rl}
	case NanoTDFPolicyModeEncrypted:
	case NanoTDFPolicyModeEncryptedPolicyKeyAccess:
	case NanoTDFPolicyModePlainText:
		var ep embeddedPolicy
		if err := ep.readEmbeddedPolicy(reader); err != nil {
			return errors.Join(ErrNanoTDFHeaderRead, err)
		}
		pb.ep = ep
	default:
		return errors.New("unknown policy type")
	}
	return nil
}

// writePolicyBody - helper function to encode and write a PolicyBody object
func (pb *PolicyBody) writePolicyBody(writer io.Writer) error {
	var err error

	switch pb.mode {
	case NanoTDFPolicyModeRemote: // remote policy - resource locator
		if err = binary.Write(writer, binary.BigEndian, pb.mode); err != nil {
			return err
		}
		if err = pb.rp.url.writeResourceLocator(writer); err != nil {
			return err
		}
		return nil
	case NanoTDFPolicyModeEncrypted:
	case NanoTDFPolicyModeEncryptedPolicyKeyAccess:
	case NanoTDFPolicyModePlainText:
		// embedded policy - inline
		if err = binary.Write(writer, binary.BigEndian, pb.mode); err != nil {
			return err
		}
		if err = pb.ep.writeEmbeddedPolicy(writer); err != nil {
			return err
		}
	default:
		return errors.New("unsupported policy mode")
	}
	return nil
}

func validNanoTDFPolicyMode(mode policyType) bool {
	switch mode {
	case NanoTDFPolicyModeRemote, NanoTDFPolicyModePlainText, NanoTDFPolicyModeEncrypted, NanoTDFPolicyModeEncryptedPolicyKeyAccess:
		return true
	default:
		return false
	}
}

// createEmbeddedPolicy creates an embedded policy object, encrypting it if required by the policy mode
func createNanoTDFEmbeddedPolicy(policyObjectAsStr []byte, config NanoTDFConfig) (embeddedPolicy, error) {
	if config.policyMode == NanoTDFPolicyModeEncrypted { //nolint:nestif // TODO: refactor
		if config.kasPublicKey == nil {
			return embeddedPolicy{}, fmt.Errorf("KAS public key is required for encrypted policy mode")
		}

		ecdhKey, err := ocrypto.ConvertToECDHPrivateKey(config.keyPair.PrivateKey)
		if err != nil {
			return embeddedPolicy{}, fmt.Errorf("ocrypto.ConvertToECDHPrivateKey failed:%w", err)
		}

		symKey, err := ocrypto.ComputeECDHKeyFromECDHKeys(config.kasPublicKey, ecdhKey)
		if err != nil {
			return embeddedPolicy{}, fmt.Errorf("ocrypto.ComputeECDHKeyFromEC failed:%w", err)
		}

		salt := versionSalt()
		symmetricKey, err := ocrypto.CalculateHKDF(salt, symKey)
		if err != nil {
			return embeddedPolicy{}, fmt.Errorf("ocrypto.CalculateHKDF failed:%w", err)
		}

		aesGcm, err := ocrypto.NewAESGcm(symmetricKey)
		if err != nil {
			return embeddedPolicy{}, fmt.Errorf("ocrypto.NewAESGcm failed:%w", err)
		}

		tagSize, err := SizeOfAuthTagForCipher(config.sigCfg.cipher)
		if err != nil {
			return embeddedPolicy{}, fmt.Errorf("SizeOfAuthTagForCipher failed:%w", err)
		}

		const kIvLength = 12
		iv := make([]byte, kIvLength)
		cipherText, err := aesGcm.EncryptWithIVAndTagSize(iv, policyObjectAsStr, tagSize)
		if err != nil {
			return embeddedPolicy{}, fmt.Errorf("AesGcm.EncryptWithIVAndTagSize failed:%w", err)
		}

		return embeddedPolicy{
			lengthBody: uint16(len(cipherText) - len(iv)),
			body:       cipherText[len(iv):],
		}, nil
	}

	return embeddedPolicy{
		lengthBody: uint16(len(policyObjectAsStr)),
		body:       policyObjectAsStr,
	}, nil
}
