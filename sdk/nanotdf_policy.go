package sdk

import (
	"encoding/binary"
	"errors"
	"io"
)

// ============================================================================================================
// Support for nanoTDF policy operations
//
// ============================================================================================================

type policyType uint8

const (
	policyTypeRemotePolicy                           policyType = 0
	policyTypeEmbeddedPolicyPlainText                policyType = 1
	policyTypeEmbeddedPolicyEncrypted                policyType = 2
	policyTypeEmbeddedPolicyEncryptedPolicyKeyAccess policyType = 3
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
	case policyTypeRemotePolicy:
		var rl ResourceLocator
		if err := rl.readResourceLocator(reader); err != nil {
			return errors.Join(ErrNanoTDFHeaderRead, err)
		}
		pb.rp = remotePolicy{url: rl}
	case policyTypeEmbeddedPolicyPlainText:
	case policyTypeEmbeddedPolicyEncrypted:
	case policyTypeEmbeddedPolicyEncryptedPolicyKeyAccess:
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
	case policyTypeRemotePolicy: // remote policy - resource locator
		if err = binary.Write(writer, binary.BigEndian, pb.mode); err != nil {
			return err
		}
		if err = pb.rp.url.writeResourceLocator(writer); err != nil {
			return err
		}
		return nil
	case policyTypeEmbeddedPolicyPlainText:
	case policyTypeEmbeddedPolicyEncrypted:
	case policyTypeEmbeddedPolicyEncryptedPolicyKeyAccess:
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
