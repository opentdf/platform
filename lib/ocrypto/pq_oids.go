package ocrypto

import (
	"bytes"
	"encoding/asn1"
)

// OIDs assigned to the hybrid post-quantum/traditional KEMs we support.
//
// The composite-KEM OIDs come from `draft-ietf-lamps-pq-composite-kem-14`
// (IANA SMI Security for PKIX Algorithms arc 1.3.6.1.5.5.7.6). The X-Wing OID
// is the one registered by `draft-connolly-cfrg-xwing-kem-10` under the
// Connolly private enterprise arc 1.3.6.1.4.1.62253.
var (
	oidCompositeMLKEM768P256  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 59}
	oidCompositeMLKEM1024P384 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 6, 63}
	oidXWing                  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 62253, 25722}
)

// hybridOIDDERs holds the DER (tag+length+content) byte forms of the hybrid
// OIDs, used by containsHybridOID for cheap detection inside a larger DER
// blob (e.g. a certificate's TBSCertificate).
var hybridOIDDERs = func() [][]byte {
	oids := []asn1.ObjectIdentifier{oidXWing, oidCompositeMLKEM768P256, oidCompositeMLKEM1024P384}
	out := make([][]byte, 0, len(oids))
	for _, oid := range oids {
		der, err := asn1.Marshal(oid)
		if err != nil {
			panic("asn1.Marshal of hybrid OID failed: " + err.Error())
		}
		out = append(out, der)
	}
	return out
}()

// containsHybridOID reports whether der contains the DER encoding of any of
// our hybrid algorithm OIDs as a substring. Intended for the CERTIFICATE
// rejection path — false positives would require an unrelated OID to share
// the exact byte sequence, which is implausible given the specificity of the
// OIDs registered for these schemes.
func containsHybridOID(der []byte) bool {
	for _, oidDER := range hybridOIDDERs {
		if bytes.Contains(der, oidDER) {
			return true
		}
	}
	return false
}

// ASCII Labels mixed into the composite-KEM combiner (draft-14 §3.4) to
// domain-separate ciphertexts produced under different curve/ML-KEM pairings.
// The label values themselves are registered in draft-14 §6 alongside the OIDs.
const (
	labelMLKEM768P256  = "MLKEM768-P256"
	labelMLKEM1024P384 = "MLKEM1024-P384"
)
