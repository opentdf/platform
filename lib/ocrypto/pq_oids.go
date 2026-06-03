package ocrypto

import "encoding/asn1"

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

// ASCII Labels mixed into the composite-KEM combiner per draft-14 §4.3 to
// domain-separate ciphertexts produced under different curve/ML-KEM pairings.
const (
	labelMLKEM768P256  = "MLKEM768-P256"
	labelMLKEM1024P384 = "MLKEM1024-P384"
)
