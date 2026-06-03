package ocrypto

// Standard RFC 7468 PEM block type labels. Used by hybrid (X-Wing, P-256+ML-KEM-768,
// P-384+ML-KEM-1024) key serialization; routing happens by the AlgorithmIdentifier
// OID inside the SPKI/PKCS#8 envelope, not by the PEM block type.
const (
	pemBlockPublicKey  = "PUBLIC KEY"
	pemBlockPrivateKey = "PRIVATE KEY"
)
