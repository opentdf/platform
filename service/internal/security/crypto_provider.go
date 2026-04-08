package security

const (
	// Key agreement along P-256
	AlgorithmECP256R1 = "ec:secp256r1"
	// Key agreement along P-384
	AlgorithmECP384R1 = "ec:secp384r1"
	// Key agreement along P-521
	AlgorithmECP521R1 = "ec:secp521r1"

	// Used for encryption with RSA of the KAO
	AlgorithmRSA2048 = "rsa:2048"
	AlgorithmRSA4096 = "rsa:4096"

	// Used for hybrid X-Wing wrapping of the KAO
	AlgorithmHPQTXWing = "hpqt:xwing"

	// Used for hybrid NIST EC + ML-KEM wrapping of the KAO
	AlgorithmHPQTSecp256r1MLKEM768  = "hpqt:secp256r1-mlkem768"
	AlgorithmHPQTSecp384r1MLKEM1024 = "hpqt:secp384r1-mlkem1024"
)
