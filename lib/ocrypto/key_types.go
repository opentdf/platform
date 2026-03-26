package ocrypto

type KeyType string

const (
	RSA2048Key     KeyType = "rsa:2048"
	RSA4096Key     KeyType = "rsa:4096"
	EC256Key       KeyType = "ec:secp256r1"
	EC384Key       KeyType = "ec:secp384r1"
	EC521Key       KeyType = "ec:secp521r1"
	MLKEM768Key    KeyType = "mlkem:768"
	MLKEM1024Key   KeyType = "mlkem:1024"
	HybridXWingKey KeyType = "hpqt:xwing"
)

const (
	RSA2048Size = 2048
	RSA4096Size = 4096
)

const (
	ECCurveP256Size = 256
	ECCurveP384Size = 384
	ECCurveP521Size = 521
)
