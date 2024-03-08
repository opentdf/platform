package tdf3

import "crypto/cipher"

type Block struct {
	cipher.Block
	Algorithm  string
	Streamable bool
	IV         []byte
}

func (b Block) Method() EncryptionMethod {
	return EncryptionMethod{
		b.Algorithm,
		b.Streamable,
		b.IV,
	}
}

type Integrity interface {
	Integrity() IntegrityInformation
}

type Access interface {
	Access() []KeyAccess
}
