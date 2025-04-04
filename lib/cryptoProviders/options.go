package cryptoProviders

type Options struct {
	kek []byte
}

func WithKeyEncryptionKey(kek []byte) Options {
	return Options{kek: kek}
}
