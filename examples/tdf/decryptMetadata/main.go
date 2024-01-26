package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/opentdf/opentdf-v2-poc/internal/crypto"
)

func main() {
	key, err := hex.DecodeString("2cb259898716c7ad79a5e1fed5bcc329b4a4f6dd0b1494feff6328a0d3e06d79")
	if err != nil {
		panic(err)
	}

	gcm, err := crypto.NewAESGcm(key)
	if err != nil {
		panic(err)
	}

	data, err := base64.StdEncoding.DecodeString("Q4w78AYb0seOqtJILwigb6tBIvkt2YIo+/nqkBtNBmJNEWtYdY1WdCjlXIzfpCqxUO2rPNY9Bt7B54HAgRNcWI/u3+zfnk0oIFCxJ94qVreQKP39bfhJFVHET/sRwFf1XRnvWFm3Z5Y5Hly9fwQXJNbm+9qdrUzn28yzdqSR8U28Gmo8M5Q/yP2YCovq/IuXHKTqtvysBk8nK2PKNCpAeNg09GFKDZ93o5qP3I8c1Gd6fer1fJ/wJwec8tc/e3owigj+kgo+SVKY0sHhBUi0d7PUQvKdALaSaY4ziGLeiv8l18PndKFAgIYlAEgp6O09LrqXhAPcr3+8Enobeg1Ws/tTqeUV8P/7lI2KMChIUb1EanUuU50iLpGXepXkq9sVkM+nwDwMD8sc5CDgokUPMFsrLbzmiNYMce4M7FSc/TxC5IaGm3IqIEXalHRVMQ0rrpE+LPYOvlzJB3ur6CCflIjCI+hLoDcHlRvvIpFpMsDcpDSym+7VdzGXJMiv6xt4/c+tvwaZLPzAiPpsHgsISc6xETypmBWOj8sIyaEKNU2PlJzN2VxJGZr58i3stwo=")
	if err != nil {
		panic(err)
	}

	metadata, err := gcm.Decrypt(data)
	if err != nil {
		panic(err)
	}

	fmt.Println("metadata", string(metadata))
}
