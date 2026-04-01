package ocrypto

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	kasRSA2048PrivateKey = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDGKCUv1RhyH79N
zHw+5TZHW3pVxzBnybbjrQqr6nckzJ1Xld5cm+OV6ELE+4MMTGhO2ePh8ZHA2OyO
Plxslur3b1VEHYGkUucbJfWJQYbNpyRdy++8XDPQOiAfUg6HSzOAMY+WzoGiSgxF
1sL1urkSsPVO+DWV1nyopf70dhpkmbr0qQGNJlvpbMlIaTeUhROClrd1SQIxyl4k
xHQ5ikNboI9iuBtsZ8A0BFl6PlSC5E2wAMv0+I8o52UTN1lWFuVgWAYoQDftde4I
R+rWbIdeaVGY4eow0YHOIYG7UJ5Ev7h9t/43KQYBZDbXpK1twKUVccLobX+wW46E
UTXZ36/NAgMBAAECggEALOpWm4P62Yt2qmTKWNtNtVj33s+amjvvt6W2gIdR4EZ8
96hh0a4IJSeTUuELsFL1ZcIf1EwUVJkW7ZsXCgofUlyrABiMFToxZkbxY941dxIG
vTgHrDNeDznNpCvOXT5fexRAztcaLTYJmB747AgaATGZOQAr7T3D3dpacwD+NIT5
1mrXJ42F35Ep29poMvgg5BRdVptjqTu7jzcORgFQmyWolZLdJK5yk6PQTpohZgLV
bSTkadlHQdSYWsn/Zc8MoFvN5URx/3jqH5OdZ0cx/1h0nNR1Xi2ejUFFtmYgro1D
o2UYCVPzAzDqiNlANJnBrOuUXn06rbD7In+vOtSbIQKBgQDrWbHTfL1g5xAnX6Vz
RFKEIt0fdHp1mYu27ou4cXjN6OOklGc7J+X/ve0m3/JX5gTOelxkKRVLGDs07VGw
+LbiBBm/QvFxCPWKHA261EVqdYD77v7WhPgGor8jrC/2RBC/9Vz+80X4PhlWD9HO
s7bX6ZQ6BAHALssFbArDJYWV1QKBgQDXiwfEBWdRmtLlnk/+MXtxIEAgZ6RxmMFE
gCiuUkBkQjjG+VbycHVs8oreQYm7x2IrTRvA3MOxVt2/ay+aM8z9HWdFPXeZEh6U
0oCnl4DKP/HmWV89MUUFc4aTNk0vg2YNvERCUACNHTvsn7VZOSbECxVUvkX8s+im
86ha2ETWGQKBgQDWxCIXaSR0Mkc2dvzHZBicxifdFXDOshCiHatY5Aumc5iQznAp
tm4XY5zvNbuz5I6MUXLQYAEzZuhYkxxSD5TsSWupcpBbYx6WKqWI0T6LOLE8tcrN
vceMXqVoCzA1XcWfNmvnp944+4opVARUyQDYpSmDi7aBRvIzf3WOwUXXBQKBgEdX
oU5ka3o7QKr354o/XphnEFKpe2iOIwpFUTHBz8ZflONnDDxatMNG1GgUUT5yFDA4
6YLAj5VXJzaAh9UGaEcvQEtOuRNVSAICWssd/mbzG2IfGsLqV+oh/t0jEBE18MWD
FyTLziLnFjqP8jqCDC6/bGQMRqYJ9musIoFPLBmhAoGBAItIHiH3e+0aREPFN4QC
pBOmDNaSdVjh1kh5L0/Bx346fTivkzmY05kCb+c+lxI4bfpeERoWrU19OHOKMLVT
pREiRl7wx0sg0UlJmqprZK6LKuVCiy8r6qX6wGsYNbkLNiB8t0ro/f2/+FsPprUt
2qCgxkX89uyYl/aupOnlBJMk
-----END PRIVATE KEY-----`

	kasRSA3072PrivateKey = `-----BEGIN PRIVATE KEY-----
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
Wnzkl5DShi5QHFAHEwaWZizh
-----END PRIVATE KEY-----`

	kasRSA4096PrivateKey = `-----BEGIN PRIVATE KEY-----
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
T1IXp5vmOmypUj5J0znUZnrXU+CpBA==
-----END PRIVATE KEY-----`

	clientRSA2048PublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA06c5MJO+WuhaU40o5ueP
PFiIZZaDfr0ERWpEZ0h3EeUMvD0sqrWvmay61rLkUEaHwwYZwxQp3eJ27YSGJ0Ki
fPexijdAOQuGd51inwFSJe8AwdqNSH1NzEFsZNYSAFTU4//Qq5U+Ynwq/wUxq8p8
zJ133pTyNLiAJ7tG6J2tij87e0yr0ZDDPuKlpwdHukEnKLTZUd49Y+9Fg+HiaNh1
uUzQFOoElb4wKB58E5w5fu9X8j545OAZx4x3li0Dddn/WiF3vK4xx5LYcPNsVOcQ
lebrUSiq40m+Mh1GYycp92KrGGG0tw9lEza5F/ArQVsl6RAQ3kJ0Z9P8Qn5OgFN/
VwIDAQAB
-----END PUBLIC KEY-----`

	clientRSA3072PublicKey = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAxBu04Tq3Xp4IJ/2h1hWT
VvumUMKNXJ9jpm3NUinjx6QyQazUAgMF4eNs8m8beIAMpCpYG9sS8Sc5xil3UmUn
DwhgMalDU/MxDPiTWMe6TP+DRYB6uCgvJUBz2dkaLHyQrEsOdi9auQ0p3NZzjUid
yDNQBdd2EyJYslVKuZuWiPEHsfihaJcf48mUQ+XAbu1ludClN2xGyb9bvcE8p5Ev
2lAh24U7Vln+/PEwn9nsqZ9915JZBQNsswlFl1bvFhZ80Ab0AEWGEVD9HGS32t9c
x+wVl2DXBYBnCz6Rqr2oAMPGsuBMnHxF2qBL+bmM33t52Tc/l9Etnc53l56UWvZG
t9u5kh67mNoH2Si+T7j3Saor6iAGZ7FDVrBZ7Dm/vGtYIcph3winv/hLntsPMeM3
z5+8Bqmuvt/KsKVy7L89bKGxfoY7NwwjIMfoQCJAKb72GiLJJQYVDfuhjKBCsoXR
kVskEtG/mHUmiMlRrY5fqVLBku+KgrfjyS5iBedVmpPbAgMBAAE=
-----END PUBLIC KEY-----`

	clientRSA4096PublicKey = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtK01xut0kOEcloZBn2Aq
4mcVfqbidyy3B4vmuybaIyZz+UYiYIKXbm4j6PN5U32tYT2WjMUj2ReSVcEZirX0
RA0n5nnif2rAyshF3PD6HOkV43XTYAano0RZf8oxow78hQBQFdGEl+yPLwclBUal
vRWjY1O5ueuehoYM99eIR0Ua+AYYlCNELsTyowuTwGBpsssQYtSiIMgtZEfrZfnA
Hv+mIjo4mwN8VKFcqEcSD8/BsBY31Jg5qcRfF2sQ3nmU4rICPc/J4o1wHDbEGQNx
NvJ41ntLLvnRtJFL9E5fD5MVB7wCOD6bdYlqectMegoFM6XPBh4KuvJ7N/mnRz4j
JOl2cwCVHdzxe12/Eoym2j2aPoDY+J1H+dCBLMfKqbDEM7Q7ORG2jZH6m2SVn6ZE
NoCpEll+lRA6p0N3dvRiCyI+HnLRjqGBaJox62+D/vYkXubaE8fyd7R1kTMkHuI1
EYHwqOnKfzb4NSCmALlwGetnzegurRec2e7jESV/5ecEbSGsq5+n5jWuJvfaBNhQ
RG1TziH0dC5JCzlJ5jfOSAMbjg18svfWyodAuPxf9QHZga0/t8JsW5QThnyJoZrq
Na1ka2d9Dn3UUkRCFfJjltIZfhaoFj98AUhWXmCwQ0atTh2AP5DI7xXhywKqqyL+
AUWCoPbjycIQvYTZzNYT4d8CAwEAAQ==
-----END PUBLIC KEY-----`

	kasEC256PrivateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpe8aN73TmHsOQGXO
GVGzimdlJgxs5DTqptIrvJwh626hRANCAATV5IRj+4uCWIqSrSSU2nOeVf0s4haw
WH4Q2O7mgD+9ldjhKLSw2X+32hrH4g6ObklllKQINih56VqNTGlAhmBG
-----END PRIVATE KEY-----`

	kasEC384PrivateKey = `-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDALXfz/NrisKyuyvwX7
3WLUwryz4mytjHahcDn8pxVGQDUiP0zX6B+PcCCge47+Y0WhZANiAARa3f5RH5Gn
GBvmIWi6Qdt/2SKJNuJTaL2MspouEGpJnOgzV59C+lZpxtv36vkP0y//Luz5OFb/
b54Aqhp4NIweGg7WBLHRhcd6P38Kp9Ol0NubgcmL9pQnaAvCNKtKeyM=
-----END PRIVATE KEY-----`

	kasEC521PrivateKey = `-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIArPqCq8Pxh2XS0Faz
OxZ3Mznwm8rHrQU0mnrn3xlrVVQefkCEeRDmsD8wAXBdd72t3HU7HvMCqWHUhLfg
ByDKS6GhgYkDgYYABACS64DocOOJZReBxrFPXoYetkglB2zMq8km8dgep0fJxcAT
MwHCtmXCbJMMyzTMLXMqenQomDag38kQxyQv/sGPewDJsTXDJJX3Mc/bhvMM2lBO
ud3VcmnvhY0KUj6b8KMYI8xk68E83JZ/zKxNDSMUOz3wAQEDt0G8VkvY72UuGtQS
3g==
-----END PRIVATE KEY-----`

	nanotdfEC256PublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEM1fJlnzL3bMYoh6yU9aOmbwaWHWq
7CATl+sjaEefNduwTwZZRquNkI5gZzeUuodvGAolQIGhLUdWq9nnS/qx8g==
-----END PUBLIC KEY-----`

	nanotdfEC384PublicKey = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEDIVAsQDhX/eyPwouPbsxReSWrs0vlgdD
s3kp0xhuYNIsEn6geCTHzun15DrmW93/vMdUGwdhuZHDEgNCMM5K3Tkp12husDyc
9wSoe9aBJItnbFPYXV83qu4AndpZh09l
-----END PUBLIC KEY-----`

	nanotdfEC521publicKey = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBKSdtLB/5LTSsQLqEB2ytZ/lIj0vS
IS2IIgjRvGPUr5F6ZoZ4v78oAMT+rg8INZfC0Mxw429k2AuNXI56WD/jIxABLiB0
Oq7JS/8bGTEEMLptt5CwLzbp7oGXN08SMNMKGuP5fnsD8t89zx7u4AGbF3Btb5iT
O9LiKgComz+oA+dOoU8=
-----END PUBLIC KEY-----`

	clientEC256PublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPebiI6IF413z3FwiPRpytpTqgDfF
RPqR3T4Y9UHNmiK++aTHtVVIqm/QShe/RX/i9tTp/ugDiMKVhlsnWvp7iQ==
-----END PUBLIC KEY-----`

	clientEC384PublicKey = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEN7TqOJkT4HVkEfdXboquj5Setj/NRZ+m
syXDsW03OracrQgC7YcCZGaYOdw7CKyB2mQhUxnUjt24uwzKxrwqdwdVbdCgRZ+q
Qvvv1gTSFPaaynTKcmRKeJrB8E+x402h
-----END PUBLIC KEY-----`

	clientEC521PublicKey = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBbCtibYZHdlg4ZRa2RAIdNrEQe1K+
/g6s6mwAduMulwDRjh2HyXmqMITIi8pLdBuxqemyIp3iA0bBQO9+q8vuv7sAj7L4
E9taFLDINdJN9QbNXkfiIqPEgbrFmZSg6jjU5h7qkMd63kt4he2LuBheduWx1Pcy
3bZlcIP9SNOY614VF7A=
-----END PUBLIC KEY-----`
)

const (
	// this wrapped key is generated by encrypting 32 byte symmetric key with  kasRSA2048PublicKey
	rsa2048WrappedKey   = `rKNvfoTo8vl+cfFuaWFxu+7btyj0DrMR59iIpgugyKjnb0V+dlaVFIw03UbWThEZA/1xGYYTK4CsX3J5h4FV0kAAdMXkRjaW7fygigHPixailHjDRuA34CpL6ndq+mIa6fWZ1hRbpXu3fOOfnBT+33wGhNH7sowNtNKJvNLzlta1ZObPZCPfdNuJ0wZz4eAkKijN7Lvtqt4Ts6Jtb9DOZ0GTBZBHx8j9JH3avE3Tkj0KSUydpSQRgojCkgdWDVOK6L3YcETTObMKUKPwzljBZAEUCnxi1nNGGmpytF1WfIyrUTQPJ1fPKlkCWZV7NnJ+Mk0U760hQBHg669vhw1+Cg==`
	rsa2048ActualSymKey = `ac0be299f7e067d63c524f1a56e38c6a9657f3e20983b42e3f6116a3a08fe7cc`

	// this wrapped key is generated by encrypting 32 byte symmetric key with  kasRSA3072PublicKey
	rsa3072WrappedKey   = `vk6h3gomD6P9aOA0sJ4Hiq3qSARbfKeZhIumVA9QTA1dYdUyMWm41GpCbU6goOiJOQ181zdgQah27BzztMrxDn68SkCJ1PggMWcALdqEEtDtlgWGmSPdYCMgsdXOfGfp63nSHT+Sk/AKi3pNlwpcJdCILRlKd2sD5WrhvFGvz2OJFKb50aYMmwG8+ZSPdwjHGm1/+mPG41UfEgLEWfdYvK7annnTlgR5fM/ke71OsAj9Su3g9XiAltQ7qXHJXeAMLiw9xjgcRRb+5WzX3waJhFsNF4kBFkEoOkAUoFKFhj0N9FJFAs77fPzYmUyVNKEyAQJOuLVkTMemK1IPAzHNbuWdRS6iEh6qvGTjSa3eHJNvHcdW8FMEX/T1M6eVG/kZjWXknFeuLZ37uEWB6jy5IAUNHiwoPv+6USDt43ALT9wyEhAGORN3Va4WBRzyDaXButB9mzprJ6Iy1RKOUWTtpCYhb1HIjGBdVJhNu21IXLMDVce5/FdRmL46sRY1p3d/`
	rsa3072ActualSymKey = `9220975a6eb4a6014b01d904a483a08dfcbd0ed87d6c2d827522b7f4728ee0ef`

	// this wrapped key is generated by encrypting 32 byte symmetric key with  kasRSA4096PublicKey
	rsa4096WrappedKey   = `j+myfvdo5zIv0qYOdn4ZCrGrWq/EHnFua2ifklGkhPd6mGh0TkFD3lcTB6ZnDq+a9Rcq1ugt6KBK8wImgTowZNyM+8V3W7DsGclxgEQZUAh96jZWSiY130L6e2ey1y5SdgvVbUknKkO4Fs7ZySe7ks99F4RFlMXxE1oKG8bvw57ohDF0L1KmSqA0JeMojElyPuqzCkMog1cqCU0RSsUJz6FPfyhgCZsRxZjmOA87mfTNcfIXhk7phAtQaH0aFvhdeS86sORcr19f16Sz9MRMY3ARLnNwENTYYsSqG2JWzoXhtJ7QPBu5adObkQZIg74myAMHOYIQu2KcGGAylivBxo/hRF2+DAFI7bJUN/UezDVspILF5GupUSHa7CCUZPc43AfSO9B+Jw5DlGapnqfE1BtgZrEMxn1p0lpTrRfuaZXWX2sKpO3caHhLBpt83ZdGcz/m01S1bLqMbb1y7cw+6PdZus4ag2jBq1KD2jiyhqhjSrz7mDRTuXh0WDzG1g1a9+vgdJ5u/wt8tGhkugxy+ElCdoHzgbBlf5AUkJ1Yy8coZlp/UvpGaKh+dvhu1MnSxlySp55xG8S/gB/bxU/vnYsacK8HLQAkz1P7Q/mFocPXVNCgSwmXRAaJGQZJehvlyR9ULnIKFpARIidwrFlbzY2qYW/JPCyAtLvbupR2xio=`
	rsa4096ActualSymKey = `413e390d063a87e54c713f03a843c1c190681c86de6e00f0d6ea53f7f9c4a783`
)

func BenchmarkRCAKasRewrap(b *testing.B) {
	benchmarks := []struct {
		name         string
		privateKey   string
		wrappedKey   string
		actualSymKey string
		publicKey    string
	}{
		{
			name:         "RCA2024",
			privateKey:   kasRSA2048PrivateKey,
			wrappedKey:   rsa2048WrappedKey,
			actualSymKey: rsa2048ActualSymKey,
			publicKey:    clientRSA2048PublicKey,
		},
		{
			name:         "RCA3072",
			privateKey:   kasRSA3072PrivateKey,
			wrappedKey:   rsa3072WrappedKey,
			actualSymKey: rsa3072ActualSymKey,
			publicKey:    clientRSA3072PublicKey,
		},
		{
			name:         "RCA4096",
			privateKey:   kasRSA4096PrivateKey,
			wrappedKey:   rsa4096WrappedKey,
			actualSymKey: rsa4096ActualSymKey,
			publicKey:    clientRSA4096PublicKey,
		},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			var symkey []byte
			asymDecryptor, err := NewAsymDecryption(bm.privateKey)
			if err != nil {
				b.Fatalf("NewAsymDecryption failed: %v", err)
			}

			decode, err := Base64Decode([]byte(bm.wrappedKey))
			if err != nil {
				b.Fatalf("Base64Decode failed: %v", err)
			}

			symkey, err = asymDecryptor.Decrypt(decode)
			if err != nil {
				b.Fatalf("Decrypt failed: %v", err)
			}

			asymEncryptor, err := NewAsymEncryption(bm.publicKey)
			if err != nil {
				b.Fatalf("NewAsymEncryption failed: %v", err)
			}

			wrappedKey, err := asymEncryptor.Encrypt(symkey)
			if err != nil {
				b.Fatalf("Encrypt failed: %v", err)
			}

			_ = Base64Encode(wrappedKey)

			if bm.actualSymKey != hex.EncodeToString(symkey) {
				b.Errorf("Symmetric key mismatch: expected %s, got %s", bm.actualSymKey, hex.EncodeToString(symkey))
			}
		})
	}
}

func BenchmarkEC256KasRewrap(b *testing.B) {
	benchmarks := []struct {
		name             string
		kasPrivateKey    string
		nanotdfPublicKey string
		clientPublicKey  string
		eccMode          ECCMode
	}{
		{"EC256", kasEC256PrivateKey, nanotdfEC256PublicKey, clientEC256PublicKey, ECCModeSecp256r1},
		{"EC384", kasEC384PrivateKey, nanotdfEC384PublicKey, clientEC384PublicKey, ECCModeSecp384r1},
		{"EC521", kasEC521PrivateKey, nanotdfEC521publicKey, clientEC521PublicKey, ECCModeSecp521r1},
	}

	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			// generate symmetric key from Kas private key and ephemeral public key from nano header
			kasECDHKey, err := ComputeECDHKey([]byte(bm.kasPrivateKey), []byte(bm.nanotdfPublicKey))
			require.NoError(b, err, "fail to calculate ecdh key")

			// slat
			digest := sha256.New()
			digest.Write([]byte("L1L"))

			symmetricKey, err := CalculateHKDFWithSize(digest.Sum(nil), kasECDHKey, 32)
			require.NoError(b, err, "fail to calculate HKDF key")

			kasEphemeralECKeyPair, err := NewECKeyPair(bm.eccMode)
			require.NoError(b, err, "fail on NewECKeyPair")

			kasEphemeralPrivateKey, err := kasEphemeralECKeyPair.PrivateKeyInPemFormat()
			require.NoError(b, err, "fail to generate ec private key in pem format")

			// generate session key from sdk public and kas ephemeral private key
			sessionECDHKey, err := ComputeECDHKey([]byte(kasEphemeralPrivateKey), []byte(bm.clientPublicKey))
			require.NoError(b, err, "fail to calculate ecdh key")

			sessionKey, err := CalculateHKDFWithSize(digest.Sum(nil), sessionECDHKey, 32)
			require.NoError(b, err, "fail to calculate HKDF key")

			gcm, err := NewAESGcm(sessionKey)
			require.NoError(b, err, "fail to create aes gcm")

			_, err = gcm.Encrypt(symmetricKey)
			require.NoError(b, err, "fail to encrypt symmetric key")
		})
	}
}
