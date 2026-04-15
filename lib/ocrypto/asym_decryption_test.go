package ocrypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewPrivateKeyDecryptor(t *testing.T) {
	t.Parallel()

	t.Run("RSA2048", func(t *testing.T) {
		t.Parallel()
		d, err := NewPrivateKeyDecryptor(RSA2048Key)
		require.NoError(t, err)
		require.Equal(t, RSA2048Key, d.KeyType())
	})

	t.Run("RSA4096", func(t *testing.T) {
		t.Parallel()
		d, err := NewPrivateKeyDecryptor(RSA4096Key)
		require.NoError(t, err)
		require.Equal(t, RSA4096Key, d.KeyType())
	})

	t.Run("EC256", func(t *testing.T) {
		t.Parallel()
		d, err := NewPrivateKeyDecryptor(EC256Key)
		require.NoError(t, err)
		require.Equal(t, EC256Key, d.KeyType())
	})

	t.Run("EC384", func(t *testing.T) {
		t.Parallel()
		d, err := NewPrivateKeyDecryptor(EC384Key)
		require.NoError(t, err)
		require.Equal(t, EC384Key, d.KeyType())
	})

	t.Run("EC521", func(t *testing.T) {
		t.Parallel()
		d, err := NewPrivateKeyDecryptor(EC521Key)
		require.NoError(t, err)
		require.Equal(t, EC521Key, d.KeyType())
	})

	t.Run("UnsupportedType", func(t *testing.T) {
		t.Parallel()
		_, err := NewPrivateKeyDecryptor(KeyType("dsa:1024"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported key type")
	})
}

func TestECDecryptorMethods(t *testing.T) {
	t.Parallel()

	modes := []struct {
		mode ECCMode
		kt   KeyType
	}{
		{ECCModeSecp256r1, EC256Key},
		{ECCModeSecp384r1, EC384Key},
		{ECCModeSecp521r1, EC521Key},
	}

	for _, tc := range modes {
		t.Run(string(tc.kt), func(t *testing.T) {
			t.Parallel()

			dec, err := NewECPrivateKey(tc.mode)
			require.NoError(t, err)

			// KeyType
			require.Equal(t, tc.kt, dec.KeyType())

			// PrivateKeyInPemFormat round-trip
			privPEM, err := dec.PrivateKeyInPemFormat()
			require.NoError(t, err)
			require.NotEmpty(t, privPEM)
			dec2, err := FromPrivatePEM(privPEM)
			require.NoError(t, err)
			require.Equal(t, tc.kt, dec2.KeyType())

			// Public — returns an encryptor whose public key round-trips
			enc, err := dec.Public()
			require.NoError(t, err)
			pubPEM, err := enc.PublicKeyInPemFormat()
			require.NoError(t, err)
			require.NotEmpty(t, pubPEM)
			require.Equal(t, tc.kt, enc.KeyType())
		})
	}

	t.Run("NilKeyGuards", func(t *testing.T) {
		t.Parallel()
		nilDec := ECDecryptor{}
		_, err := nilDec.Public()
		require.Error(t, err)
		_, err = nilDec.PrivateKeyInPemFormat()
		require.Error(t, err)
	})
}

func TestRsaKeyPairNewMethods(t *testing.T) {
	t.Parallel()

	sizes := []struct {
		bits int
		kt   KeyType
	}{
		{RSA2048Size, RSA2048Key},
		{RSA4096Size, RSA4096Key},
	}

	for _, tc := range sizes {
		t.Run(string(tc.kt), func(t *testing.T) {
			t.Parallel()
			kp, err := NewRSAKeyPair(tc.bits)
			require.NoError(t, err)
			require.Equal(t, tc.kt, kp.KeyType())

			enc, err := kp.Public()
			require.NoError(t, err)
			require.Equal(t, tc.kt, enc.KeyType())
		})
	}

	t.Run("NilKeyGuard", func(t *testing.T) {
		t.Parallel()
		_, err := RsaKeyPair{}.Public()
		require.Error(t, err)
	})
}

func TestECIESRoundTripAllCurves(t *testing.T) {
	t.Parallel()

	modes := []struct {
		mode ECCMode
		kt   KeyType
	}{
		{ECCModeSecp256r1, EC256Key},
		{ECCModeSecp384r1, EC384Key},
		{ECCModeSecp521r1, EC521Key},
	}

	for _, tc := range modes {
		t.Run(string(tc.kt), func(t *testing.T) {
			t.Parallel()

			dec, err := NewECPrivateKey(tc.mode)
			require.NoError(t, err)

			enc, err := dec.Public()
			require.NoError(t, err)

			plaintext := []byte("hello from " + string(tc.kt))
			ciphertext, err := enc.Encrypt(plaintext)
			require.NoError(t, err)

			ecEnc, ok := enc.(ECEncryptor)
			require.True(t, ok)

			result, err := dec.DecryptWithEphemeralKey(ciphertext, ecEnc.EphemeralKey())
			require.NoError(t, err)
			require.Equal(t, plaintext, result)
		})
	}
}

func TestECEncryptorKeyPemSeparation(t *testing.T) {
	t.Parallel()

	dec, err := NewECPrivateKey(ECCModeSecp256r1)
	require.NoError(t, err)

	enc, err := dec.Public()
	require.NoError(t, err)

	recipientPEM, err := enc.PublicKeyInPemFormat()
	require.NoError(t, err)

	ecEnc, ok := enc.(ECEncryptor)
	require.True(t, ok)

	ephemeralPEM, err := ecEnc.EphemeralPublicKeyInPemFormat()
	require.NoError(t, err)

	require.NotEqual(t, recipientPEM, ephemeralPEM,
		"PublicKeyInPemFormat (recipient) and EphemeralPublicKeyInPemFormat must differ")
}

func TestAsymDecryptionKeyType(t *testing.T) {
	t.Parallel()
	sizes := []struct {
		bits int
		kt   KeyType
	}{
		{RSA2048Size, RSA2048Key},
		{RSA4096Size, RSA4096Key},
	}
	for _, tc := range sizes {
		t.Run(string(tc.kt), func(t *testing.T) {
			t.Parallel()
			kp, err := NewRSAKeyPair(tc.bits)
			require.NoError(t, err)
			privPEM, err := kp.PrivateKeyInPemFormat()
			require.NoError(t, err)
			d, err := FromPrivatePEM(privPEM)
			require.NoError(t, err)
			ad, ok := d.(AsymDecryption)
			require.True(t, ok)
			require.Equal(t, tc.kt, ad.KeyType())
		})
	}
}
