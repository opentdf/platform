package ocrypto

import (
	"crypto/fips140"
	"crypto/mlkem"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func pkcs8PEM(t *testing.T, oid asn1.ObjectIdentifier, inner []byte, version int) string {
	t.Helper()
	der, err := asn1.Marshal(kemPKCS8{Version: version, Algorithm: kemAlgorithmIdentifier{Algorithm: oid}, PrivateKey: inner})
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: pemBlockPrivateKey, Bytes: der}))
}

func skipCIRCLWhenFIPS(t *testing.T) {
	t.Helper()
	if fips140.Enabled() {
		t.Skip("CIRCL operations are unavailable in FIPS mode")
	}
}

func TestMLKEMPrivateKeyForms(t *testing.T) {
	skipCIRCLWhenFIPS(t)
	for _, tc := range []struct {
		name string
		oid  asn1.ObjectIdentifier
		key  mlkemKEM
	}{
		{"768", OIDMLKEM768, mlkemKEM{variant: mlkem768}},
		{"1024", OIDMLKEM1024, mlkemKEM{variant: mlkem1024}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seed := make([]byte, tc.key.privSize())
			for i := range seed {
				seed[i] = byte(i + 1)
			}
			expanded, err := tc.key.expandSeed(seed)
			require.NoError(t, err)
			require.Len(t, expanded, tc.key.expandedSize())
			var public []byte
			if tc.key.variant == mlkem1024 {
				dk, err := mlkem.NewDecapsulationKey1024(seed)
				require.NoError(t, err)
				public = dk.EncapsulationKey().Bytes()
			} else {
				dk, err := mlkem.NewDecapsulationKey768(seed)
				require.NoError(t, err)
				public = dk.EncapsulationKey().Bytes()
			}
			pubPEM, err := tc.key.publicKeyPEM(public)
			require.NoError(t, err)
			enc, err := FromPublicPEM(pubPEM)
			require.NoError(t, err)
			for _, form := range []struct {
				name  string
				inner []byte
			}{
				{"seed", mustASN1(t, seed, "tag:0,implicit")},
				{"expandedKey", mustASN1(t, expanded, "")},
				{"both", mustASN1(t, struct{ Seed, ExpandedKey []byte }{seed, expanded}, "")},
			} {
				t.Run(form.name, func(t *testing.T) {
					dec, err := FromPrivatePEM(pkcs8PEM(t, tc.oid, form.inner, 0))
					require.NoError(t, err)
					dek := []byte("0123456789abcdef0123456789abcdef")
					wrapped, err := enc.Encrypt(dek)
					require.NoError(t, err)
					got, err := dec.Decrypt(wrapped)
					require.NoError(t, err)
					require.Equal(t, dek, got)
				})
			}
			der, err := marshalKEMPrivatePKCS8(tc.oid, seed)
			require.NoError(t, err)
			var p kemPKCS8
			_, err = asn1.Unmarshal(der, &p)
			require.NoError(t, err)
			var inner asn1.RawValue
			_, err = asn1.Unmarshal(p.PrivateKey, &inner)
			require.NoError(t, err)
			require.Equal(t, asn1.ClassContextSpecific, inner.Class)
			require.Equal(t, 0, inner.Tag)
		})
	}
}

func mustASN1(t *testing.T, v any, params string) []byte {
	t.Helper()
	var b []byte
	var err error
	if params == "" {
		b, err = asn1.Marshal(v)
	} else {
		b, err = asn1.MarshalWithParams(v, params)
	}
	require.NoError(t, err)
	return b
}

func TestMLKEMPrivateKeyMalformed(t *testing.T) {
	skipCIRCLWhenFIPS(t)
	seed := make([]byte, 64)
	expanded, err := (mlkemKEM{variant: mlkem768}).expandSeed(seed)
	require.NoError(t, err)
	expanded1024, err := (mlkemKEM{variant: mlkem1024}).expandSeed(seed)
	require.NoError(t, err)
	broken := append([]byte(nil), expanded...)
	broken[len(broken)-33] ^= 1 // CIRCL checks the embedded public-key hash.
	other := append([]byte(nil), expanded...)
	other[0] ^= 1
	both := func(s, e []byte) []byte {
		return mustASN1(t, struct{ Seed, ExpandedKey []byte }{s, e}, "")
	}
	for _, tc := range []struct {
		name    string
		oid     asn1.ObjectIdentifier
		inner   []byte
		version int
		want    string
	}{
		{"bad tag", OIDMLKEM768, mustASN1(t, seed, "tag:1,implicit"), 0, "invalid tag"},
		{"short seed", OIDMLKEM768, mustASN1(t, seed[:63], "tag:0,implicit"), 0, "seed length"},
		{"short expanded", OIDMLKEM768, mustASN1(t, expanded[:2399], ""), 0, "expandedKey length"},
		{"wrong OID size", OIDMLKEM1024, mustASN1(t, expanded, ""), 0, "expandedKey length"},
		{"wrong OID size reverse", OIDMLKEM768, mustASN1(t, expanded1024, ""), 0, "expandedKey length"},
		{"invalid expanded", OIDMLKEM768, mustASN1(t, broken, ""), 0, "expandedKey invalid"},
		{"short both seed", OIDMLKEM768, both(seed[:63], expanded), 0, "both seed length"},
		{"short both expanded", OIDMLKEM768, both(seed, expanded[:2399]), 0, "both expandedKey length"},
		{"inconsistent both", OIDMLKEM768, both(seed, other), 0, "disagree"},
		{"extra both field", OIDMLKEM768, mustASN1(t, struct{ A, B, C []byte }{seed, expanded, nil}, ""), 0, "both parse failed"},
		{"trailing inner", OIDMLKEM768, append(mustASN1(t, seed, "tag:0,implicit"), 0x05, 0x00), 0, "CHOICE parse failed"},
		{"truncated inner", OIDMLKEM768, mustASN1(t, seed, "tag:0,implicit")[:3], 0, "CHOICE parse failed"},
		{"version", OIDMLKEM768, mustASN1(t, seed, "tag:0,implicit"), 1, "version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := FromPrivatePEM(pkcs8PEM(t, tc.oid, tc.inner, tc.version))
			require.ErrorContains(t, err, tc.want)
		})
	}
	t.Run("outer trailing", func(t *testing.T) {
		block, _ := pem.Decode([]byte(pkcs8PEM(t, OIDMLKEM768, mustASN1(t, seed, "tag:0,implicit"), 0)))
		block.Bytes = append(block.Bytes, 0x05, 0x00)
		_, err := FromPrivatePEM(string(pem.EncodeToMemory(block)))
		require.ErrorContains(t, err, "trailing bytes")
	})
	t.Run("outer extra field", func(t *testing.T) {
		der := mustASN1(t, struct {
			Version    int
			Algorithm  kemAlgorithmIdentifier
			PrivateKey []byte
			Extra      []byte
		}{0, kemAlgorithmIdentifier{OIDMLKEM768}, mustASN1(t, seed, "tag:0,implicit"), nil}, "")
		_, err := FromPrivatePEM(string(pem.EncodeToMemory(&pem.Block{Type: pemBlockPrivateKey, Bytes: der})))
		require.ErrorContains(t, err, "extra fields")
	})
	_, err = FromPrivatePEM(pkcs8PEM(t, asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 4, 1}, mustASN1(t, seed, "tag:0,implicit"), 0))
	require.Error(t, err) // ML-KEM-512 is not registered.
}

func TestOpenSSLMLKEMBothVectors(t *testing.T) {
	skipCIRCLWhenFIPS(t)
	for _, size := range []string{"768", "1024"} {
		t.Run(size, func(t *testing.T) {
			priv, err := os.ReadFile(filepath.Join("testdata", "mlkem-openssl", size+"-private.pem"))
			require.NoError(t, err)
			pub, err := os.ReadFile(filepath.Join("testdata", "mlkem-openssl", size+"-public.pem"))
			require.NoError(t, err)
			block, _ := pem.Decode(priv)
			require.NotNil(t, block)
			var p kemPKCS8
			_, err = asn1.Unmarshal(block.Bytes, &p)
			require.NoError(t, err)
			var inner asn1.RawValue
			_, err = asn1.Unmarshal(p.PrivateKey, &inner)
			require.NoError(t, err)
			require.Equal(t, asn1.TagSequence, inner.Tag)
			dec, err := FromPrivatePEM(string(priv))
			require.NoError(t, err)
			enc, err := FromPublicPEM(string(pub))
			require.NoError(t, err)
			wrapped, err := enc.Encrypt([]byte("openssl vector"))
			require.NoError(t, err)
			got, err := dec.Decrypt(wrapped)
			require.NoError(t, err)
			require.Equal(t, "openssl vector", string(got))
		})
	}
}

func TestCIRCLDisabledInFIPSMode(t *testing.T) {
	if os.Getenv("CIRCL_FIPS_TEST_CHILD") == "1" {
		require.True(t, fips140.Enabled())
		for _, tc := range []struct {
			size string
			key  mlkemKEM
		}{
			{"768", mlkemKEM{variant: mlkem768}},
			{"1024", mlkemKEM{variant: mlkem1024}},
		} {
			t.Run(tc.size, func(t *testing.T) {
				priv, err := os.ReadFile(filepath.Join("testdata", "mlkem-openssl", tc.size+"-private.pem"))
				require.NoError(t, err)
				block, _ := pem.Decode(priv)
				require.NotNil(t, block)
				var p kemPKCS8
				rest, err := asn1.Unmarshal(block.Bytes, &p)
				require.NoError(t, err)
				require.Empty(t, rest)
				var both struct{ Seed, ExpandedKey []byte }
				rest, err = asn1.Unmarshal(p.PrivateKey, &both)
				require.NoError(t, err)
				require.Empty(t, rest)

				_, err = FromPrivatePEM(pkcs8PEM(t, p.Algorithm.Algorithm, mustASN1(t, both.Seed, "tag:0,implicit"), 0))
				require.NoError(t, err)
				_, err = FromPrivatePEM(pkcs8PEM(t, p.Algorithm.Algorithm, mustASN1(t, both.ExpandedKey, ""), 0))
				require.ErrorIs(t, err, errCIRCLInFIPSMode)
				_, err = FromPrivatePEM(string(priv))
				require.ErrorIs(t, err, errCIRCLInFIPSMode)

				require.ErrorIs(t, tc.key.validateExpanded(both.ExpandedKey), errCIRCLInFIPSMode)
				_, err = tc.key.decapsulateExpanded(both.ExpandedKey, nil)
				require.ErrorIs(t, err, errCIRCLInFIPSMode)
				_, err = tc.key.expandSeed(both.Seed)
				require.ErrorIs(t, err, errCIRCLInFIPSMode)
			})
		}
		t.Run("xwing", func(t *testing.T) {
			_, err := NewXWingKeyPair()
			require.ErrorIs(t, err, errCIRCLInFIPSMode)
			_, _, err = XWingEncapsulate(make([]byte, XWingPublicKeySize))
			require.ErrorIs(t, err, errCIRCLInFIPSMode)
			_, err = (xwingKEM{}).decapsulate(nil, nil)
			require.ErrorIs(t, err, errCIRCLInFIPSMode)

			der, err := marshalHybridPKCS8(oidXWing, make([]byte, XWingPrivateKeySize))
			require.NoError(t, err)
			_, err = FromPrivatePEM(string(pem.EncodeToMemory(&pem.Block{Type: pemBlockPrivateKey, Bytes: der})))
			require.ErrorIs(t, err, errCIRCLInFIPSMode)
		})
		return
	}

	for _, mode := range []string{"on", "only"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestCIRCLDisabledInFIPSMode$")
			cmd.Env = append(os.Environ(), "GODEBUG=fips140="+mode, "CIRCL_FIPS_TEST_CHILD=1")
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "%s", out)
		})
	}
}
