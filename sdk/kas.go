package sdk

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/opentdf/opentdf-v2-poc/internal/crypto"
)

var mockKasPublicKey = `-----BEGIN CERTIFICATE-----
MIICmDCCAYACCQC3BCaSANRhYzANBgkqhkiG9w0BAQsFADAOMQwwCgYDVQQDDANr
YXMwHhcNMjEwOTE1MTQxMTQ4WhcNMjIwOTE1MTQxMTQ4WjAOMQwwCgYDVQQDDANr
YXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDOpiotrvV2i5h6clHM
zDGgh3h/kMa0LoGx2OkDPd8jogycUh7pgE5GNiN2lpSmFkjxwYMXnyrwr9ExyczB
WJ7sRGDCDaQg5fjVUIloZ8FJVbn+sEcfQ9iX6vmI9/S++oGK79QM3V8M8cp41r/T
1YVmuzUHE1say/TLHGhjtGkxHDF8qFy6Z2rYFTCVJQHNqGmwNVGd0qG7gim86Haw
u/CMYj4jG9oITlj8rJtQOaJ6ZqemQVoNmb3j1LkyeUKzRIt+86aoBiz+T3TfOEvX
F6xgBj3XoiOhPYK+abFPYcrArvb6oubT8NjjQoj3j0sXWUnIIMg+e4f+XNVU54Zz
DaLZAgMBAAEwDQYJKoZIhvcNAQELBQADggEBABewfZOJ4/KNRE8IQ5TsW/AVn7C1
l5ty6tUUBSVi8/df7WYts0bHEdQh9yl9agEU5i4rj43y8vMVZNzSeHcurtV/+C0j
fbkHQHeiQ1xn7cq3Sbh4UVRyuu4C5PklEH4AN6gxmgXC3kT15uWw8I4nm/plzYLs
I099IoRfC5djHUYYLMU/VkOIHuPC3sb7J65pSN26eR8bTMVNagk187V/xNwUuvkf
+NUxDO615/5BwQKnAu5xiIVagYnDZqKCOtYS5qhxF33Nlnwlm7hH8iVZ1RI+n52l
wVyElqp317Ksz+GtTIc+DE6oryxK3tZd4hrj9fXT4KiJvQ4pcRjpePgH7B8=
-----END CERTIFICATE-----`

var mockKasPrivateKey = `-----BEGIN PRIVATE KEY-----
	MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDOpiotrvV2i5h6
	clHMzDGgh3h/kMa0LoGx2OkDPd8jogycUh7pgE5GNiN2lpSmFkjxwYMXnyrwr9Ex
	yczBWJ7sRGDCDaQg5fjVUIloZ8FJVbn+sEcfQ9iX6vmI9/S++oGK79QM3V8M8cp4
	1r/T1YVmuzUHE1say/TLHGhjtGkxHDF8qFy6Z2rYFTCVJQHNqGmwNVGd0qG7gim8
	6Hawu/CMYj4jG9oITlj8rJtQOaJ6ZqemQVoNmb3j1LkyeUKzRIt+86aoBiz+T3Tf
	OEvXF6xgBj3XoiOhPYK+abFPYcrArvb6oubT8NjjQoj3j0sXWUnIIMg+e4f+XNVU
	54ZzDaLZAgMBAAECggEBALb0yK0PlMUyzHnEUwXV1y5AIoAWhsYp0qvJ1msHUVKz
	+yQ/VJz4+tQQxI8OvGbbnhNkd5LnWdYkYzsIZl7b/kBCPcQw3Zo+4XLCzhUAn1E1
	M+n42c8le1LtN6Z7mVWoZh7DPONy7t+ABvm7b7S1+1i78DPmgCeWYZGeAhIcPXG6
	5AxWIV3jigxksE6kYY9Y7DmtsZgMRrdV7SU8VtgPtT7tua8z5/U3Av0WINyKBSoM
	0yDHsAg57KnM8znx2JWLtHd0Mk5bBuu2DLbtyKNrVUAUuMPzrLGBh9S9QRd934KU
	uFAi1TEfgEachnGgSHJpzVzr2ur1tifABnQ7GNXObe0CgYEA6KowK0subdDY+uGW
	ciP2XDAMerbJJeL0/UIGPb/LUmskniio2493UBGgY2FsRyvbzJ+/UAOjIPyIxhj7
	78ZyVG8BmIzKan1RRVh//O+5yvks/eTOYjWeQ1Lcgqs3q4YAO13CEBZgKWKTUomg
	mskFJq04tndeSIyhDaW+BuWaXA8CgYEA42ABz3pql+DH7oL5C4KYBymK6wFBBOqk
	dVk+ftyJQ6PzuZKpfsu4aPIjKm71lkTgK6O9o08s3SckAdu6vLukq2TZFF+a+9OI
	lu5ww7GvfdMTgLAaFchD4bPlOInh1KVjBc1MwGXpl0ROde5pi8+WUrv9QJuoQfB/
	4rhYdbJLSpcCgYA41mqSCPm8pgp7r2RbWeGzP6Gs0L5u3PTQcbKonxQCfF4jrPcj
	O/b/vm6aGJClClfVsyi/WUQeqNKY4j2Zo7cGXV/cbnh8b0TNVgNePQn8Rcbx91Vb
	tJGHDNUFruIYqtGfrxXbbDvtoEExJqHvbjAt9J8oJB0KSCCH/vdfI/QDjQKBgQCD
	xLPH5Y24js/O7aAeh4RLQkv7fTKNAt5kE2AgbPYveOhZ9yC7Fpy8VPcENGGmwCuZ
	nr7b0ZqSX4iCezBxB92aZktXf0B2CFT0AyLehi7JoHWA8o1rai/MsVB5v45ciawl
	RKDiLy18OF2wAoawO5FGSSOvOYX9EL9MSMEbFESF6QKBgCVlZ9pPC+55rGT6AcEL
	tUpDs+/wZvcmfsFd8xC5mMUN0DatAVzVAUI95+tQaWU3Uj+bqHq0lC6Wy2VceG0D
	D+7EicjdGFN/2WVPXiYX1fblkxasZY+wChYBrPLjA9g0qOzzmXbRBph5QxDuQjJ6
	qcddVKB624a93ZBssn7OivnR
	-----END PRIVATE KEY-----`

func RunKAS() (*httptest.Server, string, string, error) {
	signingKeyPair, err := crypto.NewRSAKeyPair(tdf3KeySize)
	if err != nil {
		return nil, "", "", fmt.Errorf("crypto.NewRSAKeyPair: %v", err)
	}

	signingPubKey, err := signingKeyPair.PublicKeyInPemFormat()
	if err != nil {
		return nil, "", "", fmt.Errorf("crypto.PublicKeyInPemFormat failed: %v", err)
	}

	signingPrivateKey, err := signingKeyPair.PrivateKeyInPemFormat()
	if err != nil {
		return nil, "", "", fmt.Errorf("crypto.PrivateKeyInPemFormat failed: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(kAcceptKey) != kContentTypeJSONValue {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("expected Accept: application/json header, got: %s", r.Header.Get("Accept"))))
			return
		}

		r.Header.Set(kContentTypeKey, kContentTypeJSONValue)

		switch {
		case r.URL.Path == kasPublicKeyPath:
			kasPublicKeyResponse, err := json.Marshal(mockKasPublicKey)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(fmt.Sprintf("json.Marshal failed: %v", err)))
			}
			w.WriteHeader(http.StatusOK)
			_, err = w.Write(kasPublicKeyResponse)
			if err != nil {
				slog.Error("http.ResponseWriter.Write failed", slog.String("error", err.Error()))
			}
		case r.URL.Path == kRewrapV2:
			requestBody, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(fmt.Sprintf("io.ReadAll failed: %v", err)))
			}
			var data map[string]string
			err = json.Unmarshal(requestBody, &data)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(fmt.Sprintf("json.Unmarshal failed: %v", err)))
			}
			tokenString, ok := data[kSignedRequestToken]
			if !ok {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(fmt.Sprintf("signed token missing in rewrap response")))
			}
			token, err := jwt.ParseWithClaims(tokenString, &rewrapJWTClaims{}, func(token *jwt.Token) (interface{}, error) {
				signingRSAPublicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(signingPubKey))
				if err != nil {
					return nil, fmt.Errorf("jwt.ParseRSAPrivateKeyFromPEM failed: %w", err)
				}

				return signingRSAPublicKey, nil
			})
			var rewrapRequest = ""
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(fmt.Sprintf("jwt.ParseWithClaims failed:%v", err)))
			} else if claims, fine := token.Claims.(*rewrapJWTClaims); fine {
				rewrapRequest = claims.Body
			} else {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(fmt.Sprintf("unknown claims type, cannot proceed")))
			}
			err = json.Unmarshal([]byte(rewrapRequest), &data)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(fmt.Sprintf("json.Unmarshal failed: %v", err)))
			}
			wrappedKey, err := crypto.Base64Decode([]byte(data["wrappedKey"]))
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(fmt.Sprintf("crypto.Base64Decode failed: %v", err)))
			}
			kasPrivateKey := strings.ReplaceAll(mockKasPrivateKey, "\n\t", "\n")
			asymDecrypt, err := crypto.NewAsymDecryption(kasPrivateKey)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(fmt.Sprintf("crypto.NewAsymDecryption failed: %v", err)))
			}
			symmetricKey, err := asymDecrypt.Decrypt(wrappedKey)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(fmt.Sprintf("crypto.Decrypt failed: %v", err)))
			}
			asymEncrypt, err := crypto.NewAsymEncryption(data[kClientPublicKey])
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(fmt.Sprintf("crypto.NewAsymEncryption failed: %v", err)))
			}
			entityWrappedKey, err := asymEncrypt.Encrypt(symmetricKey)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(fmt.Sprintf("crypto.encrypt failed: %v", err)))
			}
			response, err := json.Marshal(map[string]string{
				kEntityWrappedKey: string(crypto.Base64Encode(entityWrappedKey)),
			})
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(fmt.Sprintf("json.Marshal failed: %v", err)))
			}
			w.WriteHeader(http.StatusOK)
			_, err = w.Write(response)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(fmt.Sprintf("http.ResponseWriter.Write failed: %v", err)))
			}
		default:
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("expected to request: %s", r.URL.Path)))
		}
	}))

	return server, signingPubKey, signingPrivateKey, nil
}
