package sdk

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"io"
	"testing"

	"github.com/opentdf/platform/sdk/nanobuilder"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	kSampleURLBody = "test.virtru.com"
	// kSampleUrlProto = policyTypeRemotePolicy
	kSampleURLFull = "https://" + kSampleURLBody
)

// TestNanoTDFPolicyWrite - Create a new policy, write it to a buffer
func TestNanoTDFPolicy(t *testing.T) {
	pb := &PolicyBody{
		mode: nanobuilder.PolicyModeRemote,
		rp: remotePolicy{
			url: ResourceLocator{
				protocol: 1,
				body:     kSampleURLBody,
			},
		},
	}

	buffer := new(bytes.Buffer)
	err := pb.writePolicyBody(io.Writer(buffer))
	if err != nil {
		t.Fatal(err)
	}

	pb2 := &PolicyBody{}
	err = pb2.readPolicyBody(bytes.NewReader(buffer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}

	fullURL, err := pb2.rp.url.GetURL()
	if err != nil {
		t.Fatal(err)
	}
	if fullURL != kSampleURLFull {
		t.Fatal(fullURL)
	}
}

func TestCreateEmbeddedPolicy(t *testing.T) {
	// Test data
	policyData := []byte(`{"attributes":["https://example.com/attr/Classification/value/S"]}`)

	t.Run("plaintext policy", func(t *testing.T) {
		config, err := new(SDK).NewNanoTDFConfig()
		require.NoError(t, err)
		err = config.SetPolicyMode(nanobuilder.PolicyModePlainText)
		require.NoError(t, err)

		policy, err := createNanoTDFEmbeddedPolicy(make([]byte, 32), policyData, *config)
		require.NoError(t, err)
		assert.Equal(t, uint16(len(policyData)), policy.lengthBody)
		assert.Equal(t, policyData, policy.body)
	})

	t.Run("encrypted policy", func(t *testing.T) {
		config, err := new(SDK).NewNanoTDFConfig()
		require.NoError(t, err)

		// Defaults to encrypted policy

		// Setup KAS public key
		key, err := ecdh.P256().GenerateKey(rand.Reader)
		require.NoError(t, err)
		config.kasPublicKey = key.PublicKey()

		policy, err := createNanoTDFEmbeddedPolicy(make([]byte, 32), policyData, *config)
		require.NoError(t, err)

		// Verify the encrypted policy is different from input and has expected length
		assert.NotEqual(t, policyData, policy.body)
		assert.NotEmpty(t, policy.body, "Encrypted policy body should not be empty")
		assert.Equal(t, uint16(len(policy.body)), policy.lengthBody)

		assert.NotEqual(t, policyData, policy.body, "Policy body should be encrypted and different from original data")
		assert.NotEmpty(t, policy.body, "Policy body should not be empty after encryption")
	})
}
