package sdk

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNanoTDFConfig1 - Create a new config, verify that the config contains valid PEMs for the key pair
func TestNanoTDFConfig1(t *testing.T) {
	var s SDK
	conf, err := s.NewNanoTDFConfig()
	if err != nil {
		t.Fatal(err)
	}
	pemPrvKey, err := conf.keyPair.PrivateKeyInPemFormat()
	if err != nil {
		t.Fatal(err)
	}

	if len(pemPrvKey) == 0 {
		t.Fatal("no private key")
	}

	pemPubKey, err := conf.keyPair.PublicKeyInPemFormat()
	if err != nil {
		t.Fatal(err)
	}
	if len(pemPubKey) == 0 {
		t.Fatal("no public key")
	}
}

// TestNanoTDFConfig2 - set kas url, retrieve kas url, verify value is correct
func TestNanoTDFConfig2(t *testing.T) {
	const (
		kasURL = "https://test.virtru.com"
	)

	var s SDK
	conf, err := s.NewNanoTDFConfig()
	if err != nil {
		t.Fatal(err)
	}
	err = conf.SetKasURL(kasURL)
	if err != nil {
		t.Fatal(err)
	}

	readKasURL, err := conf.kasURL.GetURL()
	if err != nil {
		t.Fatal(err)
	}
	if readKasURL != kasURL {
		t.Fatalf("expect %s, got %s", kasURL, readKasURL)
	}
}

func TestNewNanoTDFReaderConfig(t *testing.T) {
	t.Run("Valid options", func(t *testing.T) {
		config, err := newNanoTDFReaderConfig(
			WithNanoKasAllowlist([]string{"https://example.com:443", "https://another.com"}),
			WithNanoIgnoreAllowlist(true),
		)
		require.NoError(t, err, "Expected no error when creating NanoTDFReaderConfig with valid options")
		assert.NotNil(t, config, "Expected NanoTDFReaderConfig to be created")
		assert.True(t, config.ignoreAllowList, "Expected ignoreAllowList to be true")
		assert.True(t, config.kasAllowlist.IsAllowed("https://example.com:443"), "Expected KAS URL to be allowed")
		assert.True(t, config.kasAllowlist.IsAllowed("https://another.com"), "Expected KAS URL to be allowed")
	})

	t.Run("Invalid KAS URL in allowlist", func(t *testing.T) {
		config, err := newNanoTDFReaderConfig(
			WithNanoKasAllowlist([]string{""}),
		)
		require.Error(t, err, "Expected an error when creating NanoTDFReaderConfig with invalid KAS URL")
		assert.Nil(t, config, "Expected NanoTDFReaderConfig to be nil")
	})
}

func TestWithNanoKasAllowlist(t *testing.T) {
	t.Run("Valid KAS URLs", func(t *testing.T) {
		config := &NanoTDFReaderConfig{}
		err := WithNanoKasAllowlist([]string{"https://example.com:443", "https://another.com"})(config)
		require.NoError(t, err, "Expected no error when adding valid KAS URLs to allowlist")
		assert.True(t, config.kasAllowlist.IsAllowed("https://example.com"), "Expected KAS URL to be allowed")
		assert.True(t, config.kasAllowlist.IsAllowed("https://another.com"), "Expected KAS URL to be allowed")
	})

	t.Run("Invalid KAS URL", func(t *testing.T) {
		config := &NanoTDFReaderConfig{}
		err := WithNanoKasAllowlist([]string{""})(config)
		require.Error(t, err, "Expected an error when adding invalid KAS URL to allowlist")
	})
}

func TestWithNanoIgnoreAllowlist(t *testing.T) {
	t.Run("Set ignoreAllowList to true", func(t *testing.T) {
		config := &NanoTDFReaderConfig{}
		err := WithNanoIgnoreAllowlist(true)(config)
		require.NoError(t, err, "Expected no error when setting ignoreAllowList to true")
		assert.True(t, config.ignoreAllowList, "Expected ignoreAllowList to be true")
	})

	t.Run("Set ignoreAllowList to false", func(t *testing.T) {
		config := &NanoTDFReaderConfig{}
		err := WithNanoIgnoreAllowlist(false)(config)
		require.NoError(t, err, "Expected no error when setting ignoreAllowList to false")
		assert.False(t, config.ignoreAllowList, "Expected ignoreAllowList to be false")
	})
}

func TestWithNanoKasAllowlist_with(t *testing.T) {
	t.Run("Valid AllowList", func(t *testing.T) {
		allowlist := AllowList{"https://example.com:443": true}
		config := &NanoTDFReaderConfig{}
		err := withNanoKasAllowlist(allowlist)(config)
		require.NoError(t, err, "Expected no error when setting valid AllowList")
		assert.True(t, config.kasAllowlist.IsAllowed("https://example.com"), "Expected KAS URL to be allowed")
	})

	t.Run("Empty AllowList", func(t *testing.T) {
		allowlist := AllowList{}
		config := &NanoTDFReaderConfig{}
		err := withNanoKasAllowlist(allowlist)(config)
		require.NoError(t, err, "Expected no error when setting empty AllowList")
		assert.False(t, config.kasAllowlist.IsAllowed("https://example.com:443"), "Expected KAS URL to not be allowed")
	})
}

func TestSetPolicyMode(t *testing.T) {
	t.Run("Set to plaintext", func(t *testing.T) {
		var s SDK
		conf, err := s.NewNanoTDFConfig()
		require.NoError(t, err)

		err = conf.SetPolicyMode(NanoTDFPolicyModePlainText)
		require.NoError(t, err)
		assert.Equal(t, NanoTDFPolicyModePlainText, conf.policyMode)
	})

	t.Run("Set to encrypted", func(t *testing.T) {
		var s SDK
		conf, err := s.NewNanoTDFConfig()
		require.NoError(t, err)

		err = conf.SetPolicyMode(NanoTDFPolicyModeEncrypted)
		require.NoError(t, err)
		assert.Equal(t, NanoTDFPolicyModeEncrypted, conf.policyMode)
	})

	t.Run("Set to invalid mode", func(t *testing.T) {
		var s SDK
		conf, err := s.NewNanoTDFConfig()
		require.NoError(t, err)

		err = conf.SetPolicyMode(PolicyType(99)) // Assuming 99 is an invalid policyType
		require.Error(t, err)
		assert.NotEqual(t, PolicyType(99), conf.policyMode)
	})
}

func TestWithNanoDissems(t *testing.T) {
	dissems := []string{"user1@example.com", "user2@example.com"}

	conf := &NanoTDFConfig{}
	err := WithNanoDissems(dissems...)(conf)

	require.NoError(t, err)
	assert.Equal(t, dissems, conf.dissem)
}
