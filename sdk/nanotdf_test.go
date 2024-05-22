package sdk

//// nanotdfEqual compares two nanoTdf structures for equality.
//func nanoTDFEqual(a, b *NanoTDFHeader) bool {
//	// Compare magicNumber field
//	if a.magicNumber != b.magicNumber {
//		return false
//	}
//
//	// Compare kasURL field
//	if a.kasURL.protocol != b.kasURL.protocol || a.kasURL.getLength() != b.kasURL.getLength() || a.kasURL.body != b.kasURL.body {
//		return false
//	}
//
//	// Compare binding field
//	if a.binding.useEcdsaBinding != b.binding.useEcdsaBinding || a.binding.padding != b.binding.padding || a.binding.eccMode != b.binding.eccMode {
//		return false
//	}
//
//	// Compare sigCfg field
//	if a.sigCfg.hasSignature != b.sigCfg.hasSignature || a.sigCfg.signatureMode != b.sigCfg.signatureMode || a.sigCfg.cipher != b.sigCfg.cipher {
//		return false
//	}
//
//	// Compare policy field
//	if a.policy.body.mode != b.policy.body.mode || !policyBodyEqual(a.policy.body, b.policy.body) || !eccSignatureEqual(a.policy.binding, b.policy.binding) {
//		return false
//	}
//
//	// Compare EphemeralPublicKey field
//	if !bytes.Equal(a.EphemeralPublicKey.Key, b.EphemeralPublicKey.Key) {
//		return false
//	}
//
//	// If all comparisons passed, the structures are equal
//	return true
//}
//
//// policyBodyEqual compares two PolicyBody instances for equality.
//func policyBodyEqual(a, b PolicyBody) bool {
//	// Compare based on the concrete type of PolicyBody
//	switch a.mode {
//	case policyTypeRemotePolicy:
//		return remotePolicyEqual(a.rp, b.rp)
//	case policyTypeEmbeddedPolicyPlainText:
//	case policyTypeEmbeddedPolicyEncrypted:
//	case policyTypeEmbeddedPolicyEncryptedPolicyKeyAccess:
//		return embeddedPolicyEqual(a.ep, b.ep)
//	}
//	return false
//}
//
//// remotePolicyEqual compares two remotePolicy instances for equality.
//func remotePolicyEqual(a, b remotePolicy) bool {
//	// Compare url field
//	if a.url.protocol != b.url.protocol || a.url.getLength() != b.url.getLength() || a.url.body != b.url.body {
//		return false
//	}
//	return true
//}
//
//// embeddedPolicyEqual compares two embeddedPolicy instances for equality.
//func embeddedPolicyEqual(a, b embeddedPolicy) bool {
//	// Compare lengthBody and body fields
//	return a.lengthBody == b.lengthBody && a.body == b.body
//}
//
//// eccSignatureEqual compares two eccSignature instances for equality.
//func eccSignatureEqual(a, b *eccSignature) bool {
//	// Compare value field
//	return bytes.Equal(a.value, b.value)
//}
//
//func init() {
//	// Register the remotePolicy type with gob
//	gob.Register(&remotePolicy{})
//}
//
//func TestReadNanoTDFHeader(t *testing.T) {
//	// Prepare a sample nanoTdf structure
//	goodHeader := NanoTDFHeader{
//		magicNumber: [3]byte{'L', '1', 'L'},
//		kasURL: ResourceLocator{
//			protocol: urlProtocolHTTPS,
//			body:     "kas.virtru.com",
//		},
//		binding: bindingConfig{
//			useEcdsaBinding: true,
//			padding:         0,
//			eccMode:     ocrypto.ECCModeSecp256r1,
//		},
//		sigCfg: signatureConfig{
//			hasSignature:  true,
//			signatureMode: ocrypto.ECCModeSecp256r1,
//			cipher:        cipherModeAes256gcm64Bit,
//		},
//		policy: policyInfo{
//			body: PolicyBody{
//				mode: policyTypeRemotePolicy,
//				rp: remotePolicy{
//					url: ResourceLocator{
//						protocol: urlProtocolHTTPS,
//						body:     "kas.virtru.com/policy",
//					},
//				},
//			},
//			binding: &eccSignature{
//				value: []byte{181, 228, 19, 166, 2, 17, 229, 241},
//			},
//		},
//		EphemeralPublicKey: eccKey{
//			Key: []byte{123, 34, 52, 160, 205, 63, 54, 255, 123, 186, 109,
//				143, 232, 223, 35, 246, 44, 157, 9, 53, 111, 133,
//				130, 248, 169, 207, 21, 18, 108, 138, 157, 164, 108},
//		},
//	}
//
//	// Serialize the sample nanoTdf structure into a byte slice using gob
//	file, err := os.Open("nanotdfspec.ntdf")
//	if err != nil {
//		t.Fatalf("Cannot open nanoTdf file: %v", err)
//	}
//	defer file.Close()
//
//	var resultHeader NanoTDFHeader
//	err = resultHeader.ReadNanoTDFHeader(file)
//	if err != nil {
//		t.Fatalf("Error while reading nanoTdf header: %v", err)
//	}
//
//	// Compare the result with the original nanoTdf structure
//	if !nanoTDFEqual(&resultHeader, &goodHeader) {
//		t.Error("Result does not match the expected nanoTdf structure.")
//	}
//}

const (
	sdkPrivateKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1HjFYV8D16BQszNW
6Hx/JxTE53oqk5/bWaIj4qV5tOyhRANCAAQW1Hsq0tzxN6ObuXqV+JoJN0f78Em/
PpJXUV02Y6Ex3WlxK/Oaebj8ATsbfaPaxrhyCWB3nc3w/W6+lySlLPn5
-----END PRIVATE KEY-----`

	//	sdkPublicKey = `-----BEGIN PUBLIC KEY-----
	// MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFtR7KtLc8Tejm7l6lfiaCTdH+/BJ
	// vz6SV1FdNmOhMd1pcSvzmnm4/AE7G32j2sa4cglgd53N8P1uvpckpSz5+Q==
	// -----END PUBLIC KEY-----`

	//	kasPrivateKey = `-----BEGIN PRIVATE KEY-----
	// MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu2Hmm80uUzQB1OfB
	// PyMhWIyJhPA61v+j0arvcLjTwtqhRANCAASHCLUHY4szFiVV++C9+AFMkEL2gG+O
	// byN4Hi7Ywl8GMPOAPcQdIeUkoTd9vub9PcuSj23I8/pLVzs23qhefoUf
	// -----END PRIVATE KEY-----`

	kasPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEhwi1B2OLMxYlVfvgvfgBTJBC9oBv
jm8jeB4u2MJfBjDzgD3EHSHlJKE3fb7m/T3Lko9tyPP6S1c7Nt6oXn6FHw==
-----END PUBLIC KEY-----`
)

//func TestNanoTdfWriteHeader(t *testing.T) {
//	compressedPubKey := [...]byte{
//		0x03, 0x16, 0xd4, 0x7b, 0x2a, 0xd2, 0xdc, 0xf1, 0x37, 0xa3, 0x9b, 0xb9, 0x7a, 0x95, 0xf8, 0x9a,
//		0x09, 0x37, 0x47, 0xfb, 0xf0, 0x49, 0xbf, 0x3e, 0x92, 0x57, 0x51, 0x5d, 0x36, 0x63, 0xa1, 0x31,
//		0xdd,
//	}
//
//	expectedHeader := [...]byte{
//		0x4c, 0x31, 0x4c, 0x01, 0x12, 0x61, 0x70, 0x69, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x2e,
//		0x63, 0x6f, 0x6d, 0x2f, 0x6b, 0x61, 0x73, 0x00, 0x00, 0x00, 0x01, 0x56, 0x61, 0x70, 0x69, 0x2d,
//		0x64, 0x65, 0x76, 0x65, 0x6c, 0x6f, 0x70, 0x30, 0x31, 0x2e, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x6f,
//		0x70, 0x2e, 0x76, 0x69, 0x72, 0x74, 0x72, 0x75, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x61, 0x63, 0x6d,
//		0x2f, 0x61, 0x70, 0x69, 0x2f, 0x70, 0x6f, 0x6c, 0x69, 0x63, 0x69, 0x65, 0x73, 0x2f, 0x31, 0x61,
//		0x31, 0x64, 0x35, 0x65, 0x34, 0x32, 0x2d, 0x62, 0x66, 0x39, 0x31, 0x2d, 0x34, 0x35, 0x63, 0x37,
//		0x2d, 0x61, 0x38, 0x36, 0x61, 0x2d, 0x36, 0x31, 0x64, 0x35, 0x33, 0x33, 0x31, 0x63, 0x31, 0x66,
//		0x35, 0x35, 0x33, 0x31, 0x63, 0x31, 0x66, 0x35, 0x35, 0x00, 0x03, 0x16, 0xd4, 0x7b, 0x2a, 0xd2,
//		0xdc, 0xf1, 0x37, 0xa3, 0x9b, 0xb9, 0x7a, 0x95, 0xf8, 0x9a, 0x09, 0x37, 0x47, 0xfb, 0xf0, 0x49,
//		0xbf, 0x3e, 0x92, 0x57, 0x51, 0x5d, 0x36, 0x63, 0xa1, 0x31, 0xdd,
//	}
//
//	kasUrl := "https://api.exampl.com/kas"
//
//	remotePolicyUrl := "https://api-develop01.develop.virtru.com/acm/api/policies/1a1d5e42-bf91-45c7-a86a-61d5331c1f55"
//
//	policyBinding := [...]byte{0x33, 0x31, 0x63, 0x31, 0x66, 0x35, 0x35, 0x00}
//
//	{ // Construct empty header - encrypt use case
//		var err error
//		config := NanoTDFConfig{}
//
//		err = config.kasURL.setUrl(kasUrl)
//		if err != nil {
//			t.Fatalf("Cannot set policy url: %v", err)
//		}
//
//		config.eccMode = ocrypto.ECCModeSecp256r1
//
//		config.sigCfg = deserializeSignatureCfg(0x00) // no signature and AES_256_GCM_64_TAG
//
//		config.mKasPublicKey = kasPublicKey
//		config.privateKey = sdkPrivateKey
//
//		config.binding = deserializeBindingCfg(0x00)
//
//		var policyUrl ResourceLocator
//		err = policyUrl.setUrl(remotePolicyUrl)
//		if err != nil {
//			t.Fatalf("Cannot set policy url: %v", err)
//		}
//
//		policyBody := PolicyBody{mode: policyTypeRemotePolicy, rp: remotePolicy{url: policyUrl}}
//
//		polInfo := policyInfo{body: policyBody, binding: nil}
//		config.policy = polInfo
//
//		// Copy pre-built compressed public key
//		var epk eccKey
//		epk.Key = make([]byte, len(compressedPubKey))
//
//		// TODO FIXME - has to be a better way of copying this fixed data in
//		var i int
//		for _, b := range compressedPubKey {
//			epk.Key[i] = b
//			i++
//		}
//		config.EphemeralPublicKey = epk
//
//		var header NanoTDFHeader
//		err = createHeader(&header, &config)
//		if err != nil {
//			t.Fatalf("Cannot create nanoTdf header: %v", err)
//		}
//
//		// Copy pre-built policy binding
//		header.policyBinding = make([]byte, len(policyBinding))
//		i = 0
//		for _, b := range policyBinding {
//			header.policyBinding[i] = b
//			i++
//		}
//
//		headerLength := header.getLength()
//		headerBuffer := bytes.NewBuffer(make([]byte, 0, headerLength))
//		hbWriter := bufio.NewWriter(headerBuffer)
//
//		err = writeHeader(&header, hbWriter)
//		if err != nil {
//			t.Fatalf("Cannot write nanoTdf header: %v", err)
//		}
//
//		err = hbWriter.Flush()
//		if err != nil {
//			t.Fatalf("Cannot flush nanoTdf header: %v", err)
//		}
//
//		// Check length
//		if uint64(len(expectedHeader)) != headerLength {
//			t.Logf("Wrong header length. Expected %d, got %d", len(expectedHeader), headerLength)
//		}
//
//		// Check content
//		i = 0
//		hbReader := bufio.NewReader(headerBuffer)
//		for _, b := range expectedHeader {
//			hb, err := hbReader.ReadByte()
//			if err != nil {
//				t.Fatalf("Cannot read nanoTdf header buffer: %v", err)
//			}
//			if b != hb {
//				//t.Fatalf("Unexpected header byte read: offset %d expected %v, got %v", i, b, hb)
//				t.Logf("Unexpected header byte read: offset %d expected %v, got %v", i, b, hb)
//			}
//			i++
//		}
//	}
//
//	// result, err := ReadNanoTDFHeader(file)
//	// if err != nil {
//	//	t.Fatalf("Error while reading nanoTdf header: %v", err)
//	// }
//}
//
//func NotTestNanoTDFEncryptFile(t *testing.T) {
//	infile, err := os.Open("nanotest1.txt")
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	// try to delete the output file in case it exists already - ignore error if it doesn't exist
//	_ = os.Remove("nanotest1.ntdf")
//
//	outfile, err := os.Create("nanotest1.ntdf")
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	// TODO - populate config properly
//	var kasURL = "https://kas.virtru.com/kas"
//	var config NanoTDFConfig
//	config.bufferSize = 8192 * 1024
//	err = config.kasURL.setUrl(kasURL)
//	if err != nil {
//		t.Fatal(err)
//	}
//	config.privateKey = sdkPrivateKey
//	config.mKasPublicKey = kasPublicKey
//	config.eccMode = ocrypto.ECCModeSecp256r1
//
//	err = NanoTDFEncryptFile(infile, outfile, config)
//	if err != nil {
//		t.Fatal(err)
//	}
//}
//
//func TestCreateNanoTDF(t *testing.T) {
//
//	infile, err := os.Open("nanotest1.txt")
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	// try to delete the output file in case it exists already - ignore error if it doesn't exist
//	_ = os.Remove("nanotest1.ntdf")
//
//	outfile, err := os.Create("nanotest1.ntdf")
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	// TODO - populate config properly
//	var kasURL = "https://kas.virtru.com/kas"
//	var config NanoTDFConfig
//	config.bufferSize = 8192 * 1024
//	config.kasURL.body = kasURL               // TODO - check for excessive length here
//	config.kasURL.protocol = urlProtocolHTTPS // TODO FIXME - should be derived from URL
//	config.privateKey = sdkPrivateKey
//	config.mKasPublicKey = kasPublicKey
//	config.eccMode = ocrypto.ECCModeSecp256r1
//
//	_, err = CreateNanoTDF(outfile, infile, config)
//	if err != nil {
//		t.Fatal(err)
//	}
//}
