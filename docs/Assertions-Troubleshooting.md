# Troubleshooting Assertions

Common issues and solutions when working with custom assertion providers.

See also: [Assertions.md](./Assertions.md) for assertion format details.

## Key Loading Errors

### Error: "no PEM block found in key file"

**Cause:** The key file is not in PEM format or is corrupted.

**Solution:**
1. Verify the file contains a PEM header:
   ```
   -----BEGIN RSA PRIVATE KEY-----
   or
   -----BEGIN PRIVATE KEY-----
   ```

2. Check file encoding (should be ASCII/UTF-8, not binary DER)

3. Generate a new key if needed:
   ```bash
   # RSA key
   openssl genrsa -out private-key.pem 2048

   # EC key
   openssl ecparam -genkey -name prime256v1 -out private-key.pem
   ```

### Error: "unsupported key type: PUBLIC KEY"

**Cause:** Trying to use a public key file where a private key is required.

**Solution:**
- For **signing** (encrypt): Use the private key file
- For **validation** (decrypt): The examples extract the public key from the private key file

### Error: "key is not an RSA private key"

**Cause:** The key file contains a different key type (e.g., ECDSA) than expected.

**Solution:**
1. Check key type:
   ```bash
   openssl pkey -in private-key.pem -text -noout | head -1
   ```

2. Either:
   - Use the correct key type (RSA examples currently support RSA only)
   - Convert the key (if possible)
   - Generate a new RSA key

### Error: "failed to read key file: permission denied"

**Cause:** Insufficient file permissions.

**Solution:**
```bash
# Set proper permissions
chmod 600 private-key.pem

# Verify ownership
ls -la private-key.pem
```

## Assertion Validation Errors

### Error: "assertion verification failed"

**Cause:** The assertion signature doesn't match.

**Possible causes:**
1. **Wrong key:** Using different keys for signing and validation
2. **Corrupted TDF:** File was modified after creation
3. **Key mismatch:** Public key doesn't correspond to private key used for signing

**Solution:**
1. Verify you're using the same key:
   ```bash
   # Extract public key from private key
   openssl rsa -in private-key.pem -pubout -out public-key.pem

   # Compare with expected public key
   ```

2. Re-create the TDF if it was corrupted

3. Check that encryption and decryption use matching keys

### Error: "invalid assertion value: HMAC verification failed"

**Cause:** Magic word doesn't match between encryption and decryption.

**Solution:**
```bash
# Ensure same magic word is used
./examples-cli encrypt file.txt --magic-word swordfish -o file.tdf
./examples-cli decrypt file.tdf --magic-word swordfish
```

### Error: "no validator registered for assertion"

**Cause:** No validator was registered for the assertion ID pattern.

**Solution:**
1. Check assertion ID in the TDF manifest
2. Register a validator with matching regex pattern:
   ```go
   pattern := regexp.MustCompile("^" + sdk.KeyAssertionID)
   sdk.WithAssertionValidator(pattern, validator)
   ```

## TDF Creation Errors

### Error: "failed to load assertion key"

**Cause:** Key file path is wrong or file doesn't exist.

**Solution:**
```bash
# Check file exists
ls -la /path/to/private-key.pem

# Use absolute path if relative path fails
./examples-cli encrypt file.txt --private-key-path /absolute/path/to/key.pem
```

### Error: "autoconfigure failed"

**Cause:** Platform endpoint is unreachable or attributes are misconfigured.

**Solution:**
1. Check platform connectivity:
   ```bash
   curl -v http://localhost:8080/healthz
   ```

2. Disable autoconfigure if working offline:
   ```bash
   ./examples-cli encrypt file.txt --autoconfigure=false --data-attributes=""
   ```

## Decryption Errors

### Error: "failed to open input file"

**Cause:** TDF file path is incorrect or file doesn't exist.

**Solution:**
```bash
# Check file exists
ls -la file.tdf

# Use absolute path
./examples-cli decrypt /absolute/path/to/file.tdf
```

### Error: "assertion verification disabled"

**Cause:** Assertion verification was disabled but assertions exist.

**Solution:**
Assertions are checked by default. If you see this and want validation:
```go
// Ensure verification is enabled (it is by default)
sdk.WithDisableAssertionVerification(false)
```

## Common Mistakes

### 1. Using Same Flag Values for Different Purposes

❌ **Wrong:**
```bash
# Using same key file for signing and validating (works but confusing)
./examples-cli encrypt file.txt --private-key-path key.pem
./examples-cli decrypt file.tdf --private-key-path key.pem
```

✅ **Better:**
```bash
# Be explicit about intent
./examples-cli encrypt file.txt --private-key-path signing-key.pem
./examples-cli decrypt file.tdf --private-key-path signing-key.pem
```

### 2. Mixing Assertion Types

❌ **Wrong:**
```bash
# Encrypting with key-based assertion
./examples-cli encrypt file.txt --private-key-path key.pem -o file.tdf

# Trying to decrypt with magic word (won't validate the key assertion)
./examples-cli decrypt file.tdf --magic-word swordfish
```

✅ **Correct:**
```bash
# Use same assertion type for validation
./examples-cli decrypt file.tdf --private-key-path key.pem
```

### 3. Forgetting to Enable Verification

The examples enable verification by default. If validation isn't running, check that you didn't accidentally disable it.

## Debug Tips

### 1. Inspect TDF Manifest

```bash
# Extract and view manifest (TDF is a ZIP file)
unzip -p file.tdf manifest.json | jq .

# Check assertions array
unzip -p file.tdf manifest.json | jq '.assertions'
```

### 2. Verify Key Format

```bash
# View private key details
openssl rsa -in private-key.pem -text -noout

# Check key size
openssl rsa -in private-key.pem -text -noout | grep "Private-Key"
```

### 3. Test Assertion Provider Independently

```go
// Test signing (payloadHash is computed from manifest.ComputeAggregateHash())
assertion, err := binder.Bind(ctx, payloadHash)
if err != nil {
    log.Printf("Binding failed: %v", err)
}

// Test validation
err = validator.Verify(ctx, assertion, reader)
if err != nil {
    log.Printf("Verification failed: %v", err)
}
```

## Getting Help

If you're still stuck:

1. **Check the examples:**
   - `examples/cmd/assertion_provider_mw.go` - Simple magic word provider
   - `examples/cmd/keys.go` - Key loading utilities
   - [Assertions.md](./Assertions.md) - Assertion format details

2. **Enable debug logging:**
   ```go
   // Add logging in your custom provider
   log.Printf("Assertion ID: %s", assertion.ID)
   log.Printf("Binding method: %s", assertion.Binding.Method)
   ```

3. **Review the ADR:**
   - `adr/decisions/2025-10-16-custom-assertion-providers.md`

4. **Check OpenTDF Specification:**
   - [https://github.com/opentdf/spec](https://github.com/opentdf/spec)

5. **File an issue:**
   - [https://github.com/opentdf/platform/issues](https://github.com/opentdf/platform/issues)
