# Background

Recently, we've discussed at length how we might improve the performance of the platform, while not compromising security. One of the more obvious levers to pull is to improve the performance of the various cryptographic operations that takes place in the platform, both on the client, as well as on the backend. 

RSA is currently the algorithm supported across all of our clients, and backend services. It's used for rewrapping payload keys, validating auth tokens, and, for deployments with DPOP enabled, validating DPOP signatures.

This ADR proposes switching to ECC as it is superior across several dimensions we care about:

### RSA vs. ECC Strength

Security (bits) | DSA / RSA | ECC | ECC to RSA Key Size ratio / DSA 
-- | -- | -- | -- 
80 | 1024 | 160-223 | 1:6 | 
112 | 2048 | 224-255 | 1:9 | 
128 | 3072 | 256-383 | 1:12 | 
192 | 7680 | 384-511 | 1:20 |  
256 | 15360 | 512+ | 1:30

### Standards and compliance
NIST has approved ECC algorithms as part of their cryptographic standards. 
ECC is also FIPS 140-2/140-3 compliant. 


### How ECC "rewrap" will work

Rewrap using elliptic curves will use ECIES (Elliptic Curve Integrated Encryption Scheme), in the
same way the NanoTDF specification does. Below is step by step, how a symmetric key is create/derived,
and protected.


ECIES is a hybrid encryption scheme, meaning it uses both public-key (asymmetric) 
and secret-key (symmetric) cryptography. The high-level steps involved in an ECIES fit for our purposes
are:

#### Encryption

1. Retrieve the KAS ECC public key.
2. Generate an ephemeral ECC key pair.
3. Use the ephemeral private key and the KAS public key to derive a shared secret.
4. Derive a payload key (symmetric) from the shared secret.
5. Encrypt the payload using the payload key.
6. Construct the key access object with:
   - Ephemeral public key
   - KAS key ID

#### Decryption

1. Generate an ECC key pair for the client.
2. Send a rewrap request to KAS, including:
   - Key access object (which includes the ephemeral public key and KAS key ID)
   - Client public key
3. KAS validates the request.
4. KAS extracts the ephemeral public key.
5. KAS uses the ephemeral public key and the KAS ECC private key to derive the shared secret #1.
6. KAS derives the payload key using the shared secret #1.
7. KAS generates an ephemeral ECC key pair.
8. KAS uses the client public key and the KAS ephemeral private key to derive a shared secret #2.
9. KAS derives a session key from the shared secret #2.
10. KAS encrypts the payload key using the session key.

# Options

## Option 1 - Use existing spec w/ "ec-wrapped" type

We can use the existing spec, and just add a new Key Access Object
`type` - probably `ec-wrapped`, or something similar.

The ephemeral public key which was used to derive the shared secret would 
be placed in the `wrappedKey` field. The problem with this approach is that our SDKs would need to
include functionality to inspect the ECC public keys to determine which curve was used. Option #2 proposes
using the type field to also specify the curve.

### Example

```json
{
  "type": "ec-wrapped",
  "url": "https:\/\/kas.example.com:5000",
  "kid": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
  "sid": "AD234EJ0F98ASDFSJ+NZCVSADFI0ERASDF==",
  "protocol": "kas",
  "wrappedKey": "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBTJeOqKR1Kpc8SVSf96VeVOISm3OOWqXFBLb14W3R1basXn5QpSe2+AtfZ/xru5AworbY2KaxAzD7nXLsJwLNgsbAKIsz75wOzDrDtjw4wkpEdH1492WKgOPVSzYTrbsjTtHrnLN4Yd1jvBXv+EFMsMEU+wEws=",
  "policyBinding": {
     "alg": "HS256",
     "hash": "ZoJTNW24UGBSuBBAAjA4GGAAQBTJeOqKR1Kpc8SVSf96VeVMhnXIif0mSnqLVCU="
  },
  "encryptedMetadata": "ZoJTNW24UMhnXIif0mSnqLVCU=",
  "tdf_spec_version:": "x.y.z"
}
```

## Option 2 - Use existing spec w/ curve as the KAO type

Same as option one, but we use the type field to specify which curve was used. Probably 
unnecessary as the curve is encoded into the key.

### Example

```json
{
  "type": "ec-wrapped-secp521r1",
  "url": "https:\/\/kas.example.com:5000",
  "kid": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
  "sid": "AD234EJ0F98ASDFSJ+NZCVSADFI0ERASDF==",
  "protocol": "kas",
  "wrappedKey": "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBTJeOqKR1Kpc8SVSf96VeVOISm3OOWqXFBLb14W3R1basXn5QpSe2+AtfZ/xru5AworbY2KaxAzD7nXLsJwLNgsbAKIsz75wOzDrDtjw4wkpEdH1492WKgOPVSzYTrbsjTtHrnLN4Yd1jvBXv+EFMsMEU+wEws=",
  "policyBinding": {
     "alg": "HS256",
     "hash": "ZoJTNW24UGBSuBBAAjA4GGAAQBTJeOqKR1Kpc8SVSf96VeVMhnXIif0mSnqLVCU="
  },
  "encryptedMetadata": "ZoJTNW24UMhnXIif0mSnqLVCU=",
  "tdf_spec_version:": "x.y.z"
}
```

## Option 3 - Update the spec to more closely resemble NanoTDF's fields

This approach uses the ec-wrapped type, but adds the `ephemeralPublicKey` field to be more clear that
what's being passed to the KAS isn't a wrappedKey exactly, but instead a public key used to derive
the shares secret.

### Example

```json
{
  "type": "ec-wrapped",
  "url": "https:\/\/kas.example.com:5000",
  "kid": "2",
  "sid": "AD234EJ0F98ASDFSJ+NZCVSADFI0ERASDF==",
  "protocol": "kas",
  "ephemeralPublicKey": "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBTJeOqKR1Kpc8SVSf96VeVOISm3OOWqXFBLb14W3R1basXn5QpSe2+AtfZ/xru5AworbY2KaxAzD7nXLsJwLNgsbAKIsz75wOzDrDtjw4wkpEdH1492WKgOPVSzYTrbsjTtHrnLN4Yd1jvBXv+EFMsMEU+wEws=",
  "policyBinding": {
     "alg": "HS256",
     "hash": "ZoJTNW24UGBSuBBAAjA4GGAAQBTJeOqKR1Kpc8SVSf96VeVMhnXIif0mSnqLVCU="
  },
  "encryptedMetadata": "ZoJTNW24UMhnXIif0mSnqLVCU=",
  "tdf_spec_version:": "x.y.z"
}
```

Doing 2048 bits private rsa sign ops for 10s: 17651 2048 bits private RSA sign ops in 9.90s
Doing 2048 bits public rsa verify ops for 10s: 711818 2048 bits public RSA verify ops in 9.90s
Doing 256 bits sign ecdsa ops for 10s: 584002 256 bits ECDSA sign ops in 9.89s
Doing 256 bits verify ecdsa ops for 10s: 188408 256 bits ECDSA verify ops in 9.91s
    




