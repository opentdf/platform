---
title: Create Key
command:
  name: create
  aliases:
    - c
  flags:
    - name: key-id
      description: A unique, often human-readable, identifier for the new key to be created.
      required: true
    - name: algorithm
      shorthand: a
      description: Algorithm for the new key (see table below for options).
      required: true
    - name: mode
      shorthand: m
      description: Describes how the private key is managed (see table below for options).
      required: true
    - name: kas
      description: Specify the Key Access Server (KAS) where the new key will be created. The KAS can be identified by its ID, URI, or Name.
      required: true
    - name: wrapping-key-id
      description: Identifier related to the wrapping key. Its meaning depends on the `mode`. For `local` mode, it's a descriptive ID for the `wrappingKey` you provide. For `provider` or `remote` mode, it's the ID of the key within the external provider/system used for wrapping.
    - name: wrapping-key
      shorthand: w
      description: The symmetric key material (AES cipher, hex encoded) used to wrap the generated private key. Primarily used when `mode` is `local`.
    - name: private-key-pem
      description: The private key PEM (encrypted by an AES 32-byte key, then base64 encoded). Used when importing an existing key pair, typically with `provider` mode.
    - name: provider-config-id
      shorthand: p
      description: Configuration ID for the key provider. Often required when `mode` is `provider` or `remote` and an external key provider is used.
    - name: public-key-pem
      shorthand: e
      description: The base64 encoded public key PEM. Required for `remote` and `public_key` modes, and can be used with `provider` mode if importing an existing key pair.
    - name: label
      shorthand: l
      description: Comma-separated key=value pairs for metadata labels to associate with the new key (e.g., "owner=team-a,env=production").
---

Creates a new cryptographic key within a specified Key Access Server (KAS).
This key is primarily used for encrypting and decrypting data keys in the TDF (Trusted Data Format) ecosystem, forming a crucial part of data protection policies.

## Examples

### Create a key in `local` mode

The KAS generates the key pair, and the private key is wrapped by the provided `wrappingKey`. The KAS is identified by its ID.

```shell
otdfctl policy kas-registry key create --key-id "aws-key" --algorithm "rsa:2048" --mode "local" --kas 891cfe85-b381-4f85-9699-5f7dbfe2a9ab --wrapping-key-id "virtru-stored-key" --wrapping-key "a8c4824daafcfa38ed0d13002e92b08720e6c4fcee67d52e954c1a6e045907d1"

otdfctl policy kas-registry key create --key-id "aws-key" --algorithm "rsa:2048" --mode "local" --kas "https://test-kas.com" --wrapping-key-id "virtru-stored-key" --wrapping-key "a8c4824daafcfa38ed0d13002e92b08720e6c4fcee67d52e954c1a6e045907d1"
```

```shell
otdfctl policy kas-registry key create --key-id "aws-key" --algorithm "rsa:2048" --mode "provider" --kas "https://test-kas.com" --public-key-pem "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tXG5NSUlDL1RDQ0FlV2dBd0lCQWdJVVNIVEoyYnpBaDdkUW1tRjAzcTZJcS9uMGw5MHdEUVlKS29aSWh2Y05BUUVMXG5CUUF3RGpFTU1Bb0dBMVVFQXd3RGEyRnpNQjRYRFRJME1EWXdOakUzTkRZMU5Gb1hEVEkxTURZd05qRTNORFkxXG5ORm93RGpFTU1Bb0dBMVVFQXd3RGEyRnpNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDXG5BUUVBeE4zQVBpaFRpb2pjYUg2b1dqMXRNdFpNYWFaK0lBMXF0cUZtcHk1Rmc4RDViRXNQNzM2R3h6VU1Gc01WXG5zaHJLRVh6OGRZOUtwMjN1SXd5ZUMwUlBXTGU1eElmVGtKVWJ5THBxR2RsRWdxajEwUlE4a1NWcTI3MFhQRVMyXG5HWlVpajJEdUpWZndwVHBMemN0aTJQc2dFT29PS0M2Tm5uQUkwTlMxbWFvLzJEeFF4cy9EOWhBSmpHZHB6eW1iXG54aTJUeEdudllidm9mQ1BkOFJkRlRDUHZnd0tMUzcrTXFCY21pYzlWZFg5MVFOT1BtclAzcklvS3RqamQrNVBZXG5sL3o3M1BBeFIzSzNTSXpJWkx2SXRxMmFob2JPT01pU3h3OHNvT2xPZEhOVUpUcEVDY2R1aFJicXVxbUs2ZlR3XG5WT2ZyY1JRaGhVNFRrRHU5MkxJN1NnbE9XUUlEQVFBQm8xTXdVVEFkQmdOVkhRNEVGZ1FVZGd4eDdVNUFRZ2ZpXG5pUVd1M2toaTl5bmVFVm93SHdZRFZSMGpCQmd3Rm9BVWRneHg3VTVBUWdmaWlRV3Uza2hpOXluZUVWb3dEd1lEXG5WUjBUQVFIL0JBVXdBd0VCL3pBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQVRjTFliSG9tSmdMUS9INmlEdmNBXG5JcElTRi9SY3hnaDdObklxUmtCK1RtNHhObE5ISXhsNFN6K0trRVpFUGgwV0tJdEdWRGozMjkzckFyUk9FT1hJXG50Vm1uMk9CdjlNLzVEUWtIajc2UnU0UFEyVGNMMENBQ2wxSktmcVhMc01jNkhIVHA4WlRQOGxNZHBXNGt6RWMzXG5mVnRndnRwSmM0V0hkVUlFekF0VGx6WVJxSWJ5eUJNV2VUalh3YTU0YU12M1JaUWRKK0MwZWh3V1REUURwaDduXG5LWTMrN0cwZW5ORVZ0eVc0ZHR4dlFRYmlkTWFueTBKRXByNlFwUG14QzhlMFoyM2RNRGRrUjFJb1Q5OVBoZFcvXG5RQzh4TWp1TENpUkVWN2E2ZTJNeENHajNmeHJuTVh3T0lxTzNBek5zd2UyYW1jb3oya3R1b3FnRFRZbG8rRmtLXG41dz09XG4tLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tXG4=" --private-key-pem "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tXG5NSUlDL1RDQ0FlV2dBd0lCQWdJVVNIVEoyYnpBaDdkUW1tRjAzcTZJcS9uMGw5MHdEUVlKS29aSWh2Y05BUUVMXG5CUUF3RGpFTU1Bb0dBMVVFQXd3RGEyRnpNQjRYRFRJME1EWXdOakUzTkRZMU5Gb1hEVEkxTURZd05qRTNORFkxXG5ORm93RGpFTU1Bb0dBMVVFQXd3RGEyRnpNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDXG5BUUVBeE4zQVBpaFRpb2pjYUg2b1dqMXRNdFpNYWFaK0lBMXF0cUZtcHk1Rmc4RDViRXNQNzM2R3h6VU1Gc01WXG5zaHJLRVh6OGRZOUtwMjN1SXd5ZUMwUlBXTGU1eElmVGtKVWJ5THBxR2RsRWdxajEwUlE4a1NWcTI3MFhQRVMyXG5HWlVpajJEdUpWZndwVHBMemN0aTJQc2dFT29PS0M2Tm5uQUkwTlMxbWFvLzJEeFF4cy9EOWhBSmpHZHB6eW1iXG54aTJUeEdudllidm9mQ1BkOFJkRlRDUHZnd0tMUzcrTXFCY21pYzlWZFg5MVFOT1BtclAzcklvS3RqamQrNVBZXG5sL3o3M1BBeFIzSzNTSXpJWkx2SXRxMmFob2JPT01pU3h3OHNvT2xPZEhOVUpUcEVDY2R1aFJicXVxbUs2ZlR3XG5WT2ZyY1JRaGhVNFRrRHU5MkxJN1NnbE9XUUlEQVFBQm8xTXdVVEFkQmdOVkhRNEVGZ1FVZGd4eDdVNUFRZ2ZpXG5pUVd1M2toaTl5bmVFVm93SHdZRFZSMGpCQmd3Rm9BVWRneHg3VTVBUWdmaWlRV3Uza2hpOXluZUVWb3dEd1lEXG5WUjBUQVFIL0JBVXdBd0VCL3pBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQVRjTFliSG9tSmdMUS9INmlEdmNBXG5JcElTRi9SY3hnaDdObklxUmtCK1RtNHhObE5ISXhsNFN6K0trRVpFUGgwV0tJdEdWRGozMjkzckFyUk9FT1hJXG50Vm1uMk9CdjlNLzVEUWtIajc2UnU0UFEyVGNMMENBQ2wxSktmcVhMc01jNkhIVHA4WlRQOGxNZHBXNGt6RWMzXG5mVnRndnRwSmM0V0hkVUlFekF0VGx6WVJxSWJ5eUJNV2VUalh3YTU0YU12M1JaUWRKK0MwZWh3V1REUURwaDduXG5LWTMrN0cwZW5ORVZ0eVc0ZHR4dlFRYmlkTWFueTBKRXByNlFwUG14QzhlMFoyM2RNRGRrUjFJb1Q5OVBoZFcvXG5RQzh4TWp1TENpUkVWN2E2ZTJNeENHajNmeHJuTVh3T0lxTzNBek5zd2UyYW1jb3oya3R1b3FnRFRZbG8rRmtLXG41dz09XG4tLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tXG4=" --wrapping-key-id "openbao-key" --provider-config-id "f86b166a-98a5-407a-939f-ef84916ce1e5"
```

```shell
otdfctl policy kas-registry key create --key-id "aws-key" --algorithm "rsa:2048" --mode "remote" --kas "https://test-kas.com" --wrapping-key-id "openbao-key" --provider-config-id "f86b166a-98a5-407a-939f-ef84916ce1e5" --public-key-pem "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tXG5NSUlDL1RDQ0FlV2dBd0lCQWdJVVNIVEoyYnpBaDdkUW1tRjAzcTZJcS9uMGw5MHdEUVlKS29aSWh2Y05BUUVMXG5CUUF3RGpFTU1Bb0dBMVVFQXd3RGEyRnpNQjRYRFRJME1EWXdOakUzTkRZMU5Gb1hEVEkxTURZd05qRTNORFkxXG5ORm93RGpFTU1Bb0dBMVVFQXd3RGEyRnpNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDXG5BUUVBeE4zQVBpaFRpb2pjYUg2b1dqMXRNdFpNYWFaK0lBMXF0cUZtcHk1Rmc4RDViRXNQNzM2R3h6VU1Gc01WXG5zaHJLRVh6OGRZOUtwMjN1SXd5ZUMwUlBXTGU1eElmVGtKVWJ5THBxR2RsRWdxajEwUlE4a1NWcTI3MFhQRVMyXG5HWlVpajJEdUpWZndwVHBMemN0aTJQc2dFT29PS0M2Tm5uQUkwTlMxbWFvLzJEeFF4cy9EOWhBSmpHZHB6eW1iXG54aTJUeEdudllidm9mQ1BkOFJkRlRDUHZnd0tMUzcrTXFCY21pYzlWZFg5MVFOT1BtclAzcklvS3RqamQrNVBZXG5sL3o3M1BBeFIzSzNTSXpJWkx2SXRxMmFob2JPT01pU3h3OHNvT2xPZEhOVUpUcEVDY2R1aFJicXVxbUs2ZlR3XG5WT2ZyY1JRaGhVNFRrRHU5MkxJN1NnbE9XUUlEQVFBQm8xTXdVVEFkQmdOVkhRNEVGZ1FVZGd4eDdVNUFRZ2ZpXG5pUVd1M2toaTl5bmVFVm93SHdZRFZSMGpCQmd3Rm9BVWRneHg3VTVBUWdmaWlRV3Uza2hpOXluZUVWb3dEd1lEXG5WUjBUQVFIL0JBVXdBd0VCL3pBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQVRjTFliSG9tSmdMUS9INmlEdmNBXG5JcElTRi9SY3hnaDdObklxUmtCK1RtNHhObE5ISXhsNFN6K0trRVpFUGgwV0tJdEdWRGozMjkzckFyUk9FT1hJXG50Vm1uMk9CdjlNLzVEUWtIajc2UnU0UFEyVGNMMENBQ2wxSktmcVhMc01jNkhIVHA4WlRQOGxNZHBXNGt6RWMzXG5mVnRndnRwSmM0V0hkVUlFekF0VGx6WVJxSWJ5eUJNV2VUalh3YTU0YU12M1JaUWRKK0MwZWh3V1REUURwaDduXG5LWTMrN0cwZW5ORVZ0eVc0ZHR4dlFRYmlkTWFueTBKRXByNlFwUG14QzhlMFoyM2RNRGRrUjFJb1Q5OVBoZFcvXG5RQzh4TWp1TENpUkVWN2E2ZTJNeENHajNmeHJuTVh3T0lxTzNBek5zd2UyYW1jb3oya3R1b3FnRFRZbG8rRmtLXG41dz09XG4tLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tXG4="
```

```shell
otdfctl policy kas-registry key create --key-id "aws-key" --algorithm "rsa:2048" --mode "public_key" --kas "https://test-kas.com" --public-key-pem "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tXG5NSUlDL1RDQ0FlV2dBd0lCQWdJVVNIVEoyYnpBaDdkUW1tRjAzcTZJcS9uMGw5MHdEUVlKS29aSWh2Y05BUUVMXG5CUUF3RGpFTU1Bb0dBMVVFQXd3RGEyRnpNQjRYRFRJME1EWXdOakUzTkRZMU5Gb1hEVEkxTURZd05qRTNORFkxXG5ORm93RGpFTU1Bb0dBMVVFQXd3RGEyRnpNSUlCSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDXG5BUUVBeE4zQVBpaFRpb2pjYUg2b1dqMXRNdFpNYWFaK0lBMXF0cUZtcHk1Rmc4RDViRXNQNzM2R3h6VU1Gc01WXG5zaHJLRVh6OGRZOUtwMjN1SXd5ZUMwUlBXTGU1eElmVGtKVWJ5THBxR2RsRWdxajEwUlE4a1NWcTI3MFhQRVMyXG5HWlVpajJEdUpWZndwVHBMemN0aTJQc2dFT29PS0M2Tm5uQUkwTlMxbWFvLzJEeFF4cy9EOWhBSmpHZHB6eW1iXG54aTJUeEdudllidm9mQ1BkOFJkRlRDUHZnd0tMUzcrTXFCY21pYzlWZFg5MVFOT1BtclAzcklvS3RqamQrNVBZXG5sL3o3M1BBeFIzSzNTSXpJWkx2SXRxMmFob2JPT01pU3h3OHNvT2xPZEhOVUpUcEVDY2R1aFJicXVxbUs2ZlR3XG5WT2ZyY1JRaGhVNFRrRHU5MkxJN1NnbE9XUUlEQVFBQm8xTXdVVEFkQmdOVkhRNEVGZ1FVZGd4eDdVNUFRZ2ZpXG5pUVd1M2toaTl5bmVFVm93SHdZRFZSMGpCQmd3Rm9BVWRneHg3VTVBUWdmaWlRV3Uza2hpOXluZUVWb3dEd1lEXG5WUjBUQVFIL0JBVXdBd0VCL3pBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQVRjTFliSG9tSmdMUS9INmlEdmNBXG5JcElTRi9SY3hnaDdObklxUmtCK1RtNHhObE5ISXhsNFN6K0trRVpFUGgwV0tJdEdWRGozMjkzckFyUk9FT1hJXG50Vm1uMk9CdjlNLzVEUWtIajc2UnU0UFEyVGNMMENBQ2wxSktmcVhMc01jNkhIVHA4WlRQOGxNZHBXNGt6RWMzXG5mVnRndnRwSmM0V0hkVUlFekF0VGx6WVJxSWJ5eUJNV2VUalh3YTU0YU12M1JaUWRKK0MwZWh3V1REUURwaDduXG5LWTMrN0cwZW5ORVZ0eVc0ZHR4dlFRYmlkTWFueTBKRXByNlFwUG14QzhlMFoyM2RNRGRrUjFJb1Q5OVBoZFcvXG5RQzh4TWp1TENpUkVWN2E2ZTJNeENHajNmeHJuTVh3T0lxTzNBek5zd2UyYW1jb3oya3R1b3FnRFRZbG8rRmtLXG41dz09XG4tLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tXG4="
```

1. The `"algorithm"` specifies the key algorithm:

    | Key Algorithm  |
    | -------------- |
    | `rsa:2048`     |
    | `rsa:4096`     |
    | `ec:secp256r1` |
    | `ec:secp384r1` |
    | `ec:secp521r1` |

2. The `"mode"` specifies where the key that is encrypting TDFs is stored. All keys will be encrypted when stored in Virtru's DB, for modes `"local"` and `"provider"`

    | Mode         | Description                                                                                             |
    | ------------ | ------------------------------------------------------------------------------------------------------- |
    | `local`      | Root Key is stored within Virtru's database and the symmetric wrapping key is stored in KAS             |
    | `provider`   | Root Key is stored within Virtru's database and the symmetric wrapping key is stored externally         |
    | `remote`     | Root Key and wrapping key are stored remotely                                                           |
    | `public_key` | Root Key and wrapping key are stored remotely. Use this when importing another org's policy information |
