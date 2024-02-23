# NanoTDF: A compact, binary format for data protection.
# https://github.com/virtru/nanotdf
---
meta:
  id: nanotdf
  file-extension: tdf
  endian: be
seq:
  - id: header
    type: header
  - id: payload
    type: payload
  - id: signature
    type: ntdf_signature
    if: header.sig_cfg.has_signature
types:
  header:
    seq:
      - id: magic
        contents: L1L
      - id: kas
        type: resource_locator
      - id: binding
        type: binding_cfg
      - id: sig_cfg
        type: signature_config
      - id: policy
        type: policy
      - id: ephemeral_public_key
        type: ecc_key
  payload:
    seq:
      - id: length
        type: b24
      - id: payload_body
        size: length
  ntdf_signature:
    seq:
      - id: client_key
        type: ecc_key
      - id: client_signature
        type: ecc_signature
  binding_cfg:
    seq:
      - id: use_ecdsa_binding
        type: b1
      - id: padding
        type: b3
      - id: binding_body
        type: b4
        enum: ecc_mode
  signature_config:
    seq:
      - id: has_signature
        type: b1
      - id: signature_mode
        type: b3
        enum: ecc_mode
      - id: cipher
        type: b4
        enum: cipher_mode
  resource_locator:
    seq:
      - id: protocol
        type: u1
        enum: url_protocol
      - id: len
        type: u1
      - id: body
        type: str
        encoding: UTF-8
        size: len
  policy:
    seq:
      - id: mode
        type: u1
      - id: body
        type:
          switch-on: mode
          cases:
            0: remote_policy
            1: embedded_policy
            2: embedded_policy # encrypted
            3: embedded_policy # Policy KA
      - id: binding
        type: ecc_signature
  embedded_policy:
    seq:
      - id: len
        type: u2
      - id: body
        encoding: UTF-8
        type: str
        size: len
  remote_policy:
    seq:
      - id: url
        type: resource_locator
  ecc_signature:
    seq:
      - id: value
        size: >
          2 * (
            _root.header.binding.binding_body == ecc_mode::secp256r1 ? 32
              : _root.header.binding.binding_body == ecc_mode::secp384r1 ? 48
              : _root.header.binding.binding_body == ecc_mode::secp521r1 ? 66
              : 0
          )
  ecc_key:
    seq:
      - id: key
        size: >
          1 + (
            _root.header.binding.binding_body == ecc_mode::secp256r1 ? 32
              : _root.header.binding.binding_body == ecc_mode::secp384r1 ? 48
              : _root.header.binding.binding_body == ecc_mode::secp521r1 ? 66
              : 0
          )
enums:
  url_protocol:
    0: http
    1: https
    0xFF: shared
  ecc_mode:
    0: secp256r1
    1: secp384r1
    2: secp521r1
    3: secp256k1
  cipher_mode:
    0: aes256gcm_64_bit
    1: aes256gcm_96_bit
    2: aes256gcm_104_bit
    3: aes256gcm_112_bit
    4: aes256gcm_120_bit
    5: aes256gcm_128_bit
