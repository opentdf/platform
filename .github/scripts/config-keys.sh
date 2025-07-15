#!/usr/bin/env bash

# Adds $EXTRA_KEYS json object keys to the opentdf.yaml and filesystem

set -e

allowed_algorithms=(ec:secp256r1 rsa:2048)

if echo "$PLATFORM_VERSION" | awk -F. '{ if ($1 > 0 || ($1 == 0 && $2 > 7) || ($1 == 0 && $2 == 7 && $3 >= 1)) exit 0; else exit 1; }'; then
  # For versions 0.7.1 and later, we allow rsa:4096 ec:secp384r1 ec:secp521r1
  allowed_algorithms+=(rsa:4096 ec:secp384r1 ec:secp521r1 mlkem:768)
fi

keys=()

while IFS= read -r -d $'\0' key_json <&3; do
  printf 'processing %s\n' "${key_json}"
  alg="$(jq -r '.alg' <<<"${key_json}")"

  if ! printf '%s\n' "${allowed_algorithms[@]}" | grep -q -w -F -- "${alg}"; then
    printf 'algorithm [%s] is not allowed. Skipping extra key [%s]\n' "${alg}" "${kid}" 1>&2
    continue
  fi

  private_pem="$(jq -r '.privateKey' <<<"${key_json}")"
  cert_pem="$(jq -r '.cert' <<<"${key_json}")"
  kid="$(jq -r '.kid' <<<"${key_json}")"

  # don't allow injection of paths. the regex can't be quoted in bash
  if [[ ! ${kid} =~ ^[-0-9a-zA-Z_]+$ ]]; then
    printf 'kid is not valid: [%s]\n' "${kid}" 1>&2
    exit 1
  fi

  private_path="${kid}.pem"
  echo "${private_pem}" >"${private_path}"

  if [[ -n ${cert_pem} ]]; then
    cert_path="${kid}-cert.pem"
    echo "${cert_pem}" >"${cert_path}"
    chmod a+r "${private_path}" "${cert_path}"
    key_obj="$(jq -n --arg kid "${kid}" --arg alg "${alg}" --arg private "${private_path}" --arg cert "${cert_path}" '{kid: $kid, alg: $alg, private: $private, cert: $cert}')" \
      yq -i '.server.cryptoProvider.standard.keys += [strenv(key_obj)]' opentdf.yaml
  else
    cert_path=""
    chmod a+r "${private_path}"
    key_obj="$(jq -n --arg kid "${kid}" --arg alg "${alg}" --arg private "${private_path}" '{kid: $kid, alg: $alg, private: $private}')" \
      yq -i '.server.cryptoProvider.standard.keys += [strenv(key_obj)]' opentdf.yaml
  fi

  keyring_obj="$(jq -n --arg kid "${kid}" --arg alg "${alg}" '{kid: $kid, alg: $alg}')" \
    yq -i '.services.kas.keyring += [strenv(keyring_obj)]' opentdf.yaml

  keys+=("${kid}")

done 3< <(jq -c --raw-output0 '.[]' <<<"${EXTRA_KEYS}")

printf 'added the following keys: [%s]\n' "${keys[@]}" 1>&2
