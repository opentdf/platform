---
title: Encrypt file or stdin as a TDF
command:
  name: encrypt [file]
  flags:
    - name: out
      shorthand: o
      description: The output file TDF in the current working directory instead of stdout ('-o file.txt' and '-o file.txt.tdf' both write the TDF as file.txt.tdf).
      default: ''
    - name: attr
      shorthand: a
      description: Attribute value Fully Qualified Names (FQNs, i.e. 'https://example.com/attr/attr1/value/value1') to apply to the encrypted data.
    - name: wrapping-key-algorithm
      description: >
        EXPERIMENTAL: The algorithm to use for the wrapping key 
      enum:
        - rsa:2048
        - ec:secp256r1
        - ec:secp384r1
        - ec:secp521r1
      default: rsa:2048  
    - name: mime-type
      description: The MIME type of the input data. If not provided, the MIME type is inferred from the input data.
    - name: tdf-type
      shorthand: t
      description: The type of TDF to encrypt as (tdf3 is an alias for ztdf).
      enum:
        - ztdf
        - tdf3
      default: ztdf
    - name: kas-url-path
      description: URL path to the KAS service at the platform endpoint domain. Leading slash is required if needed.
      default: /kas
    - name: target-mode
      description: The target TDF spec version (e.g., "4.3.0"); intended for legacy compatibility and subject to removal.
      default: ""
    - name: with-assertions
      description: >
        EXPERIMENTAL: JSON string or path to a JSON file of assertions to bind metadata to the TDF. See examples for more information. WARNING: Providing keys in a JSON string is strongly discouraged. If including sensitive keys, instead provide a path to a JSON file containing that information.
---

Build a Trusted Data Format (TDF) with encrypted content from a specified file or input from stdin utilizing OpenTDF platform.

## Examples

Various ways to encrypt a file

```shell
# output to stdout
otdfctl encrypt hello.txt

# output to hello.txt.tdf
otdfctl encrypt hello.txt --out hello.txt.tdf

# encrypt piped content and write to hello.txt.tdf
cat hello.txt | otdfctl encrypt --out hello.txt.tdf
```

Automatically append .tdf to the output file name

```shell
$ cat hello.txt | otdfctl encrypt --out hello.txt; ls
hello.txt  hello.txt.tdf

$ cat hello.txt | otdfctl encrypt --out hello.txt.tdf; ls
hello.txt  hello.txt.tdf
```

Advanced piping is supported

```shell
$ echo "hello world" | otdfctl encrypt | otdfctl decrypt | cat
hello world
```

## Wrapping Key Algorithm - EXPERIMENTAL

The wrapping-key-algorithm specifies the algorithm to use for the wrapping key. The available options are (default: rsa:2048):
- rsa:2048
- ec:secp256r1
- ec:secp384r1
- ec:secp521r1

Example
```shell
# Encrypt a file using the ec:secp256r1 algorithm for the wrapping key
# EXPERIMENTAL
otdfctl encrypt hello.txt --wrapping-key-algorithm ec:secp256r1 --out hello.txt.tdf
```

## Attributes

Attributes can be added to the encrypted data. The attribute value is a Fully Qualified Name (FQN) that is used to
restrict access to the data based on entity entitlements.

```shell
# output to hello.txt.tdf with attribute
otdfctl encrypt hello.txt --out hello.txt.tdf --attr https://example.com/attr/attr1/value/value1
```

## ZTDF Assertions (experimental)

Assertions are a way to bind metadata to the TDF data object in a cryptographically secure way. The data is signed with the provided signing key, or if none is provided, the payload key. The signing key algorithms supported are HS256 and RS256. 

### STANAG 5636

The following example demonstrates how to bind a STANAG 5636 metadata assertion, to the TDF data object.

```shell
otdfctl encrypt hello.txt --out hello.txt.tdf --with-assertions '[{"id":"assertion1","type":"handling","scope":"tdo","appliesToState":"encrypted","statement":{"format":"json+stanag5636","schema":"urn:nato:stanag:5636:A:1:elements:json","value":"{\"ocl\":\"2024-10-21T20:47:36Z\"}"}]'
```

We also support providing an assertions json file. 
You can optionally provide your own signing key. In this example, we provide an RS256 private key.
```json
[{"id":"assertion1","type":"handling","scope":"tdo","appliesToState":"encrypted","statement":{"format":"json+stanag5636","schema":"urn:nato:stanag:5636:A:1:elements:json","value":"{\"ocl\":\"2024-10-21T20:47:36Z\"}"},"signingKey":{"alg":"RS256","key":"-----BEGIN PRIVATE KEY-----\nMIIEugIBADANBgkqhkiG9w0BAQEFAASCBKQwggSgAgEAAoIBAQCavTBGx1c3Q702\nKW3GgbILpljAdt2I9XO86eb296fmDsWmbcc6bKB2LTbVZfU6VK5r45KtcY+MzbFt\njctOsUdBdAQhOOtpdBGnm+UoNsGc6u2NgNoprMFeBNhV16UTgAgC5BoahO50xqwc\nEaIs8RaJMvjJJ5zQ3MefazvZDiGfn8omkgk4aqPRKU1WK5903KWSOsndqmhgW/Uy\nHCLcQX+IVlDl6dwMMmZwb9RgXeaxu4dHMCsklDvfcE1G+JxYX+eqLErGmu+bxOzx\nrni2vw1ntwS7W7kboBj+lkUaTiaXyre/mjWNrvHDZ2CkmVLxOXzy1TOz7sYbwhvy\nfuYep49NAgMBAAECgf8N2RrYrTRyIZmlzMJZgpc4gCujIqSPjJfEn3D5XC5+w9XA\nu/lfONZbn/9Y6/CeTgRcpYRNKO9QI0pb3RQzgiLBO+/Z1UJjtORxR0gXdJ0XXVTz\ntLWsD4dCycpkyT8snLkMQFdzXXRAefNyYdavOVz0kvCNgGgw606rZhkYbtHUCM3X\nb1LZFcIAYrpftKUXxn+xOcSjIKdqKoUlBW6Yk7iTjJuy/Su63gTJ5PbgKpNvK7Xu\nyzu4L7t2pswE5pWxb7uMMpTujqLNYiaXDlzpy/fPN8EjL1mhKzia365+EJ3uKH8c\nQ9dz/1g36lSQnD/lus0cES9xXzQ6+1izc17dTsECgYEA1XGM4PVxCt4TaApDoT7X\npeLDG9pQW55DQQiix4A/0EmQgxf6WN0uZ4b8lds02JhNBGVUIe2nyTNknV+9styu\nJsKJhq+KjrcHmE8uy18++G2cZuOM2S49p8y0HPA8YBcRBC4fAoKFFG3cmrIJW5Vu\nMzzaN+W3/1h/xdkUTpI1lYkCgYEAuZdHWrMNt96WMUuaSwu2tg3BHaYhSeyIcbwi\nm2mIOeLQ6gGtGqyALC6N/K8Ie8KwkisTI9GqcX8O9FrkZx4RvkQrONUaS4aXEJ28\nEZzwJenybkSuWunypVLMmp/pN7+mZZ7GUaDbXTF6pg4GOrlp6MIUk4plJYGXXumg\nqaXvPqUCgYA0pmvf2etmiN00nsOL9Npw+vyx1CpaTzG7ywuMNqCHGn5hN/rzDKwz\nsWKA/K+OdhMZcH1OWTc4NEsvXryGcFUtDnOqG4cMKS3gbjfWxsnbsf4QizTlJbjj\nuWT8dm4OLeJuq4nOrq9xGKCAMEaKptOmI+6YNzwp6oSqIyAVOY+qMQKBgDM7IlRU\nNwY5qIYlE4uByUcKFvQDRw8r/yI+R+NUx2kLRpZCLjG9yofntgQ5oQLg5HME9vyd\nRQqdg1hKuuAIOeem07OVh/OvTIYmtKK8CsK8iNKNnP+1suiWKarJV8yu19UXdjFU\nURmxreSm3GtbgXPiF2H/AxrOYiWuIk6SYq+NAoGAZy96GLP3HfA41UWFZH6b8ZdP\nM6CXKDDvHOk06S/hwmhvq3UO5lQULZ+pd+aURv/TDF9DXhZIyl1CXqyOYB5IqJjk\nAFI8A9n/naq7GyIZZRjzJu2blhSjW3ukkS/5CO4zJ6HfauSUjQA4u+5RStjeK3zd\nF267fElUPN4+pSOAhPI=\n-----END PRIVATE KEY-----\n"}}]
```
```shell
otdfctl encrypt hello.txt --out hello.txt.tdf --with-assertions my_assertions_signed_rs256.json
```
Signing with HS256 is also available.
```json
[{"id":"assertion1","type":"handling","scope":"tdo","appliesToState":"encrypted","statement":{"format":"json+stanag5636","schema":"urn:nato:stanag:5636:A:1:elements:json","value":"{\"ocl\":\"2024-10-21T20:47:36Z\"}"},"signingKey":{"alg":"HS256","key":"k0cn4xBcY+49z5gs4OHUs/kbQ3/T8p+uUW9pIQ/9aqE="}}]
```
```shell
otdfctl encrypt hello.txt --out hello.txt.tdf --with-assertions my_assertions_signed_hs256.json
```

## Target Mode

To encrypt with a target tdf spec version, use the `--target-mode` flag. A version < 4.3.0 will include hex encoded signature hashes and will not include a schema version in the manifest.

```shell
otdfctl encrypt hello.txt --out hello.txt.tdf --target-mode 4.3.0
```
