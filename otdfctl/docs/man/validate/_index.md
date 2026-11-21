---
title: Validate a TDF file
command:
  name: validate
  arguments:
    - file
---

Checks whether the specified file is a well-formed TDF, using the Go SDK's `IsValidTdf`: the file must be a ZIP archive containing a manifest that conforms to the TDF manifest schema. The payload is not decrypted and its integrity is not verified.

Validation is offline. It does not contact the platform or a KAS, so it needs no profile, host, or credentials.

## Output

When the check completes, a single line of JSON is written to standard output:

```json
{"valid":true}
```

```json
{"valid":false,"reason":"<why the file is not a valid TDF>"}
```

## Exit codes

- `0`: the file is a valid TDF.
- `3`: the check completed and the file is not a valid TDF. The reason is in the JSON output.
- Any other nonzero code: the check could not run, for example because the file is missing or unreadable, or the command was used incorrectly. Nothing is written to standard output; the error is written to standard error.

## Examples

```shell
$ otdfctl validate example.tdf
{"valid":true}

$ otdfctl validate notes.txt
{"valid":false,"reason":"zipstream.NewTDFReader failed: zip: not a valid zip file"}
$ echo $?
3
```
