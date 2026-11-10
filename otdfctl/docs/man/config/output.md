---
title: Define the configured output format

command:
  name: output
  flags:
    - name: format
      description: "'json' or 'styled' as the configured output format"
      default: "styled"
      required: false
---

Define the configured output format for the 'otdfctl' command line tool. The only supported outputs at
this time are 'json' and styled CLI output, which is the default when unspecified.
