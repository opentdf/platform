---
title: Unsafe changes to attribute values
command:
  name: unsafe
  flags:
    - name: force
      description: Force unsafe change without confirmation
      required: false
---

Unsafe changes are dangerous mutations to Policy that can significantly change access behavior around existing attributes
and entitlement.

Depending on the unsafe change introduced and already existing TDFs, TDFs might become inaccessible that were previously
accessible or vice versa.

Make sure you know what you are doing.

For more information on attribute values, see the `values` subcommand.
