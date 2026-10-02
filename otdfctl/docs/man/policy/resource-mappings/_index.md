---
title: Manage resource mappings
command:
  name: resource-mappings
  aliases:
    - resm
    - remap
    - resource-mapping
---

Resource mappings are used to map resources to their respective attribute values based on the terms
that are related to the data. Alone, this service is not very useful, but when combined with a PEP
or PDP that can use the resource mappings it becomes a powerful tool for automating access control.

As an example, Tagging PDP uses resource mappings to map resources based on the terms found within
the metadata and documents which are sent to it. Combined with the resource mappings it can then
determine which attributes should be applied to the TDF and return those attributes to the PEP.
