---
title: Manage attribute namespaces
command:
  name: namespaces
  aliases:
    - ns
    - namespace
---

A namespace is the root (parent) of a set of platform policy. Like an owner or an authority, it fully qualifies attributes and their values,
resource mapping groups, etc. As the various mappings of a platform are to attributes or values, a namespace effectively "owns" the
mappings as well (transitively if not directly).

In an attribute or other FQN (Fully Qualified Name), the namespace is found after the scheme: `https://<namespace>`

Namespaces, like other FQN'd objects, are normalized to lower case both on create and in a decision request lookup.

As the Namespace is the parent of policy, a namespace's existence is required to create attributes or resource mapping groups beneath.
