---
title: Manage Actions
command:
  name: actions
  aliases:
    - action
---

Actions are a set of `standard` and `custom` verbs at the core of an Access Decision or an
Obligation. In the context of an entitlement decision, adding Actions to Subject Mappings answers
"what can an Entity _do_ to a Resource?"

Standard Actions in Policy are comprised of the below, and only their metadata labels are mutable:
- create
- read (considered within all TDF `decrypt` flows)
- update
- delete

Custom Actions known to Policy are admin-defined, globally unique (not namespaced), and will be lower
cased when stored. They may contain underscores (`_`) or hyphens (`-`) if preceded or followed
by an alphanumeric character. For example:
- download
- queue-to-print
- send_email

For more information about entitlement and Subject Mappings, see the `subject-mappings` command.