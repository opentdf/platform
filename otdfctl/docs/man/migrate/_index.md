---
title: Migrate resources

command:
  name: migrate
  aliases:
    - migration
  description: Run migration workflows for platform resources
  flags:
    - name: commit
      shorthand: c
      description: Writes changes to policy storage
      default: false
    - name: interactive
      shorthand: i
      description: Interactive walk through of migrations
      default: false
---

`migrate` groups commands used to move existing platform data or configuration from
an older model to a newer model. Migration commands can be used to preview planned
changes, apply compatible updates, and clean up data that is no longer needed after
a migration.

The parent `migrate` command owns shared flags used by migration subcommands that
support applying changes or interactive review.
