---
title: Migrate resources

command:
  name: migrate
  aliases:
    - migration
  description: Top-level command for migrating different resources
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

Top-level command for migrating different resources.
