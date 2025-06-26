---
# Required
status: 'proposed'
date: '{YYYY-MM-DD when the decision was last updated}'
tags:
 - key-management
# Optional
driver: '@c-r33d @strantalis @jrschumacher'
deciders: '@strantalis @jrschumacher @dmihalcik-virtru @damorris25'
consulted: '{list everyone whose opinions are sought (typically subject-matter experts); and with whom there is a two-way communication}'
informed: '{list everyone who is kept up-to-date on progress; and with whom there is a one-way communication}'
---
# Implementing Key Deletion in the OpenTDF Platform

## Context and Problem Statement

As an on-premise software solution, the OpenTDF Platform must empower administrators with comprehensive control over their data, including the sensitive capability to delete encryption keys. We acknowledge the profound risk: key deletion is irreversible, permanently rendering all data encrypted with that key irretrievable. Despite this, denying administrators this crucial functionality presents a greater risk. It would inevitably force them to resort to direct database manipulation, bypassing our system's controls and leading to a complete loss of audit trails—a critical component for security and compliance—and potential database corruption. Therefore, a controlled and auditable method for key deletion is essential.

<!-- This is an optional element. Feel free to remove. -->
## Decision Drivers

* Administrator Autonomy: Our on-premise model necessitates that customers have ultimate control over their data lifecycle, including deletion. We cannot be a roadblock to their operational needs.
* Auditability & Compliance: Providing an in-system mechanism for key deletion ensures that all actions are properly logged and auditable, maintaining data integrity and supporting compliance requirements.
* Risk Mitigation (Unsanctioned Actions): By offering a supported path, we prevent administrators from taking unmonitored and potentially damaging actions directly on the database.
* Data Irreversibility Acknowledgment: The solution must explicitly highlight and mitigate the inherent risk of permanent data loss associated with key deletion.

## Considered Options

### Option 1: Add Unsafe Delete with no guard rails

As the title suggests, we simply add a method for deleting keys. Only admins will be allowed to hit the endpoint. We will provide no guard rails for deleting keys.

* 🟩 **Good**, Provides a way for admins to delete keys.
* 🟩 **Good**, Using unsafe terminology denotes that this is potentially a harmful operation
* 🟩 **Good**, Most simple solution
* 🟥 **Bad**, No way of recovering your private key if not backed up before deletion.

### Option 2: Environment Variable Gate

We can introduce an environment variable, such as OPENTDF_ENABLE_KEY_DELETION, that acts as a gate. When this variable is set to true and the OpenTDF Platform is restarted, the key deletion functionality would become accessible. This approach ensures that key deletion is not enabled by default and requires a deliberate, conscious action from an administrator.

* 🟩 **Good**, Explicit Opt-In: Demands a clear and intentional administrative decision to enable a high-risk operation.
* 🟩 **Good**, Reduced Accidental Deletion: The required platform restart provides a natural "cooling-off" period, reducing the likelihood of impulsive or accidental deletions.
* 🟩 **Good**, Simple Implementation: Relatively straightforward to implement in our existing configuration management.
* 🟨 **Neutral**, Operational Friction: The necessity of a platform restart might be inconvenient for some customers, particularly in high-availability environments.
* 🟨 **Neutral**, Another environment variable to be added to the platform.
* 🟥 **Bad**, No way of recovering your private key if not backed up before deletion.

### Option 3: HashiCorp-Inspired Soft Delete (Versioned KV Store)

Drawing inspiration from HashiCorp's KV secrets engine, we could implement a "soft delete" mechanism if our key storage backend supports versioning. Instead of physically removing the key data, the delete command would mark the key as deleted and prevent it from being returned in standard get requests. The historical record of the key, including its deletion status, would be retained.

* 🟩 **Good**, Enhanced Auditability: Retains a historical record of all keys, even those "deleted," which can be invaluable for forensic analysis and compliance.
* 🟩 **Good**, Reversible (in theory): While the data remains inaccessible, the underlying key might technically be "undeleted" in an emergency (though this would be a complex and highly risky operation itself).
* 🟨 **Neutral**, Implementation Complexity: Requires a robust, versioned key-value storage backend, which might necessitate significant architectural changes if not already in place.
* 🟨 **Neutral**, Misleading "Deletion": While marked as deleted, the key data still exists, which might not align with an administrator's expectation of true "deletion" for sensitive information.
* 🟨 **Neutral**, Storage Overhead: Retaining deleted key versions increases storage requirements.
* 🟥 **Bad**, Unclear behavior when a key access server is to be deleted and all keys are marked as *deleted*. Should we allow the keys to be deleted? Should we block the deletion of the key access server?

### Option 4: Add exported column / export RPC method

Add a column to the keys table to denote whether or not the key has been exported. If it has, then we allow the unsafe deletion. If the key has not been exported we return a meaningful error instructing the user to call the export rpc.

* 🟩 **Good**, Easy to implement
* 🟩 **Good**, Provides a way for the platform to tell if the admin has intentionally backed up the key
* 🟩 **Good**, Allows admins a safe, auditable way for deleting keys
* 🟨 **Neutral**, Cannot guarantee that the admin has kept the key after calling the export key method.
* 🟥 **Bad**, No way of recovering your private key if not backed up before deletion.

## Decision Outcome

Chosen option: "{title of option 1}", because
{justification. e.g., only option, which meets k.o. criterion decision driver | which resolves force {force} | … | comes out best (see below)}.

## Consequences

* If key deletion is implemented (via either option):
  * We empower administrators with essential control, aligning with the expectations of on-premise software.
  * All key deletion events will be rigorously audited and logged, preserving the integrity of our audit trails.
  * We must implement prominent and clear warnings in the UI and CLI, explicitly stating the irreversible nature of the operation and the resulting data loss.
  * Support staff will need training on handling inquiries related to lost data due to key deletion.

* If key deletion is NOT implemented:
  * Administrators will be hamstrung in managing their data and will almost certainly bypass our system.
  * We will lose critical auditability for key management actions, creating significant compliance and security vulnerabilities.
  * There will be an increased risk of database corruption due to unmonitored manual interventions.
  * Customer frustration and dissatisfaction will likely increase.
