---
status: 'proposed'
date: '2025-10-07'
tags:
 - authorization
driver: '@jakedoublev'
consulted:
  - '@biscoe916'
  - '@c-r33d'
---

When working on surfacing obligations required upon a TDF within our SDKs, the desire was to provide each SDK
with an `Obligations()` method on the TDF readers.

The required obligations on the TDF would have either already come back from a `Rewrap` response or be retrieved
from a direct `GetDecision` call to Auth Service that would surface obligations if the user was entitled (whether
or not they were fulfilled). This would be valuable for flows like stream decryptions where the first byte handled
should have an obligation applied on it before the entire decryption occurred. Making the auth service call would
decouple decryption from surfacing obligations, which has value for multiple reasons.

Ultimately it was determined to be non-viable for now because a Rewrap flow might go to multiple federated KASes,
each provided in the TDF KAO list, and each KAS separately decisioning differently upon the TDF data attributes,
therefore each returning their own obligations.

Our SDKs currently only connect to one platform, and only one Auth Service as a result, but during TDF decryption
might talk to _n_ KASes each of a different platform. We would need all of the Auth Services involved to decision
upon their own policy in order to successfully surface Obligations without Rewraps today.

Some considered options (for a future time) to solve this problem might be:

- a Rewrap flow where KASes can talk/decision over disparate policy without providing a key back (this feels awkward if
a KAS exists to safeguard key material, but a parallel exists in the ACM getContract vs policy metadata endpoints)
- some kind of flag in the rewrap request that indicates no key is needed, which is propagated into audit logs
and/or changes the rewrap response behavior’s key material
- some kind of authz/platform brokering
- allowing the PEP to call the sdk Obligations() method with given namespaces it cares about, or associate policy
namespaces with various platforms
- allowing a PEP to strip off namespaces it doesn’t care about, then make the Obligations call with only those it wants to respect
