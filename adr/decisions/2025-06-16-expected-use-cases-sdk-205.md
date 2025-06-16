---
# Required
status: 'accepted'
date: '2025-06-16'
tags:
 - sdk:v2.0.5
 - key management
# Optional
driver: '@strantalis @jrschumacher @c-r33d @damorris25'
deciders: '@strantalis @jrschumacher @c-r33d @damorris25'
consulted: '@strantalis @jrschumacher @c-r33d @damorris25'
informed: '@strantalis @jrschumacher @c-r33d @damorris25'
---
# SDK backwards/forward compatibility v2.0.5

## Decision Outcome

1. v2.0.5 of SDK should work with < v2.0.4 of platform
2. < v2.0.5 of SDK should work with >= v2.0.5 of plaform
3. We should not have a WithBaseKeyEnabled option, instead the platform version should be derived from the well-known. For v2.0.5 of the SDK we will prefer to use the base key if present and set properly. If it is not, we will fallback to using the default kases. In v2.0.6 the plan would be to error if the platform is >= v2.0.5 and the base key is not set.
4. When creating a split plan if the SDK notices that there are key mappings it will **only** use those key mappings instead of grants. If no key mappings are present, the sdk will fallback to grants.

<!-- This is an optional element. Feel free to remove. -->
### Consequences

- 🟩 **Good**, maintains backwards/forward compatibility
- 🟩 **Good**, allows us to not add another TDFOption
- 🟨 **Neutral**: Wellknown needs to be updated with platform version information.
- 🟨 **Neutral**: After an admin creates their first key mapping the SDK will ignore previously created grants.

<!-- This is an optional element. Feel free to remove. -->
## Validation

- **Unit Tests:** SDK conditions for no base key functionality based on platform version
- **Integration Tests:** Mix of tests using new and old platform/sdk. *Should be covered in existing XTests*
- **Manual Testing:** Deploy different versions of the SDK/Platform.
- **Documentation:** Update SDK and platform documentation to reflect the new configuration option and its usage.
