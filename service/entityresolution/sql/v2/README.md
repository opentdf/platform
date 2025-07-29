# SQL Entity Resolution Service v2

📋 **This documentation has been consolidated into the parent directory.**

👉 **See [`../README.md`](../README.md) for complete SQL ERS documentation covering both v1 and v2 protocols.**

## Quick Links

- **[Configuration Examples](../README.md#database-specific-configuration)** - PostgreSQL, MySQL, SQLite setup
- **[v2 Protocol Usage](../README.md#v2-protocol)** - EphemeralId, plural method names  
- **[Migration Guide](../README.md#from-v1-to-v2-protocol)** - Upgrading from v1 to v2
- **[Integration Testing](../README.md#integration-testing)** - Contract testing framework

## Key v2 Changes

- Uses `entity.Entity` instead of `authorization.Entity`
- Method: `CreateEntityChainsFromTokens` (plural)
- Field: `EphemeralId` instead of `Id`
- Import: `entityresolution/v2`