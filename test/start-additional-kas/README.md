# Start an additional KAS

Run this action after `test/start-up-with-containers`. It copies the platform's
development configuration into a separate configuration for the additional KAS.

## Private-key caching

Set `key-cache-expiration` to a Go duration such as `5m` to enable private-key
caching for that KAS. Set it to `0` to disable caching. The default is empty,
which preserves the value inherited from the platform configuration, including
leaving the setting absent when it is not configured.

For example, to enable caching on a KAS using the basic key manager:

```yaml
- uses: opentdf/platform/test/start-additional-kas@main
  with:
    kas-name: km3
    kas-port: 8787
    key-management: true
    root-key: ${{ steps.km-check.outputs.root_key }}
    key-cache-expiration: 5m
```

The input sets `services.kas.key_cache_expiration` in the generated KAS
configuration. It does not modify the source platform configuration or other
KAS instances. Invalid duration values are rejected when the KAS starts.
