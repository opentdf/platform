# opentdf-v2-poc
OpenTDF V2 POC

- [Configuration](./docs/configuration.md)
- [Development](#development)

## Development

### Prerequisites

`brew install air`

`brew install buf`

### Run

1. `docker-compose -f opentdf-compose.yaml up`

2. `cp example-opentdf.yaml opentdf.yaml`

3. `air`

This should bring up a grpc server on port 9000 and http server on port 8080. Air will watch for changes and restart the server.

### Test

```bash
  grpcurl -plaintext localhost:9000 list

  acre.v1.ResourcEncodingService
  attributes.v1.AttributesService
  grpc.reflection.v1.ServerReflection
  grpc.reflection.v1alpha.ServerReflection

  grpcurl -plaintext localhost:9000 list attributes.v1.AttributesService

  attributes.v1.AttributesService.CreateAttribute
  attributes.v1.AttributesService.DeleteAttribute
  attributes.v1.AttributesService.GetAttribute
  attributes.v1.AttributesService.ListAttributes
  attributes.v1.AttributesService.UpdateAttribute

```

Create Attribute

```bash
grpcurl -plaintext -d @ localhost:8082 attributes.v1.AttributesService/CreateAttribute <<EOM  
{
    "definition": {
        "name": "test",
        "rule":"ATTRIBUTE_RULE_TYPE_ANY_OF",
        "values": [
            {
                "value": "test1"
            },
            {
                "value": "test2"
            }
        ],
        "descriptor": {
            "version": "1",
            "label": "test",
            "description": "this is a test attribute",
            "namespace": "virtru.com"
        }
    }
}
EOM
```

List Attributes

```bash
grpcurl -plaintext -d @ localhost:8082 attributes.v1.AttributesService/ListAttributes
```
