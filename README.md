# OpenTDF Enhancements POC

- [Configuration](./docs/configuration.md)
- [Development](#development)

## Development

### Prerequisites

[Air](https://github.com/cosmtrek/air)

With go 1.18 or higher:

`go install github.com/cosmtrek/air@v1.49.0`

[Buf](https://buf.build/docs/ecosystem/cli-overview)

`brew install buf`

### Run

1. `docker-compose -f opentdf-compose.yaml up`

2. `cp example-opentdf.yaml opentdf.yaml` and update the values

3. `air`

This should bring up a grpc server on port **9000** and http server on port **8080** (see [example-opentdf.yaml](https://github.com/opentdf/opentdf-v2-poc/blob/main/example-opentdf.yaml#L38-L43)). Air will watch for changes and restart the server.

### Test

> [!WARNING]
> GRPC and reflection is disabled by default. Please see the `opentdf.yaml` for more details (see [example-opentdf.yaml](https://github.com/opentdf/opentdf-v2-poc/blob/main/example-opentdf.yaml#L38-L43))

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
grpcurl -plaintext -d @ localhost:9000 attributes.v1.AttributesService/CreateAttribute <<EOM  
{
    "definition": {
        "name": "relto",
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
            "labels": [
                {
                    "key": "test2",
                    "value": "test2"
                },
                {
                    "key": "test3",
                    "value": "test3"
                }
            ],
            "description": "this is a test attribute",
            "namespace": "virtru.com",
            "name": "attribute1",
            "type":"POLICY_RESOURCE_TYPE_ATTRIBUTE_DEFINITION"
        }
    }
}

EOM
```

List Attributes

```bash
grpcurl -plaintext localhost:9000 attributes.v1.AttributesService/ListAttributes
```
