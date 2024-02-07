# OpenTDF Enhancements POC

- [Configuration](./docs/configuration.md)
- [Development](#development)
- [Policy Config Schema](./migrations/20240131000000_diagram.md)
- [Policy Config Testing Diagram](./integration/testing_diagram.png)

## Development

### Prerequisites

[Air](https://github.com/cosmtrek/air)

With go 1.18 or higher:

`go install github.com/cosmtrek/air@v1.49.0`

[Buf](https://buf.build/docs/ecosystem/cli-overview)

`brew install buf`

[grpcurl](https://github.com/fullstorydev/grpcurl)

`brew install grpcurl`

### Run

1. `docker-compose -f opentdf-compose.yaml up`

2. `cp example-opentdf.yaml opentdf.yaml` and update the values

3. `air`

This should bring up a grpc server on port **9000** and http server on port **8080** (see [example-opentdf.yaml](https://github.com/opentdf/opentdf-v2-poc/blob/main/example-opentdf.yaml#L38-L43)). Air will watch for changes and restart the server.

### Test

```bash
  grpcurl -plaintext localhost:9000 list

  attributes.AttributesService
  grpc.reflection.v1.ServerReflection
  grpc.reflection.v1alpha.ServerReflection
  kasregistry.KeyAccessServerRegistryService
  namespaces.NamespaceService
  resourcemapping.ResourceMappingService
  subjectmapping.SubjectMappingService

  grpcurl -plaintext localhost:9000 list attributes.AttributesService

  attributes.AttributesService.CreateAttribute
  attributes.AttributesService.CreateAttributeValue
  attributes.AttributesService.DeleteAttribute
  attributes.AttributesService.DeleteAttributeValue
  attributes.AttributesService.GetAttribute
  attributes.AttributesService.GetAttributeValue
  attributes.AttributesService.ListAttributeValues
  attributes.AttributesService.ListAttributes
  attributes.AttributesService.UpdateAttribute
  attributes.AttributesService.UpdateAttributeValue
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

### Generation

Our native gRPC service functions are generated from `proto` definitions using [Buf](https://buf.build/docs/introduction).

The `Makefile` provides command scripts to invoke `Buf` with the `buf.gen.yaml` config, including OpenAPI docs, grpc docs, and the
generated code.

For convenience, the `make pre-build` script checks if you have the necessary dependencies for `proto -> gRPC` generation.

