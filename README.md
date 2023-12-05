# opentdf-v2-poc
OpenTDF V2 POC

## Development

### Prerequisites

`brew install air`
`brew install buf`
`brew install ariga/tap/atlas`

### Run

`docker-compose -f opentdf-compose.yaml up`
`export DB_URL=postgres://postgres:changeme@localhost:5432/opentdf?sslmode=disable`
`air`

This should bring up a grpc server on port 8082 and http server on port 8081

### Test

```bash
  grpcurl -plaintext localhost:8082 list

  acre.v1.ResourcEncodingService
  attributes.v1.AttributesService
  grpc.reflection.v1.ServerReflection
  grpc.reflection.v1alpha.ServerReflection

  grpcurl -plaintext localhost:8082 list attributes.v1.AttributesService

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
