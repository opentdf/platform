# WireMock for GRPC

A Docker container with [wiremock](https://wiremock.org/) + [wiremock grpc extension](https://wiremock.org/docs/grpc/)

WireMock requires service decriptions for the proto spec.  To generate service descriptions:

```shell
buf build ../../proto \
-o grpc/services.dsc
```

Service Mappings are located in [mapping](mappings)
Response Body Messages are located in [messages](messages)

Run mock server:
```shell
docker-compose up
```

# Examples:

Note, wiremock does not support server reflection. Therefore, the `-protoset` option is used to inform grpcurl of the api spec.

List Namespaces
```shell
grpcurl -plaintext -d '{}' -protoset grpc/services.dsc localhost:9000 namespaces.NamespaceService/ListNamespaces
```


List Attributes 
```shell
grpcurl -plaintext -d '{}' -protoset grpc/services.dsc localhost:9000 attributes.AttributesService/ListAttributes
```

Get Decision:

```shell
grpcurl -plaintext -d '{}' -protoset grpc/services.dsc localhost:9000 authorization.AuthorizationService/GetDecisions
```



