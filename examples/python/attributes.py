import grpc
from gen.attributes.v1 import attributes_pb2
from gen.common.v1 import common_pb2
from gen.attributes.v1 import attributes_pb2_grpc


# Create a new Attributes object
attr = attributes_pb2.AttributeDefinition(
  name="my_attribute",
  rule=attributes_pb2.AttributeDefinition.AttributeRuleType.ATTRIBUTE_RULE_TYPE_ANY_OF,
  values=[
    attributes_pb2.AttributeDefinitionValue(
      value="my_value",
      attribute_public_key="my_attribute_public_key"
    ),
    attributes_pb2.AttributeDefinitionValue(
      value="my_value2",
      attribute_public_key="my_attribute_public_key2"
    ),
  ],
  descriptor=common_pb2.ResourceDescriptor(
    version="1",
    namespace="demo.com",
    fqn="https://demo.com/attr/my_attribute",
    label="my_attribute",
    description="My Attribute",
  )
)
print(attr)

chan = grpc.insecure_channel("localhost:8082")
stub = attributes_pb2_grpc.AttributesServiceStub(chan)

try:
    stub.CreateAttribute(attributes_pb2.CreateAttributeRequest(
        definition=attr
    ))
    
    resp = stub.ListAttributes(attributes_pb2.ListAttributesRequest())
    print(resp) 
except grpc.RpcError as e:
    # This will print the gRPC error message
    print(f"gRPC call failed: {e.details()}")
    print(f"Status code: {e.code()}")