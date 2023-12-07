"""Client and server classes corresponding to protobuf-defined services."""
import grpc
from ...attributes.v1 import attributes_pb2 as attributes_dot_v1_dot_attributes__pb2

class AttributesServiceStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.GetAttribute = channel.unary_unary('/attributes.v1.AttributesService/GetAttribute', request_serializer=attributes_dot_v1_dot_attributes__pb2.GetAttributeRequest.SerializeToString, response_deserializer=attributes_dot_v1_dot_attributes__pb2.GetAttributeResponse.FromString)
        self.GetAttributeGroup = channel.unary_unary('/attributes.v1.AttributesService/GetAttributeGroup', request_serializer=attributes_dot_v1_dot_attributes__pb2.GetAttributeGroupRequest.SerializeToString, response_deserializer=attributes_dot_v1_dot_attributes__pb2.GetAttributeGroupResponse.FromString)
        self.ListAttributes = channel.unary_unary('/attributes.v1.AttributesService/ListAttributes', request_serializer=attributes_dot_v1_dot_attributes__pb2.ListAttributesRequest.SerializeToString, response_deserializer=attributes_dot_v1_dot_attributes__pb2.ListAttributesResponse.FromString)
        self.ListAttributeGroups = channel.unary_unary('/attributes.v1.AttributesService/ListAttributeGroups', request_serializer=attributes_dot_v1_dot_attributes__pb2.ListAttributeGroupsRequest.SerializeToString, response_deserializer=attributes_dot_v1_dot_attributes__pb2.ListAttributeGroupsResponse.FromString)
        self.CreateAttribute = channel.unary_unary('/attributes.v1.AttributesService/CreateAttribute', request_serializer=attributes_dot_v1_dot_attributes__pb2.CreateAttributeRequest.SerializeToString, response_deserializer=attributes_dot_v1_dot_attributes__pb2.CreateAttributeResponse.FromString)
        self.CreateAttributeGroup = channel.unary_unary('/attributes.v1.AttributesService/CreateAttributeGroup', request_serializer=attributes_dot_v1_dot_attributes__pb2.CreateAttributeGroupRequest.SerializeToString, response_deserializer=attributes_dot_v1_dot_attributes__pb2.CreateAttributeGroupResponse.FromString)
        self.UpdateAttribute = channel.unary_unary('/attributes.v1.AttributesService/UpdateAttribute', request_serializer=attributes_dot_v1_dot_attributes__pb2.UpdateAttributeRequest.SerializeToString, response_deserializer=attributes_dot_v1_dot_attributes__pb2.UpdateAttributeResponse.FromString)
        self.UpdateAttributeGroup = channel.unary_unary('/attributes.v1.AttributesService/UpdateAttributeGroup', request_serializer=attributes_dot_v1_dot_attributes__pb2.UpdateAttributeGroupRequest.SerializeToString, response_deserializer=attributes_dot_v1_dot_attributes__pb2.UpdateAttributeGroupResponse.FromString)
        self.DeleteAttribute = channel.unary_unary('/attributes.v1.AttributesService/DeleteAttribute', request_serializer=attributes_dot_v1_dot_attributes__pb2.DeleteAttributeRequest.SerializeToString, response_deserializer=attributes_dot_v1_dot_attributes__pb2.DeleteAttributeResponse.FromString)
        self.DeleteAttributeGroup = channel.unary_unary('/attributes.v1.AttributesService/DeleteAttributeGroup', request_serializer=attributes_dot_v1_dot_attributes__pb2.DeleteAttributeGroupRequest.SerializeToString, response_deserializer=attributes_dot_v1_dot_attributes__pb2.DeleteAttributeGroupResponse.FromString)

class AttributesServiceServicer(object):
    """Missing associated documentation comment in .proto file."""

    def GetAttribute(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetAttributeGroup(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def ListAttributes(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def ListAttributeGroups(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def CreateAttribute(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def CreateAttributeGroup(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def UpdateAttribute(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def UpdateAttributeGroup(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def DeleteAttribute(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def DeleteAttributeGroup(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

def add_AttributesServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {'GetAttribute': grpc.unary_unary_rpc_method_handler(servicer.GetAttribute, request_deserializer=attributes_dot_v1_dot_attributes__pb2.GetAttributeRequest.FromString, response_serializer=attributes_dot_v1_dot_attributes__pb2.GetAttributeResponse.SerializeToString), 'GetAttributeGroup': grpc.unary_unary_rpc_method_handler(servicer.GetAttributeGroup, request_deserializer=attributes_dot_v1_dot_attributes__pb2.GetAttributeGroupRequest.FromString, response_serializer=attributes_dot_v1_dot_attributes__pb2.GetAttributeGroupResponse.SerializeToString), 'ListAttributes': grpc.unary_unary_rpc_method_handler(servicer.ListAttributes, request_deserializer=attributes_dot_v1_dot_attributes__pb2.ListAttributesRequest.FromString, response_serializer=attributes_dot_v1_dot_attributes__pb2.ListAttributesResponse.SerializeToString), 'ListAttributeGroups': grpc.unary_unary_rpc_method_handler(servicer.ListAttributeGroups, request_deserializer=attributes_dot_v1_dot_attributes__pb2.ListAttributeGroupsRequest.FromString, response_serializer=attributes_dot_v1_dot_attributes__pb2.ListAttributeGroupsResponse.SerializeToString), 'CreateAttribute': grpc.unary_unary_rpc_method_handler(servicer.CreateAttribute, request_deserializer=attributes_dot_v1_dot_attributes__pb2.CreateAttributeRequest.FromString, response_serializer=attributes_dot_v1_dot_attributes__pb2.CreateAttributeResponse.SerializeToString), 'CreateAttributeGroup': grpc.unary_unary_rpc_method_handler(servicer.CreateAttributeGroup, request_deserializer=attributes_dot_v1_dot_attributes__pb2.CreateAttributeGroupRequest.FromString, response_serializer=attributes_dot_v1_dot_attributes__pb2.CreateAttributeGroupResponse.SerializeToString), 'UpdateAttribute': grpc.unary_unary_rpc_method_handler(servicer.UpdateAttribute, request_deserializer=attributes_dot_v1_dot_attributes__pb2.UpdateAttributeRequest.FromString, response_serializer=attributes_dot_v1_dot_attributes__pb2.UpdateAttributeResponse.SerializeToString), 'UpdateAttributeGroup': grpc.unary_unary_rpc_method_handler(servicer.UpdateAttributeGroup, request_deserializer=attributes_dot_v1_dot_attributes__pb2.UpdateAttributeGroupRequest.FromString, response_serializer=attributes_dot_v1_dot_attributes__pb2.UpdateAttributeGroupResponse.SerializeToString), 'DeleteAttribute': grpc.unary_unary_rpc_method_handler(servicer.DeleteAttribute, request_deserializer=attributes_dot_v1_dot_attributes__pb2.DeleteAttributeRequest.FromString, response_serializer=attributes_dot_v1_dot_attributes__pb2.DeleteAttributeResponse.SerializeToString), 'DeleteAttributeGroup': grpc.unary_unary_rpc_method_handler(servicer.DeleteAttributeGroup, request_deserializer=attributes_dot_v1_dot_attributes__pb2.DeleteAttributeGroupRequest.FromString, response_serializer=attributes_dot_v1_dot_attributes__pb2.DeleteAttributeGroupResponse.SerializeToString)}
    generic_handler = grpc.method_handlers_generic_handler('attributes.v1.AttributesService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))

class AttributesService(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def GetAttribute(request, target, options=(), channel_credentials=None, call_credentials=None, insecure=False, compression=None, wait_for_ready=None, timeout=None, metadata=None):
        return grpc.experimental.unary_unary(request, target, '/attributes.v1.AttributesService/GetAttribute', attributes_dot_v1_dot_attributes__pb2.GetAttributeRequest.SerializeToString, attributes_dot_v1_dot_attributes__pb2.GetAttributeResponse.FromString, options, channel_credentials, insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def GetAttributeGroup(request, target, options=(), channel_credentials=None, call_credentials=None, insecure=False, compression=None, wait_for_ready=None, timeout=None, metadata=None):
        return grpc.experimental.unary_unary(request, target, '/attributes.v1.AttributesService/GetAttributeGroup', attributes_dot_v1_dot_attributes__pb2.GetAttributeGroupRequest.SerializeToString, attributes_dot_v1_dot_attributes__pb2.GetAttributeGroupResponse.FromString, options, channel_credentials, insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def ListAttributes(request, target, options=(), channel_credentials=None, call_credentials=None, insecure=False, compression=None, wait_for_ready=None, timeout=None, metadata=None):
        return grpc.experimental.unary_unary(request, target, '/attributes.v1.AttributesService/ListAttributes', attributes_dot_v1_dot_attributes__pb2.ListAttributesRequest.SerializeToString, attributes_dot_v1_dot_attributes__pb2.ListAttributesResponse.FromString, options, channel_credentials, insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def ListAttributeGroups(request, target, options=(), channel_credentials=None, call_credentials=None, insecure=False, compression=None, wait_for_ready=None, timeout=None, metadata=None):
        return grpc.experimental.unary_unary(request, target, '/attributes.v1.AttributesService/ListAttributeGroups', attributes_dot_v1_dot_attributes__pb2.ListAttributeGroupsRequest.SerializeToString, attributes_dot_v1_dot_attributes__pb2.ListAttributeGroupsResponse.FromString, options, channel_credentials, insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def CreateAttribute(request, target, options=(), channel_credentials=None, call_credentials=None, insecure=False, compression=None, wait_for_ready=None, timeout=None, metadata=None):
        return grpc.experimental.unary_unary(request, target, '/attributes.v1.AttributesService/CreateAttribute', attributes_dot_v1_dot_attributes__pb2.CreateAttributeRequest.SerializeToString, attributes_dot_v1_dot_attributes__pb2.CreateAttributeResponse.FromString, options, channel_credentials, insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def CreateAttributeGroup(request, target, options=(), channel_credentials=None, call_credentials=None, insecure=False, compression=None, wait_for_ready=None, timeout=None, metadata=None):
        return grpc.experimental.unary_unary(request, target, '/attributes.v1.AttributesService/CreateAttributeGroup', attributes_dot_v1_dot_attributes__pb2.CreateAttributeGroupRequest.SerializeToString, attributes_dot_v1_dot_attributes__pb2.CreateAttributeGroupResponse.FromString, options, channel_credentials, insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def UpdateAttribute(request, target, options=(), channel_credentials=None, call_credentials=None, insecure=False, compression=None, wait_for_ready=None, timeout=None, metadata=None):
        return grpc.experimental.unary_unary(request, target, '/attributes.v1.AttributesService/UpdateAttribute', attributes_dot_v1_dot_attributes__pb2.UpdateAttributeRequest.SerializeToString, attributes_dot_v1_dot_attributes__pb2.UpdateAttributeResponse.FromString, options, channel_credentials, insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def UpdateAttributeGroup(request, target, options=(), channel_credentials=None, call_credentials=None, insecure=False, compression=None, wait_for_ready=None, timeout=None, metadata=None):
        return grpc.experimental.unary_unary(request, target, '/attributes.v1.AttributesService/UpdateAttributeGroup', attributes_dot_v1_dot_attributes__pb2.UpdateAttributeGroupRequest.SerializeToString, attributes_dot_v1_dot_attributes__pb2.UpdateAttributeGroupResponse.FromString, options, channel_credentials, insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def DeleteAttribute(request, target, options=(), channel_credentials=None, call_credentials=None, insecure=False, compression=None, wait_for_ready=None, timeout=None, metadata=None):
        return grpc.experimental.unary_unary(request, target, '/attributes.v1.AttributesService/DeleteAttribute', attributes_dot_v1_dot_attributes__pb2.DeleteAttributeRequest.SerializeToString, attributes_dot_v1_dot_attributes__pb2.DeleteAttributeResponse.FromString, options, channel_credentials, insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def DeleteAttributeGroup(request, target, options=(), channel_credentials=None, call_credentials=None, insecure=False, compression=None, wait_for_ready=None, timeout=None, metadata=None):
        return grpc.experimental.unary_unary(request, target, '/attributes.v1.AttributesService/DeleteAttributeGroup', attributes_dot_v1_dot_attributes__pb2.DeleteAttributeGroupRequest.SerializeToString, attributes_dot_v1_dot_attributes__pb2.DeleteAttributeGroupResponse.FromString, options, channel_credentials, insecure, call_credentials, compression, wait_for_ready, timeout, metadata)