// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/resourcemapping/resource_mapping.proto

// Protobuf Java Version: 3.25.3
package com.resourcemapping;

public final class ResourceMappingProto {
  private ResourceMappingProto() {}
  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistryLite registry) {
  }

  public static void registerAllExtensions(
      com.google.protobuf.ExtensionRegistry registry) {
    registerAllExtensions(
        (com.google.protobuf.ExtensionRegistryLite) registry);
  }
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_resourcemapping_ResourceMapping_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_resourcemapping_ResourceMapping_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_resourcemapping_ResourceMappingCreateUpdate_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_resourcemapping_ResourceMappingCreateUpdate_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_resourcemapping_ListResourceMappingsRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_resourcemapping_ListResourceMappingsRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_resourcemapping_ListResourceMappingsResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_resourcemapping_ListResourceMappingsResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_resourcemapping_GetResourceMappingRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_resourcemapping_GetResourceMappingRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_resourcemapping_GetResourceMappingResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_resourcemapping_GetResourceMappingResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_resourcemapping_CreateResourceMappingRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_resourcemapping_CreateResourceMappingRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_resourcemapping_CreateResourceMappingResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_resourcemapping_CreateResourceMappingResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_resourcemapping_UpdateResourceMappingRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_resourcemapping_UpdateResourceMappingRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_resourcemapping_UpdateResourceMappingResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_resourcemapping_UpdateResourceMappingResponse_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_resourcemapping_DeleteResourceMappingRequest_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_resourcemapping_DeleteResourceMappingRequest_fieldAccessorTable;
  static final com.google.protobuf.Descriptors.Descriptor
    internal_static_resourcemapping_DeleteResourceMappingResponse_descriptor;
  static final 
    com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internal_static_resourcemapping_DeleteResourceMappingResponse_fieldAccessorTable;

  public static com.google.protobuf.Descriptors.FileDescriptor
      getDescriptor() {
    return descriptor;
  }
  private static  com.google.protobuf.Descriptors.FileDescriptor
      descriptor;
  static {
    java.lang.String[] descriptorData = {
      "\n-policy/resourcemapping/resource_mappin" +
      "g.proto\022\017resourcemapping\032\"policy/attribu" +
      "tes/attributes.proto\032\033buf/validate/valid" +
      "ate.proto\032\023common/common.proto\032\034google/a" +
      "pi/annotations.proto\"\251\001\n\017ResourceMapping" +
      "\022\016\n\002id\030\001 \001(\tR\002id\022,\n\010metadata\030\002 \001(\0132\020.com" +
      "mon.MetadataR\010metadata\022B\n\017attribute_valu" +
      "e\030\003 \001(\0132\021.attributes.ValueB\006\272H\003\310\001\001R\016attr" +
      "ibuteValue\022\024\n\005terms\030\004 \003(\tR\005terms\"\226\001\n\033Res" +
      "ourceMappingCreateUpdate\0223\n\010metadata\030\001 \001" +
      "(\0132\027.common.MetadataMutableR\010metadata\022,\n" +
      "\022attribute_value_id\030\002 \001(\tR\020attributeValu" +
      "eId\022\024\n\005terms\030\003 \003(\tR\005terms\"\035\n\033ListResourc" +
      "eMappingsRequest\"m\n\034ListResourceMappings" +
      "Response\022M\n\021resource_mappings\030\001 \003(\0132 .re" +
      "sourcemapping.ResourceMappingR\020resourceM" +
      "appings\"3\n\031GetResourceMappingRequest\022\026\n\002" +
      "id\030\001 \001(\tB\006\272H\003\310\001\001R\002id\"i\n\032GetResourceMappi" +
      "ngResponse\022K\n\020resource_mapping\030\001 \001(\0132 .r" +
      "esourcemapping.ResourceMappingR\017resource" +
      "Mapping\"\177\n\034CreateResourceMappingRequest\022" +
      "_\n\020resource_mapping\030\001 \001(\0132,.resourcemapp" +
      "ing.ResourceMappingCreateUpdateB\006\272H\003\310\001\001R" +
      "\017resourceMapping\"l\n\035CreateResourceMappin" +
      "gResponse\022K\n\020resource_mapping\030\001 \001(\0132 .re" +
      "sourcemapping.ResourceMappingR\017resourceM" +
      "apping\"\227\001\n\034UpdateResourceMappingRequest\022" +
      "\026\n\002id\030\001 \001(\tB\006\272H\003\310\001\001R\002id\022_\n\020resource_mapp" +
      "ing\030\002 \001(\0132,.resourcemapping.ResourceMapp" +
      "ingCreateUpdateB\006\272H\003\310\001\001R\017resourceMapping" +
      "\"l\n\035UpdateResourceMappingResponse\022K\n\020res" +
      "ource_mapping\030\001 \001(\0132 .resourcemapping.Re" +
      "sourceMappingR\017resourceMapping\"6\n\034Delete" +
      "ResourceMappingRequest\022\026\n\002id\030\001 \001(\tB\006\272H\003\310" +
      "\001\001R\002id\"l\n\035DeleteResourceMappingResponse\022" +
      "K\n\020resource_mapping\030\001 \001(\0132 .resourcemapp" +
      "ing.ResourceMappingR\017resourceMapping2\250\006\n" +
      "\026ResourceMappingService\022\217\001\n\024ListResource" +
      "Mappings\022,.resourcemapping.ListResourceM" +
      "appingsRequest\032-.resourcemapping.ListRes" +
      "ourceMappingsResponse\"\032\202\323\344\223\002\024\022\022/resource" +
      "-mappings\022\216\001\n\022GetResourceMapping\022*.resou" +
      "rcemapping.GetResourceMappingRequest\032+.r" +
      "esourcemapping.GetResourceMappingRespons" +
      "e\"\037\202\323\344\223\002\031\022\027/resource-mappings/{id}\022\244\001\n\025C" +
      "reateResourceMapping\022-.resourcemapping.C" +
      "reateResourceMappingRequest\032..resourcema" +
      "pping.CreateResourceMappingResponse\",\202\323\344" +
      "\223\002&\"\022/resource-mappings:\020resource_mappin" +
      "g\022\251\001\n\025UpdateResourceMapping\022-.resourcema" +
      "pping.UpdateResourceMappingRequest\032..res" +
      "ourcemapping.UpdateResourceMappingRespon" +
      "se\"1\202\323\344\223\002+\"\027/resource-mappings/{id}:\020res" +
      "ource_mapping\022\227\001\n\025DeleteResourceMapping\022" +
      "-.resourcemapping.DeleteResourceMappingR" +
      "equest\032..resourcemapping.DeleteResourceM" +
      "appingResponse\"\037\202\323\344\223\002\031*\027/resource-mappin" +
      "gs/{id}B\315\001\n\023com.resourcemappingB\024Resourc" +
      "eMappingProtoP\001ZDgithub.com/opentdf/open" +
      "tdf-v2-poc/protocol/go/policy/resourcema" +
      "pping\242\002\003RXX\252\002\017Resourcemapping\312\002\017Resource" +
      "mapping\342\002\033Resourcemapping\\GPBMetadata\352\002\017" +
      "Resourcemappingb\006proto3"
    };
    descriptor = com.google.protobuf.Descriptors.FileDescriptor
      .internalBuildGeneratedFileFrom(descriptorData,
        new com.google.protobuf.Descriptors.FileDescriptor[] {
          com.attributes.AttributesProto.getDescriptor(),
          com.buf.validate.ValidateProto.getDescriptor(),
          com.common.CommonProto.getDescriptor(),
          com.google.api.AnnotationsProto.getDescriptor(),
        });
    internal_static_resourcemapping_ResourceMapping_descriptor =
      getDescriptor().getMessageTypes().get(0);
    internal_static_resourcemapping_ResourceMapping_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_resourcemapping_ResourceMapping_descriptor,
        new java.lang.String[] { "Id", "Metadata", "AttributeValue", "Terms", });
    internal_static_resourcemapping_ResourceMappingCreateUpdate_descriptor =
      getDescriptor().getMessageTypes().get(1);
    internal_static_resourcemapping_ResourceMappingCreateUpdate_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_resourcemapping_ResourceMappingCreateUpdate_descriptor,
        new java.lang.String[] { "Metadata", "AttributeValueId", "Terms", });
    internal_static_resourcemapping_ListResourceMappingsRequest_descriptor =
      getDescriptor().getMessageTypes().get(2);
    internal_static_resourcemapping_ListResourceMappingsRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_resourcemapping_ListResourceMappingsRequest_descriptor,
        new java.lang.String[] { });
    internal_static_resourcemapping_ListResourceMappingsResponse_descriptor =
      getDescriptor().getMessageTypes().get(3);
    internal_static_resourcemapping_ListResourceMappingsResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_resourcemapping_ListResourceMappingsResponse_descriptor,
        new java.lang.String[] { "ResourceMappings", });
    internal_static_resourcemapping_GetResourceMappingRequest_descriptor =
      getDescriptor().getMessageTypes().get(4);
    internal_static_resourcemapping_GetResourceMappingRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_resourcemapping_GetResourceMappingRequest_descriptor,
        new java.lang.String[] { "Id", });
    internal_static_resourcemapping_GetResourceMappingResponse_descriptor =
      getDescriptor().getMessageTypes().get(5);
    internal_static_resourcemapping_GetResourceMappingResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_resourcemapping_GetResourceMappingResponse_descriptor,
        new java.lang.String[] { "ResourceMapping", });
    internal_static_resourcemapping_CreateResourceMappingRequest_descriptor =
      getDescriptor().getMessageTypes().get(6);
    internal_static_resourcemapping_CreateResourceMappingRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_resourcemapping_CreateResourceMappingRequest_descriptor,
        new java.lang.String[] { "ResourceMapping", });
    internal_static_resourcemapping_CreateResourceMappingResponse_descriptor =
      getDescriptor().getMessageTypes().get(7);
    internal_static_resourcemapping_CreateResourceMappingResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_resourcemapping_CreateResourceMappingResponse_descriptor,
        new java.lang.String[] { "ResourceMapping", });
    internal_static_resourcemapping_UpdateResourceMappingRequest_descriptor =
      getDescriptor().getMessageTypes().get(8);
    internal_static_resourcemapping_UpdateResourceMappingRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_resourcemapping_UpdateResourceMappingRequest_descriptor,
        new java.lang.String[] { "Id", "ResourceMapping", });
    internal_static_resourcemapping_UpdateResourceMappingResponse_descriptor =
      getDescriptor().getMessageTypes().get(9);
    internal_static_resourcemapping_UpdateResourceMappingResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_resourcemapping_UpdateResourceMappingResponse_descriptor,
        new java.lang.String[] { "ResourceMapping", });
    internal_static_resourcemapping_DeleteResourceMappingRequest_descriptor =
      getDescriptor().getMessageTypes().get(10);
    internal_static_resourcemapping_DeleteResourceMappingRequest_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_resourcemapping_DeleteResourceMappingRequest_descriptor,
        new java.lang.String[] { "Id", });
    internal_static_resourcemapping_DeleteResourceMappingResponse_descriptor =
      getDescriptor().getMessageTypes().get(11);
    internal_static_resourcemapping_DeleteResourceMappingResponse_fieldAccessorTable = new
      com.google.protobuf.GeneratedMessageV3.FieldAccessorTable(
        internal_static_resourcemapping_DeleteResourceMappingResponse_descriptor,
        new java.lang.String[] { "ResourceMapping", });
    com.google.protobuf.ExtensionRegistry registry =
        com.google.protobuf.ExtensionRegistry.newInstance();
    registry.add(com.buf.validate.ValidateProto.field);
    registry.add(com.google.api.AnnotationsProto.http);
    com.google.protobuf.Descriptors.FileDescriptor
        .internalUpdateFileDescriptor(descriptor, registry);
    com.attributes.AttributesProto.getDescriptor();
    com.buf.validate.ValidateProto.getDescriptor();
    com.common.CommonProto.getDescriptor();
    com.google.api.AnnotationsProto.getDescriptor();
  }

  // @@protoc_insertion_point(outer_class_scope)
}
