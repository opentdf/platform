// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: resourcemapping/resource_mapping.proto

// Protobuf Java Version: 3.25.2
package com.resourcemapping;

public interface UpdateResourceMappingRequestOrBuilder extends
    // @@protoc_insertion_point(interface_extends:resourcemapping.UpdateResourceMappingRequest)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>string id = 1 [json_name = "id", (.buf.validate.field) = { ... }</code>
   * @return The id.
   */
  java.lang.String getId();
  /**
   * <code>string id = 1 [json_name = "id", (.buf.validate.field) = { ... }</code>
   * @return The bytes for id.
   */
  com.google.protobuf.ByteString
      getIdBytes();

  /**
   * <code>.resourcemapping.ResourceMappingCreateUpdate resource_mapping = 2 [json_name = "resourceMapping", (.buf.validate.field) = { ... }</code>
   * @return Whether the resourceMapping field is set.
   */
  boolean hasResourceMapping();
  /**
   * <code>.resourcemapping.ResourceMappingCreateUpdate resource_mapping = 2 [json_name = "resourceMapping", (.buf.validate.field) = { ... }</code>
   * @return The resourceMapping.
   */
  com.resourcemapping.ResourceMappingCreateUpdate getResourceMapping();
  /**
   * <code>.resourcemapping.ResourceMappingCreateUpdate resource_mapping = 2 [json_name = "resourceMapping", (.buf.validate.field) = { ... }</code>
   */
  com.resourcemapping.ResourceMappingCreateUpdateOrBuilder getResourceMappingOrBuilder();
}
