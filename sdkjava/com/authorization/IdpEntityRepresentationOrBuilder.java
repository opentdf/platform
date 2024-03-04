// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: authorization/idp_plugin.proto

// Protobuf Java Version: 3.25.3
package com.authorization;

public interface IdpEntityRepresentationOrBuilder extends
    // @@protoc_insertion_point(interface_extends:authorization.IdpEntityRepresentation)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>repeated .google.protobuf.Struct additional_props = 1 [json_name = "additionalProps"];</code>
   */
  java.util.List<com.google.protobuf.Struct> 
      getAdditionalPropsList();
  /**
   * <code>repeated .google.protobuf.Struct additional_props = 1 [json_name = "additionalProps"];</code>
   */
  com.google.protobuf.Struct getAdditionalProps(int index);
  /**
   * <code>repeated .google.protobuf.Struct additional_props = 1 [json_name = "additionalProps"];</code>
   */
  int getAdditionalPropsCount();
  /**
   * <code>repeated .google.protobuf.Struct additional_props = 1 [json_name = "additionalProps"];</code>
   */
  java.util.List<? extends com.google.protobuf.StructOrBuilder> 
      getAdditionalPropsOrBuilderList();
  /**
   * <code>repeated .google.protobuf.Struct additional_props = 1 [json_name = "additionalProps"];</code>
   */
  com.google.protobuf.StructOrBuilder getAdditionalPropsOrBuilder(
      int index);

  /**
   * <pre>
   * ephemeral entity id from the request
   * </pre>
   *
   * <code>string original_id = 2 [json_name = "originalId"];</code>
   * @return The originalId.
   */
  java.lang.String getOriginalId();
  /**
   * <pre>
   * ephemeral entity id from the request
   * </pre>
   *
   * <code>string original_id = 2 [json_name = "originalId"];</code>
   * @return The bytes for originalId.
   */
  com.google.protobuf.ByteString
      getOriginalIdBytes();
}
