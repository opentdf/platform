// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: namespaces/namespaces.proto

// Protobuf Java Version: 3.25.2
package com.namespaces;

public interface ListNamespacesRequestOrBuilder extends
    // @@protoc_insertion_point(interface_extends:namespaces.ListNamespacesRequest)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <pre>
   * ACTIVE by default when not specified
   * </pre>
   *
   * <code>.common.StateTypeEnum state = 1 [json_name = "state"];</code>
   * @return The enum numeric value on the wire for state.
   */
  int getStateValue();
  /**
   * <pre>
   * ACTIVE by default when not specified
   * </pre>
   *
   * <code>.common.StateTypeEnum state = 1 [json_name = "state"];</code>
   * @return The state.
   */
  com.common.StateTypeEnum getState();
}
