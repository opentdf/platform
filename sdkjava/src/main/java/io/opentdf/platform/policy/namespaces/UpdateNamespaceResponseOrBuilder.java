// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/namespaces/namespaces.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.namespaces;

public interface UpdateNamespaceResponseOrBuilder extends
    // @@protoc_insertion_point(interface_extends:policy.namespaces.UpdateNamespaceResponse)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>.policy.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
   * @return Whether the namespace field is set.
   */
  boolean hasNamespace();
  /**
   * <code>.policy.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
   * @return The namespace.
   */
  io.opentdf.platform.policy.namespaces.Namespace getNamespace();
  /**
   * <code>.policy.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
   */
  io.opentdf.platform.policy.namespaces.NamespaceOrBuilder getNamespaceOrBuilder();
}
