// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: wellknownconfigurationtemp/wellknown_configuration.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.wellknownconfiguration;

public interface WellKnownConfigOrBuilder extends
    // @@protoc_insertion_point(interface_extends:wellknownconfiguration.WellKnownConfig)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>map&lt;string, .google.protobuf.Struct&gt; configuration = 1 [json_name = "configuration"];</code>
   */
  int getConfigurationCount();
  /**
   * <code>map&lt;string, .google.protobuf.Struct&gt; configuration = 1 [json_name = "configuration"];</code>
   */
  boolean containsConfiguration(
      java.lang.String key);
  /**
   * Use {@link #getConfigurationMap()} instead.
   */
  @java.lang.Deprecated
  java.util.Map<java.lang.String, com.google.protobuf.Struct>
  getConfiguration();
  /**
   * <code>map&lt;string, .google.protobuf.Struct&gt; configuration = 1 [json_name = "configuration"];</code>
   */
  java.util.Map<java.lang.String, com.google.protobuf.Struct>
  getConfigurationMap();
  /**
   * <code>map&lt;string, .google.protobuf.Struct&gt; configuration = 1 [json_name = "configuration"];</code>
   */
  /* nullable */
com.google.protobuf.Struct getConfigurationOrDefault(
      java.lang.String key,
      /* nullable */
com.google.protobuf.Struct defaultValue);
  /**
   * <code>map&lt;string, .google.protobuf.Struct&gt; configuration = 1 [json_name = "configuration"];</code>
   */
  com.google.protobuf.Struct getConfigurationOrThrow(
      java.lang.String key);
}
