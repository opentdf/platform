// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: common/common.proto

// Protobuf Java Version: 3.25.3
package com.common;

public interface MetadataMutableOrBuilder extends
    // @@protoc_insertion_point(interface_extends:common.MetadataMutable)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <pre>
   * optional short description
   * </pre>
   *
   * <code>map&lt;string, string&gt; labels = 3 [json_name = "labels"];</code>
   */
  int getLabelsCount();
  /**
   * <pre>
   * optional short description
   * </pre>
   *
   * <code>map&lt;string, string&gt; labels = 3 [json_name = "labels"];</code>
   */
  boolean containsLabels(
      java.lang.String key);
  /**
   * Use {@link #getLabelsMap()} instead.
   */
  @java.lang.Deprecated
  java.util.Map<java.lang.String, java.lang.String>
  getLabels();
  /**
   * <pre>
   * optional short description
   * </pre>
   *
   * <code>map&lt;string, string&gt; labels = 3 [json_name = "labels"];</code>
   */
  java.util.Map<java.lang.String, java.lang.String>
  getLabelsMap();
  /**
   * <pre>
   * optional short description
   * </pre>
   *
   * <code>map&lt;string, string&gt; labels = 3 [json_name = "labels"];</code>
   */
  /* nullable */
java.lang.String getLabelsOrDefault(
      java.lang.String key,
      /* nullable */
java.lang.String defaultValue);
  /**
   * <pre>
   * optional short description
   * </pre>
   *
   * <code>map&lt;string, string&gt; labels = 3 [json_name = "labels"];</code>
   */
  java.lang.String getLabelsOrThrow(
      java.lang.String key);

  /**
   * <pre>
   * optional long description
   * </pre>
   *
   * <code>string description = 4 [json_name = "description"];</code>
   * @return The description.
   */
  java.lang.String getDescription();
  /**
   * <pre>
   * optional long description
   * </pre>
   *
   * <code>string description = 4 [json_name = "description"];</code>
   * @return The bytes for description.
   */
  com.google.protobuf.ByteString
      getDescriptionBytes();
}
