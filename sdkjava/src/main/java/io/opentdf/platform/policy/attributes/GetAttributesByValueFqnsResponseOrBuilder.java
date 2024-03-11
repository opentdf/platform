// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/attributes/attributes.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.attributes;

public interface GetAttributesByValueFqnsResponseOrBuilder extends
    // @@protoc_insertion_point(interface_extends:policy.attributes.GetAttributesByValueFqnsResponse)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <pre>
   * map of fqns to complete attributes and the one selected value
   * </pre>
   *
   * <code>map&lt;string, .policy.attributes.GetAttributesByValueFqnsResponse.AttributeAndValue&gt; fqn_attribute_values = 1 [json_name = "fqnAttributeValues"];</code>
   */
  int getFqnAttributeValuesCount();
  /**
   * <pre>
   * map of fqns to complete attributes and the one selected value
   * </pre>
   *
   * <code>map&lt;string, .policy.attributes.GetAttributesByValueFqnsResponse.AttributeAndValue&gt; fqn_attribute_values = 1 [json_name = "fqnAttributeValues"];</code>
   */
  boolean containsFqnAttributeValues(
      java.lang.String key);
  /**
   * Use {@link #getFqnAttributeValuesMap()} instead.
   */
  @java.lang.Deprecated
  java.util.Map<java.lang.String, io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsResponse.AttributeAndValue>
  getFqnAttributeValues();
  /**
   * <pre>
   * map of fqns to complete attributes and the one selected value
   * </pre>
   *
   * <code>map&lt;string, .policy.attributes.GetAttributesByValueFqnsResponse.AttributeAndValue&gt; fqn_attribute_values = 1 [json_name = "fqnAttributeValues"];</code>
   */
  java.util.Map<java.lang.String, io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsResponse.AttributeAndValue>
  getFqnAttributeValuesMap();
  /**
   * <pre>
   * map of fqns to complete attributes and the one selected value
   * </pre>
   *
   * <code>map&lt;string, .policy.attributes.GetAttributesByValueFqnsResponse.AttributeAndValue&gt; fqn_attribute_values = 1 [json_name = "fqnAttributeValues"];</code>
   */
  /* nullable */
io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsResponse.AttributeAndValue getFqnAttributeValuesOrDefault(
      java.lang.String key,
      /* nullable */
io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsResponse.AttributeAndValue defaultValue);
  /**
   * <pre>
   * map of fqns to complete attributes and the one selected value
   * </pre>
   *
   * <code>map&lt;string, .policy.attributes.GetAttributesByValueFqnsResponse.AttributeAndValue&gt; fqn_attribute_values = 1 [json_name = "fqnAttributeValues"];</code>
   */
  io.opentdf.platform.policy.attributes.GetAttributesByValueFqnsResponse.AttributeAndValue getFqnAttributeValuesOrThrow(
      java.lang.String key);
}
