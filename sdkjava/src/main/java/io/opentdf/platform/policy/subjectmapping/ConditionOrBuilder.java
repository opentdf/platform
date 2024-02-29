// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/subjectmapping/subject_mapping.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.subjectmapping;

public interface ConditionOrBuilder extends
    // @@protoc_insertion_point(interface_extends:policy.subjectmapping.Condition)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <pre>
   * Resource Attribute Key; NOT Attribute Definition Attribute name
   * </pre>
   *
   * <code>string subject_attribute = 1 [json_name = "subjectAttribute"];</code>
   * @return The subjectAttribute.
   */
  java.lang.String getSubjectAttribute();
  /**
   * <pre>
   * Resource Attribute Key; NOT Attribute Definition Attribute name
   * </pre>
   *
   * <code>string subject_attribute = 1 [json_name = "subjectAttribute"];</code>
   * @return The bytes for subjectAttribute.
   */
  com.google.protobuf.ByteString
      getSubjectAttributeBytes();

  /**
   * <pre>
   * the operator
   * </pre>
   *
   * <code>.policy.subjectmapping.SubjectMappingOperatorEnum operator = 2 [json_name = "operator", (.buf.validate.field) = { ... }</code>
   * @return The enum numeric value on the wire for operator.
   */
  int getOperatorValue();
  /**
   * <pre>
   * the operator
   * </pre>
   *
   * <code>.policy.subjectmapping.SubjectMappingOperatorEnum operator = 2 [json_name = "operator", (.buf.validate.field) = { ... }</code>
   * @return The operator.
   */
  io.opentdf.platform.policy.subjectmapping.SubjectMappingOperatorEnum getOperator();

  /**
   * <pre>
   * The list of comparison values for a resource's &lt;attribute&gt; value
   * </pre>
   *
   * <code>repeated string subject_values = 3 [json_name = "subjectValues"];</code>
   * @return A list containing the subjectValues.
   */
  java.util.List<java.lang.String>
      getSubjectValuesList();
  /**
   * <pre>
   * The list of comparison values for a resource's &lt;attribute&gt; value
   * </pre>
   *
   * <code>repeated string subject_values = 3 [json_name = "subjectValues"];</code>
   * @return The count of subjectValues.
   */
  int getSubjectValuesCount();
  /**
   * <pre>
   * The list of comparison values for a resource's &lt;attribute&gt; value
   * </pre>
   *
   * <code>repeated string subject_values = 3 [json_name = "subjectValues"];</code>
   * @param index The index of the element to return.
   * @return The subjectValues at the given index.
   */
  java.lang.String getSubjectValues(int index);
  /**
   * <pre>
   * The list of comparison values for a resource's &lt;attribute&gt; value
   * </pre>
   *
   * <code>repeated string subject_values = 3 [json_name = "subjectValues"];</code>
   * @param index The index of the value to return.
   * @return The bytes of the subjectValues at the given index.
   */
  com.google.protobuf.ByteString
      getSubjectValuesBytes(int index);
}
