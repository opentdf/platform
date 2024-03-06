// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/subjectmapping/subject_mapping.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.subjectmapping;

public interface ConditionGroupOrBuilder extends
    // @@protoc_insertion_point(interface_extends:policy.subjectmapping.ConditionGroup)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
   */
  java.util.List<io.opentdf.platform.policy.subjectmapping.Condition> 
      getConditionsList();
  /**
   * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
   */
  io.opentdf.platform.policy.subjectmapping.Condition getConditions(int index);
  /**
   * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
   */
  int getConditionsCount();
  /**
   * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
   */
  java.util.List<? extends io.opentdf.platform.policy.subjectmapping.ConditionOrBuilder> 
      getConditionsOrBuilderList();
  /**
   * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
   */
  io.opentdf.platform.policy.subjectmapping.ConditionOrBuilder getConditionsOrBuilder(
      int index);

  /**
   * <pre>
   * the boolean evaluation type across the conditions
   * </pre>
   *
   * <code>.policy.subjectmapping.ConditionBooleanTypeEnum boolean_type = 2 [json_name = "booleanType", (.buf.validate.field) = { ... }</code>
   * @return The enum numeric value on the wire for booleanType.
   */
  int getBooleanTypeValue();
  /**
   * <pre>
   * the boolean evaluation type across the conditions
   * </pre>
   *
   * <code>.policy.subjectmapping.ConditionBooleanTypeEnum boolean_type = 2 [json_name = "booleanType", (.buf.validate.field) = { ... }</code>
   * @return The booleanType.
   */
  io.opentdf.platform.policy.subjectmapping.ConditionBooleanTypeEnum getBooleanType();
}
