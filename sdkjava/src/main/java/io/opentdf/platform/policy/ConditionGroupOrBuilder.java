// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/types.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy;

public interface ConditionGroupOrBuilder extends
    // @@protoc_insertion_point(interface_extends:policy.ConditionGroup)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>repeated .policy.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
   */
  java.util.List<io.opentdf.platform.policy.Condition> 
      getConditionsList();
  /**
   * <code>repeated .policy.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
   */
  io.opentdf.platform.policy.Condition getConditions(int index);
  /**
   * <code>repeated .policy.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
   */
  int getConditionsCount();
  /**
   * <code>repeated .policy.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
   */
  java.util.List<? extends io.opentdf.platform.policy.ConditionOrBuilder> 
      getConditionsOrBuilderList();
  /**
   * <code>repeated .policy.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
   */
  io.opentdf.platform.policy.ConditionOrBuilder getConditionsOrBuilder(
      int index);

  /**
   * <pre>
   * the boolean evaluation type across the conditions
   * </pre>
   *
   * <code>.policy.ConditionBooleanTypeEnum boolean_operator = 2 [json_name = "booleanOperator", (.buf.validate.field) = { ... }</code>
   * @return The enum numeric value on the wire for booleanOperator.
   */
  int getBooleanOperatorValue();
  /**
   * <pre>
   * the boolean evaluation type across the conditions
   * </pre>
   *
   * <code>.policy.ConditionBooleanTypeEnum boolean_operator = 2 [json_name = "booleanOperator", (.buf.validate.field) = { ... }</code>
   * @return The booleanOperator.
   */
  io.opentdf.platform.policy.ConditionBooleanTypeEnum getBooleanOperator();
}
