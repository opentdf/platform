// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: authorization/authorization.proto

// Protobuf Java Version: 3.25.3
package com.authorization;

public interface DecisionResponseOrBuilder extends
    // @@protoc_insertion_point(interface_extends:authorization.DecisionResponse)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <pre>
   * ephemeral entity chain id from the request
   * </pre>
   *
   * <code>string entity_chain_id = 1 [json_name = "entityChainId"];</code>
   * @return The entityChainId.
   */
  java.lang.String getEntityChainId();
  /**
   * <pre>
   * ephemeral entity chain id from the request
   * </pre>
   *
   * <code>string entity_chain_id = 1 [json_name = "entityChainId"];</code>
   * @return The bytes for entityChainId.
   */
  com.google.protobuf.ByteString
      getEntityChainIdBytes();

  /**
   * <pre>
   * ephemeral resource attributes id from the request
   * </pre>
   *
   * <code>string resource_attributes_id = 2 [json_name = "resourceAttributesId"];</code>
   * @return The resourceAttributesId.
   */
  java.lang.String getResourceAttributesId();
  /**
   * <pre>
   * ephemeral resource attributes id from the request
   * </pre>
   *
   * <code>string resource_attributes_id = 2 [json_name = "resourceAttributesId"];</code>
   * @return The bytes for resourceAttributesId.
   */
  com.google.protobuf.ByteString
      getResourceAttributesIdBytes();

  /**
   * <pre>
   * Action of the decision response
   * </pre>
   *
   * <code>.authorization.Action action = 3 [json_name = "action"];</code>
   * @return Whether the action field is set.
   */
  boolean hasAction();
  /**
   * <pre>
   * Action of the decision response
   * </pre>
   *
   * <code>.authorization.Action action = 3 [json_name = "action"];</code>
   * @return The action.
   */
  com.authorization.Action getAction();
  /**
   * <pre>
   * Action of the decision response
   * </pre>
   *
   * <code>.authorization.Action action = 3 [json_name = "action"];</code>
   */
  com.authorization.ActionOrBuilder getActionOrBuilder();

  /**
   * <pre>
   * The decision response
   * </pre>
   *
   * <code>.authorization.DecisionResponse.Decision decision = 4 [json_name = "decision"];</code>
   * @return The enum numeric value on the wire for decision.
   */
  int getDecisionValue();
  /**
   * <pre>
   * The decision response
   * </pre>
   *
   * <code>.authorization.DecisionResponse.Decision decision = 4 [json_name = "decision"];</code>
   * @return The decision.
   */
  com.authorization.DecisionResponse.Decision getDecision();

  /**
   * <pre>
   *optional list of obligations represented in URI format
   * </pre>
   *
   * <code>repeated string obligations = 5 [json_name = "obligations"];</code>
   * @return A list containing the obligations.
   */
  java.util.List<java.lang.String>
      getObligationsList();
  /**
   * <pre>
   *optional list of obligations represented in URI format
   * </pre>
   *
   * <code>repeated string obligations = 5 [json_name = "obligations"];</code>
   * @return The count of obligations.
   */
  int getObligationsCount();
  /**
   * <pre>
   *optional list of obligations represented in URI format
   * </pre>
   *
   * <code>repeated string obligations = 5 [json_name = "obligations"];</code>
   * @param index The index of the element to return.
   * @return The obligations at the given index.
   */
  java.lang.String getObligations(int index);
  /**
   * <pre>
   *optional list of obligations represented in URI format
   * </pre>
   *
   * <code>repeated string obligations = 5 [json_name = "obligations"];</code>
   * @param index The index of the value to return.
   * @return The bytes of the obligations at the given index.
   */
  com.google.protobuf.ByteString
      getObligationsBytes(int index);
}
