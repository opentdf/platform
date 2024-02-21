// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: authorization/authorization.proto

// Protobuf Java Version: 3.25.3
package com.authorization;

public interface DecisionRequestOrBuilder extends
    // @@protoc_insertion_point(interface_extends:authorization.DecisionRequest)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>repeated .authorization.Action actions = 1 [json_name = "actions"];</code>
   */
  java.util.List<com.authorization.Action> 
      getActionsList();
  /**
   * <code>repeated .authorization.Action actions = 1 [json_name = "actions"];</code>
   */
  com.authorization.Action getActions(int index);
  /**
   * <code>repeated .authorization.Action actions = 1 [json_name = "actions"];</code>
   */
  int getActionsCount();
  /**
   * <code>repeated .authorization.Action actions = 1 [json_name = "actions"];</code>
   */
  java.util.List<? extends com.authorization.ActionOrBuilder> 
      getActionsOrBuilderList();
  /**
   * <code>repeated .authorization.Action actions = 1 [json_name = "actions"];</code>
   */
  com.authorization.ActionOrBuilder getActionsOrBuilder(
      int index);

  /**
   * <code>repeated .authorization.EntityChain entity_chains = 2 [json_name = "entityChains"];</code>
   */
  java.util.List<com.authorization.EntityChain> 
      getEntityChainsList();
  /**
   * <code>repeated .authorization.EntityChain entity_chains = 2 [json_name = "entityChains"];</code>
   */
  com.authorization.EntityChain getEntityChains(int index);
  /**
   * <code>repeated .authorization.EntityChain entity_chains = 2 [json_name = "entityChains"];</code>
   */
  int getEntityChainsCount();
  /**
   * <code>repeated .authorization.EntityChain entity_chains = 2 [json_name = "entityChains"];</code>
   */
  java.util.List<? extends com.authorization.EntityChainOrBuilder> 
      getEntityChainsOrBuilderList();
  /**
   * <code>repeated .authorization.EntityChain entity_chains = 2 [json_name = "entityChains"];</code>
   */
  com.authorization.EntityChainOrBuilder getEntityChainsOrBuilder(
      int index);

  /**
   * <code>repeated .authorization.ResourceAttribute resource_attributes = 3 [json_name = "resourceAttributes"];</code>
   */
  java.util.List<com.authorization.ResourceAttribute> 
      getResourceAttributesList();
  /**
   * <code>repeated .authorization.ResourceAttribute resource_attributes = 3 [json_name = "resourceAttributes"];</code>
   */
  com.authorization.ResourceAttribute getResourceAttributes(int index);
  /**
   * <code>repeated .authorization.ResourceAttribute resource_attributes = 3 [json_name = "resourceAttributes"];</code>
   */
  int getResourceAttributesCount();
  /**
   * <code>repeated .authorization.ResourceAttribute resource_attributes = 3 [json_name = "resourceAttributes"];</code>
   */
  java.util.List<? extends com.authorization.ResourceAttributeOrBuilder> 
      getResourceAttributesOrBuilderList();
  /**
   * <code>repeated .authorization.ResourceAttribute resource_attributes = 3 [json_name = "resourceAttributes"];</code>
   */
  com.authorization.ResourceAttributeOrBuilder getResourceAttributesOrBuilder(
      int index);
}
