// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: authorization/idpaddon/idp_add_on.proto

// Protobuf Java Version: 3.25.3
package com.authorization.idpaddon;

public interface IdpAddOnResponseOrBuilder extends
    // @@protoc_insertion_point(interface_extends:authorization.idpaddon.IdpAddOnResponse)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
   */
  java.util.List<com.authorization.idpaddon.IdpEntityRepresentation> 
      getEntityRepresentationsList();
  /**
   * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
   */
  com.authorization.idpaddon.IdpEntityRepresentation getEntityRepresentations(int index);
  /**
   * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
   */
  int getEntityRepresentationsCount();
  /**
   * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
   */
  java.util.List<? extends com.authorization.idpaddon.IdpEntityRepresentationOrBuilder> 
      getEntityRepresentationsOrBuilderList();
  /**
   * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
   */
  com.authorization.idpaddon.IdpEntityRepresentationOrBuilder getEntityRepresentationsOrBuilder(
      int index);
}
