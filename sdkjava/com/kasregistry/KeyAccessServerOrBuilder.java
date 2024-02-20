// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: kasregistry/key_access_server_registry.proto

// Protobuf Java Version: 3.25.3
package com.kasregistry;

public interface KeyAccessServerOrBuilder extends
    // @@protoc_insertion_point(interface_extends:kasregistry.KeyAccessServer)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <code>string id = 1 [json_name = "id"];</code>
   * @return The id.
   */
  java.lang.String getId();
  /**
   * <code>string id = 1 [json_name = "id"];</code>
   * @return The bytes for id.
   */
  com.google.protobuf.ByteString
      getIdBytes();

  /**
   * <code>.common.Metadata metadata = 2 [json_name = "metadata"];</code>
   * @return Whether the metadata field is set.
   */
  boolean hasMetadata();
  /**
   * <code>.common.Metadata metadata = 2 [json_name = "metadata"];</code>
   * @return The metadata.
   */
  com.common.Metadata getMetadata();
  /**
   * <code>.common.Metadata metadata = 2 [json_name = "metadata"];</code>
   */
  com.common.MetadataOrBuilder getMetadataOrBuilder();

  /**
   * <pre>
   * Address of a KAS instance
   * </pre>
   *
   * <code>string uri = 3 [json_name = "uri"];</code>
   * @return The uri.
   */
  java.lang.String getUri();
  /**
   * <pre>
   * Address of a KAS instance
   * </pre>
   *
   * <code>string uri = 3 [json_name = "uri"];</code>
   * @return The bytes for uri.
   */
  com.google.protobuf.ByteString
      getUriBytes();

  /**
   * <code>.kasregistry.PublicKey public_key = 4 [json_name = "publicKey"];</code>
   * @return Whether the publicKey field is set.
   */
  boolean hasPublicKey();
  /**
   * <code>.kasregistry.PublicKey public_key = 4 [json_name = "publicKey"];</code>
   * @return The publicKey.
   */
  com.kasregistry.PublicKey getPublicKey();
  /**
   * <code>.kasregistry.PublicKey public_key = 4 [json_name = "publicKey"];</code>
   */
  com.kasregistry.PublicKeyOrBuilder getPublicKeyOrBuilder();
}
