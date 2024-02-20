// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: kasregistry/key_access_server_registry.proto

// Protobuf Java Version: 3.25.3
package com.kasregistry;

/**
 * Protobuf type {@code kasregistry.UpdateKeyAccessServerResponse}
 */
public final class UpdateKeyAccessServerResponse extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:kasregistry.UpdateKeyAccessServerResponse)
    UpdateKeyAccessServerResponseOrBuilder {
private static final long serialVersionUID = 0L;
  // Use UpdateKeyAccessServerResponse.newBuilder() to construct.
  private UpdateKeyAccessServerResponse(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private UpdateKeyAccessServerResponse() {
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new UpdateKeyAccessServerResponse();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return com.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_UpdateKeyAccessServerResponse_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return com.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_UpdateKeyAccessServerResponse_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            com.kasregistry.UpdateKeyAccessServerResponse.class, com.kasregistry.UpdateKeyAccessServerResponse.Builder.class);
  }

  private int bitField0_;
  public static final int KEY_ACCESS_SERVER_FIELD_NUMBER = 1;
  private com.kasregistry.KeyAccessServer keyAccessServer_;
  /**
   * <code>.kasregistry.KeyAccessServer key_access_server = 1 [json_name = "keyAccessServer"];</code>
   * @return Whether the keyAccessServer field is set.
   */
  @java.lang.Override
  public boolean hasKeyAccessServer() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <code>.kasregistry.KeyAccessServer key_access_server = 1 [json_name = "keyAccessServer"];</code>
   * @return The keyAccessServer.
   */
  @java.lang.Override
  public com.kasregistry.KeyAccessServer getKeyAccessServer() {
    return keyAccessServer_ == null ? com.kasregistry.KeyAccessServer.getDefaultInstance() : keyAccessServer_;
  }
  /**
   * <code>.kasregistry.KeyAccessServer key_access_server = 1 [json_name = "keyAccessServer"];</code>
   */
  @java.lang.Override
  public com.kasregistry.KeyAccessServerOrBuilder getKeyAccessServerOrBuilder() {
    return keyAccessServer_ == null ? com.kasregistry.KeyAccessServer.getDefaultInstance() : keyAccessServer_;
  }

  private byte memoizedIsInitialized = -1;
  @java.lang.Override
  public final boolean isInitialized() {
    byte isInitialized = memoizedIsInitialized;
    if (isInitialized == 1) return true;
    if (isInitialized == 0) return false;

    memoizedIsInitialized = 1;
    return true;
  }

  @java.lang.Override
  public void writeTo(com.google.protobuf.CodedOutputStream output)
                      throws java.io.IOException {
    if (((bitField0_ & 0x00000001) != 0)) {
      output.writeMessage(1, getKeyAccessServer());
    }
    getUnknownFields().writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    if (((bitField0_ & 0x00000001) != 0)) {
      size += com.google.protobuf.CodedOutputStream
        .computeMessageSize(1, getKeyAccessServer());
    }
    size += getUnknownFields().getSerializedSize();
    memoizedSize = size;
    return size;
  }

  @java.lang.Override
  public boolean equals(final java.lang.Object obj) {
    if (obj == this) {
     return true;
    }
    if (!(obj instanceof com.kasregistry.UpdateKeyAccessServerResponse)) {
      return super.equals(obj);
    }
    com.kasregistry.UpdateKeyAccessServerResponse other = (com.kasregistry.UpdateKeyAccessServerResponse) obj;

    if (hasKeyAccessServer() != other.hasKeyAccessServer()) return false;
    if (hasKeyAccessServer()) {
      if (!getKeyAccessServer()
          .equals(other.getKeyAccessServer())) return false;
    }
    if (!getUnknownFields().equals(other.getUnknownFields())) return false;
    return true;
  }

  @java.lang.Override
  public int hashCode() {
    if (memoizedHashCode != 0) {
      return memoizedHashCode;
    }
    int hash = 41;
    hash = (19 * hash) + getDescriptor().hashCode();
    if (hasKeyAccessServer()) {
      hash = (37 * hash) + KEY_ACCESS_SERVER_FIELD_NUMBER;
      hash = (53 * hash) + getKeyAccessServer().hashCode();
    }
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static com.kasregistry.UpdateKeyAccessServerResponse parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.kasregistry.UpdateKeyAccessServerResponse parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.kasregistry.UpdateKeyAccessServerResponse parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.kasregistry.UpdateKeyAccessServerResponse parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.kasregistry.UpdateKeyAccessServerResponse parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.kasregistry.UpdateKeyAccessServerResponse parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.kasregistry.UpdateKeyAccessServerResponse parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.kasregistry.UpdateKeyAccessServerResponse parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static com.kasregistry.UpdateKeyAccessServerResponse parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static com.kasregistry.UpdateKeyAccessServerResponse parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static com.kasregistry.UpdateKeyAccessServerResponse parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.kasregistry.UpdateKeyAccessServerResponse parseFrom(
      com.google.protobuf.CodedInputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  @java.lang.Override
  public Builder newBuilderForType() { return newBuilder(); }
  public static Builder newBuilder() {
    return DEFAULT_INSTANCE.toBuilder();
  }
  public static Builder newBuilder(com.kasregistry.UpdateKeyAccessServerResponse prototype) {
    return DEFAULT_INSTANCE.toBuilder().mergeFrom(prototype);
  }
  @java.lang.Override
  public Builder toBuilder() {
    return this == DEFAULT_INSTANCE
        ? new Builder() : new Builder().mergeFrom(this);
  }

  @java.lang.Override
  protected Builder newBuilderForType(
      com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
    Builder builder = new Builder(parent);
    return builder;
  }
  /**
   * Protobuf type {@code kasregistry.UpdateKeyAccessServerResponse}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:kasregistry.UpdateKeyAccessServerResponse)
      com.kasregistry.UpdateKeyAccessServerResponseOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return com.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_UpdateKeyAccessServerResponse_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return com.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_UpdateKeyAccessServerResponse_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              com.kasregistry.UpdateKeyAccessServerResponse.class, com.kasregistry.UpdateKeyAccessServerResponse.Builder.class);
    }

    // Construct using com.kasregistry.UpdateKeyAccessServerResponse.newBuilder()
    private Builder() {
      maybeForceBuilderInitialization();
    }

    private Builder(
        com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
      super(parent);
      maybeForceBuilderInitialization();
    }
    private void maybeForceBuilderInitialization() {
      if (com.google.protobuf.GeneratedMessageV3
              .alwaysUseFieldBuilders) {
        getKeyAccessServerFieldBuilder();
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      bitField0_ = 0;
      keyAccessServer_ = null;
      if (keyAccessServerBuilder_ != null) {
        keyAccessServerBuilder_.dispose();
        keyAccessServerBuilder_ = null;
      }
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return com.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_UpdateKeyAccessServerResponse_descriptor;
    }

    @java.lang.Override
    public com.kasregistry.UpdateKeyAccessServerResponse getDefaultInstanceForType() {
      return com.kasregistry.UpdateKeyAccessServerResponse.getDefaultInstance();
    }

    @java.lang.Override
    public com.kasregistry.UpdateKeyAccessServerResponse build() {
      com.kasregistry.UpdateKeyAccessServerResponse result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public com.kasregistry.UpdateKeyAccessServerResponse buildPartial() {
      com.kasregistry.UpdateKeyAccessServerResponse result = new com.kasregistry.UpdateKeyAccessServerResponse(this);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartial0(com.kasregistry.UpdateKeyAccessServerResponse result) {
      int from_bitField0_ = bitField0_;
      int to_bitField0_ = 0;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        result.keyAccessServer_ = keyAccessServerBuilder_ == null
            ? keyAccessServer_
            : keyAccessServerBuilder_.build();
        to_bitField0_ |= 0x00000001;
      }
      result.bitField0_ |= to_bitField0_;
    }

    @java.lang.Override
    public Builder clone() {
      return super.clone();
    }
    @java.lang.Override
    public Builder setField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        java.lang.Object value) {
      return super.setField(field, value);
    }
    @java.lang.Override
    public Builder clearField(
        com.google.protobuf.Descriptors.FieldDescriptor field) {
      return super.clearField(field);
    }
    @java.lang.Override
    public Builder clearOneof(
        com.google.protobuf.Descriptors.OneofDescriptor oneof) {
      return super.clearOneof(oneof);
    }
    @java.lang.Override
    public Builder setRepeatedField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        int index, java.lang.Object value) {
      return super.setRepeatedField(field, index, value);
    }
    @java.lang.Override
    public Builder addRepeatedField(
        com.google.protobuf.Descriptors.FieldDescriptor field,
        java.lang.Object value) {
      return super.addRepeatedField(field, value);
    }
    @java.lang.Override
    public Builder mergeFrom(com.google.protobuf.Message other) {
      if (other instanceof com.kasregistry.UpdateKeyAccessServerResponse) {
        return mergeFrom((com.kasregistry.UpdateKeyAccessServerResponse)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(com.kasregistry.UpdateKeyAccessServerResponse other) {
      if (other == com.kasregistry.UpdateKeyAccessServerResponse.getDefaultInstance()) return this;
      if (other.hasKeyAccessServer()) {
        mergeKeyAccessServer(other.getKeyAccessServer());
      }
      this.mergeUnknownFields(other.getUnknownFields());
      onChanged();
      return this;
    }

    @java.lang.Override
    public final boolean isInitialized() {
      return true;
    }

    @java.lang.Override
    public Builder mergeFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws java.io.IOException {
      if (extensionRegistry == null) {
        throw new java.lang.NullPointerException();
      }
      try {
        boolean done = false;
        while (!done) {
          int tag = input.readTag();
          switch (tag) {
            case 0:
              done = true;
              break;
            case 10: {
              input.readMessage(
                  getKeyAccessServerFieldBuilder().getBuilder(),
                  extensionRegistry);
              bitField0_ |= 0x00000001;
              break;
            } // case 10
            default: {
              if (!super.parseUnknownField(input, extensionRegistry, tag)) {
                done = true; // was an endgroup tag
              }
              break;
            } // default:
          } // switch (tag)
        } // while (!done)
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        throw e.unwrapIOException();
      } finally {
        onChanged();
      } // finally
      return this;
    }
    private int bitField0_;

    private com.kasregistry.KeyAccessServer keyAccessServer_;
    private com.google.protobuf.SingleFieldBuilderV3<
        com.kasregistry.KeyAccessServer, com.kasregistry.KeyAccessServer.Builder, com.kasregistry.KeyAccessServerOrBuilder> keyAccessServerBuilder_;
    /**
     * <code>.kasregistry.KeyAccessServer key_access_server = 1 [json_name = "keyAccessServer"];</code>
     * @return Whether the keyAccessServer field is set.
     */
    public boolean hasKeyAccessServer() {
      return ((bitField0_ & 0x00000001) != 0);
    }
    /**
     * <code>.kasregistry.KeyAccessServer key_access_server = 1 [json_name = "keyAccessServer"];</code>
     * @return The keyAccessServer.
     */
    public com.kasregistry.KeyAccessServer getKeyAccessServer() {
      if (keyAccessServerBuilder_ == null) {
        return keyAccessServer_ == null ? com.kasregistry.KeyAccessServer.getDefaultInstance() : keyAccessServer_;
      } else {
        return keyAccessServerBuilder_.getMessage();
      }
    }
    /**
     * <code>.kasregistry.KeyAccessServer key_access_server = 1 [json_name = "keyAccessServer"];</code>
     */
    public Builder setKeyAccessServer(com.kasregistry.KeyAccessServer value) {
      if (keyAccessServerBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        keyAccessServer_ = value;
      } else {
        keyAccessServerBuilder_.setMessage(value);
      }
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>.kasregistry.KeyAccessServer key_access_server = 1 [json_name = "keyAccessServer"];</code>
     */
    public Builder setKeyAccessServer(
        com.kasregistry.KeyAccessServer.Builder builderForValue) {
      if (keyAccessServerBuilder_ == null) {
        keyAccessServer_ = builderForValue.build();
      } else {
        keyAccessServerBuilder_.setMessage(builderForValue.build());
      }
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>.kasregistry.KeyAccessServer key_access_server = 1 [json_name = "keyAccessServer"];</code>
     */
    public Builder mergeKeyAccessServer(com.kasregistry.KeyAccessServer value) {
      if (keyAccessServerBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0) &&
          keyAccessServer_ != null &&
          keyAccessServer_ != com.kasregistry.KeyAccessServer.getDefaultInstance()) {
          getKeyAccessServerBuilder().mergeFrom(value);
        } else {
          keyAccessServer_ = value;
        }
      } else {
        keyAccessServerBuilder_.mergeFrom(value);
      }
      if (keyAccessServer_ != null) {
        bitField0_ |= 0x00000001;
        onChanged();
      }
      return this;
    }
    /**
     * <code>.kasregistry.KeyAccessServer key_access_server = 1 [json_name = "keyAccessServer"];</code>
     */
    public Builder clearKeyAccessServer() {
      bitField0_ = (bitField0_ & ~0x00000001);
      keyAccessServer_ = null;
      if (keyAccessServerBuilder_ != null) {
        keyAccessServerBuilder_.dispose();
        keyAccessServerBuilder_ = null;
      }
      onChanged();
      return this;
    }
    /**
     * <code>.kasregistry.KeyAccessServer key_access_server = 1 [json_name = "keyAccessServer"];</code>
     */
    public com.kasregistry.KeyAccessServer.Builder getKeyAccessServerBuilder() {
      bitField0_ |= 0x00000001;
      onChanged();
      return getKeyAccessServerFieldBuilder().getBuilder();
    }
    /**
     * <code>.kasregistry.KeyAccessServer key_access_server = 1 [json_name = "keyAccessServer"];</code>
     */
    public com.kasregistry.KeyAccessServerOrBuilder getKeyAccessServerOrBuilder() {
      if (keyAccessServerBuilder_ != null) {
        return keyAccessServerBuilder_.getMessageOrBuilder();
      } else {
        return keyAccessServer_ == null ?
            com.kasregistry.KeyAccessServer.getDefaultInstance() : keyAccessServer_;
      }
    }
    /**
     * <code>.kasregistry.KeyAccessServer key_access_server = 1 [json_name = "keyAccessServer"];</code>
     */
    private com.google.protobuf.SingleFieldBuilderV3<
        com.kasregistry.KeyAccessServer, com.kasregistry.KeyAccessServer.Builder, com.kasregistry.KeyAccessServerOrBuilder> 
        getKeyAccessServerFieldBuilder() {
      if (keyAccessServerBuilder_ == null) {
        keyAccessServerBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
            com.kasregistry.KeyAccessServer, com.kasregistry.KeyAccessServer.Builder, com.kasregistry.KeyAccessServerOrBuilder>(
                getKeyAccessServer(),
                getParentForChildren(),
                isClean());
        keyAccessServer_ = null;
      }
      return keyAccessServerBuilder_;
    }
    @java.lang.Override
    public final Builder setUnknownFields(
        final com.google.protobuf.UnknownFieldSet unknownFields) {
      return super.setUnknownFields(unknownFields);
    }

    @java.lang.Override
    public final Builder mergeUnknownFields(
        final com.google.protobuf.UnknownFieldSet unknownFields) {
      return super.mergeUnknownFields(unknownFields);
    }


    // @@protoc_insertion_point(builder_scope:kasregistry.UpdateKeyAccessServerResponse)
  }

  // @@protoc_insertion_point(class_scope:kasregistry.UpdateKeyAccessServerResponse)
  private static final com.kasregistry.UpdateKeyAccessServerResponse DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new com.kasregistry.UpdateKeyAccessServerResponse();
  }

  public static com.kasregistry.UpdateKeyAccessServerResponse getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<UpdateKeyAccessServerResponse>
      PARSER = new com.google.protobuf.AbstractParser<UpdateKeyAccessServerResponse>() {
    @java.lang.Override
    public UpdateKeyAccessServerResponse parsePartialFrom(
        com.google.protobuf.CodedInputStream input,
        com.google.protobuf.ExtensionRegistryLite extensionRegistry)
        throws com.google.protobuf.InvalidProtocolBufferException {
      Builder builder = newBuilder();
      try {
        builder.mergeFrom(input, extensionRegistry);
      } catch (com.google.protobuf.InvalidProtocolBufferException e) {
        throw e.setUnfinishedMessage(builder.buildPartial());
      } catch (com.google.protobuf.UninitializedMessageException e) {
        throw e.asInvalidProtocolBufferException().setUnfinishedMessage(builder.buildPartial());
      } catch (java.io.IOException e) {
        throw new com.google.protobuf.InvalidProtocolBufferException(e)
            .setUnfinishedMessage(builder.buildPartial());
      }
      return builder.buildPartial();
    }
  };

  public static com.google.protobuf.Parser<UpdateKeyAccessServerResponse> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<UpdateKeyAccessServerResponse> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public com.kasregistry.UpdateKeyAccessServerResponse getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

