// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: kasregistry/key_access_server_registry.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.kasregistry;

/**
 * Protobuf type {@code kasregistry.CreateKeyAccessServerRequest}
 */
public final class CreateKeyAccessServerRequest extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:kasregistry.CreateKeyAccessServerRequest)
    CreateKeyAccessServerRequestOrBuilder {
private static final long serialVersionUID = 0L;
  // Use CreateKeyAccessServerRequest.newBuilder() to construct.
  private CreateKeyAccessServerRequest(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private CreateKeyAccessServerRequest() {
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new CreateKeyAccessServerRequest();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return io.opentdf.platform.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_CreateKeyAccessServerRequest_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return io.opentdf.platform.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_CreateKeyAccessServerRequest_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest.class, io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest.Builder.class);
  }

  private int bitField0_;
  public static final int KEY_ACCESS_SERVER_FIELD_NUMBER = 1;
  private io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdate keyAccessServer_;
  /**
   * <code>.kasregistry.KeyAccessServerCreateUpdate key_access_server = 1 [json_name = "keyAccessServer", (.buf.validate.field) = { ... }</code>
   * @return Whether the keyAccessServer field is set.
   */
  @java.lang.Override
  public boolean hasKeyAccessServer() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <code>.kasregistry.KeyAccessServerCreateUpdate key_access_server = 1 [json_name = "keyAccessServer", (.buf.validate.field) = { ... }</code>
   * @return The keyAccessServer.
   */
  @java.lang.Override
  public io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdate getKeyAccessServer() {
    return keyAccessServer_ == null ? io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdate.getDefaultInstance() : keyAccessServer_;
  }
  /**
   * <code>.kasregistry.KeyAccessServerCreateUpdate key_access_server = 1 [json_name = "keyAccessServer", (.buf.validate.field) = { ... }</code>
   */
  @java.lang.Override
  public io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdateOrBuilder getKeyAccessServerOrBuilder() {
    return keyAccessServer_ == null ? io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdate.getDefaultInstance() : keyAccessServer_;
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
    if (!(obj instanceof io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest)) {
      return super.equals(obj);
    }
    io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest other = (io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest) obj;

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

  public static io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest parseFrom(
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
  public static Builder newBuilder(io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest prototype) {
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
   * Protobuf type {@code kasregistry.CreateKeyAccessServerRequest}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:kasregistry.CreateKeyAccessServerRequest)
      io.opentdf.platform.kasregistry.CreateKeyAccessServerRequestOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return io.opentdf.platform.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_CreateKeyAccessServerRequest_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return io.opentdf.platform.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_CreateKeyAccessServerRequest_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest.class, io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest.Builder.class);
    }

    // Construct using io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest.newBuilder()
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
      return io.opentdf.platform.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_CreateKeyAccessServerRequest_descriptor;
    }

    @java.lang.Override
    public io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest getDefaultInstanceForType() {
      return io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest.getDefaultInstance();
    }

    @java.lang.Override
    public io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest build() {
      io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest buildPartial() {
      io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest result = new io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest(this);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartial0(io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest result) {
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
      if (other instanceof io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest) {
        return mergeFrom((io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest other) {
      if (other == io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest.getDefaultInstance()) return this;
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

    private io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdate keyAccessServer_;
    private com.google.protobuf.SingleFieldBuilderV3<
        io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdate, io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdate.Builder, io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdateOrBuilder> keyAccessServerBuilder_;
    /**
     * <code>.kasregistry.KeyAccessServerCreateUpdate key_access_server = 1 [json_name = "keyAccessServer", (.buf.validate.field) = { ... }</code>
     * @return Whether the keyAccessServer field is set.
     */
    public boolean hasKeyAccessServer() {
      return ((bitField0_ & 0x00000001) != 0);
    }
    /**
     * <code>.kasregistry.KeyAccessServerCreateUpdate key_access_server = 1 [json_name = "keyAccessServer", (.buf.validate.field) = { ... }</code>
     * @return The keyAccessServer.
     */
    public io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdate getKeyAccessServer() {
      if (keyAccessServerBuilder_ == null) {
        return keyAccessServer_ == null ? io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdate.getDefaultInstance() : keyAccessServer_;
      } else {
        return keyAccessServerBuilder_.getMessage();
      }
    }
    /**
     * <code>.kasregistry.KeyAccessServerCreateUpdate key_access_server = 1 [json_name = "keyAccessServer", (.buf.validate.field) = { ... }</code>
     */
    public Builder setKeyAccessServer(io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdate value) {
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
     * <code>.kasregistry.KeyAccessServerCreateUpdate key_access_server = 1 [json_name = "keyAccessServer", (.buf.validate.field) = { ... }</code>
     */
    public Builder setKeyAccessServer(
        io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdate.Builder builderForValue) {
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
     * <code>.kasregistry.KeyAccessServerCreateUpdate key_access_server = 1 [json_name = "keyAccessServer", (.buf.validate.field) = { ... }</code>
     */
    public Builder mergeKeyAccessServer(io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdate value) {
      if (keyAccessServerBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0) &&
          keyAccessServer_ != null &&
          keyAccessServer_ != io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdate.getDefaultInstance()) {
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
     * <code>.kasregistry.KeyAccessServerCreateUpdate key_access_server = 1 [json_name = "keyAccessServer", (.buf.validate.field) = { ... }</code>
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
     * <code>.kasregistry.KeyAccessServerCreateUpdate key_access_server = 1 [json_name = "keyAccessServer", (.buf.validate.field) = { ... }</code>
     */
    public io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdate.Builder getKeyAccessServerBuilder() {
      bitField0_ |= 0x00000001;
      onChanged();
      return getKeyAccessServerFieldBuilder().getBuilder();
    }
    /**
     * <code>.kasregistry.KeyAccessServerCreateUpdate key_access_server = 1 [json_name = "keyAccessServer", (.buf.validate.field) = { ... }</code>
     */
    public io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdateOrBuilder getKeyAccessServerOrBuilder() {
      if (keyAccessServerBuilder_ != null) {
        return keyAccessServerBuilder_.getMessageOrBuilder();
      } else {
        return keyAccessServer_ == null ?
            io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdate.getDefaultInstance() : keyAccessServer_;
      }
    }
    /**
     * <code>.kasregistry.KeyAccessServerCreateUpdate key_access_server = 1 [json_name = "keyAccessServer", (.buf.validate.field) = { ... }</code>
     */
    private com.google.protobuf.SingleFieldBuilderV3<
        io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdate, io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdate.Builder, io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdateOrBuilder> 
        getKeyAccessServerFieldBuilder() {
      if (keyAccessServerBuilder_ == null) {
        keyAccessServerBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
            io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdate, io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdate.Builder, io.opentdf.platform.kasregistry.KeyAccessServerCreateUpdateOrBuilder>(
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


    // @@protoc_insertion_point(builder_scope:kasregistry.CreateKeyAccessServerRequest)
  }

  // @@protoc_insertion_point(class_scope:kasregistry.CreateKeyAccessServerRequest)
  private static final io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest();
  }

  public static io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<CreateKeyAccessServerRequest>
      PARSER = new com.google.protobuf.AbstractParser<CreateKeyAccessServerRequest>() {
    @java.lang.Override
    public CreateKeyAccessServerRequest parsePartialFrom(
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

  public static com.google.protobuf.Parser<CreateKeyAccessServerRequest> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<CreateKeyAccessServerRequest> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public io.opentdf.platform.kasregistry.CreateKeyAccessServerRequest getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

