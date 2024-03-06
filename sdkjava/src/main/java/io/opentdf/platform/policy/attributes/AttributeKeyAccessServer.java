// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/attributes/attributes.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.attributes;

/**
 * Protobuf type {@code policy.attributes.AttributeKeyAccessServer}
 */
public final class AttributeKeyAccessServer extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:policy.attributes.AttributeKeyAccessServer)
    AttributeKeyAccessServerOrBuilder {
private static final long serialVersionUID = 0L;
  // Use AttributeKeyAccessServer.newBuilder() to construct.
  private AttributeKeyAccessServer(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private AttributeKeyAccessServer() {
    attributeId_ = "";
    keyAccessServerId_ = "";
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new AttributeKeyAccessServer();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return io.opentdf.platform.policy.attributes.AttributesProto.internal_static_policy_attributes_AttributeKeyAccessServer_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return io.opentdf.platform.policy.attributes.AttributesProto.internal_static_policy_attributes_AttributeKeyAccessServer_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            io.opentdf.platform.policy.attributes.AttributeKeyAccessServer.class, io.opentdf.platform.policy.attributes.AttributeKeyAccessServer.Builder.class);
  }

  public static final int ATTRIBUTE_ID_FIELD_NUMBER = 1;
  @SuppressWarnings("serial")
  private volatile java.lang.Object attributeId_ = "";
  /**
   * <code>string attribute_id = 1 [json_name = "attributeId"];</code>
   * @return The attributeId.
   */
  @java.lang.Override
  public java.lang.String getAttributeId() {
    java.lang.Object ref = attributeId_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      attributeId_ = s;
      return s;
    }
  }
  /**
   * <code>string attribute_id = 1 [json_name = "attributeId"];</code>
   * @return The bytes for attributeId.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString
      getAttributeIdBytes() {
    java.lang.Object ref = attributeId_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      attributeId_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int KEY_ACCESS_SERVER_ID_FIELD_NUMBER = 2;
  @SuppressWarnings("serial")
  private volatile java.lang.Object keyAccessServerId_ = "";
  /**
   * <code>string key_access_server_id = 2 [json_name = "keyAccessServerId"];</code>
   * @return The keyAccessServerId.
   */
  @java.lang.Override
  public java.lang.String getKeyAccessServerId() {
    java.lang.Object ref = keyAccessServerId_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      keyAccessServerId_ = s;
      return s;
    }
  }
  /**
   * <code>string key_access_server_id = 2 [json_name = "keyAccessServerId"];</code>
   * @return The bytes for keyAccessServerId.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString
      getKeyAccessServerIdBytes() {
    java.lang.Object ref = keyAccessServerId_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      keyAccessServerId_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
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
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(attributeId_)) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 1, attributeId_);
    }
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(keyAccessServerId_)) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 2, keyAccessServerId_);
    }
    getUnknownFields().writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(attributeId_)) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(1, attributeId_);
    }
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(keyAccessServerId_)) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(2, keyAccessServerId_);
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
    if (!(obj instanceof io.opentdf.platform.policy.attributes.AttributeKeyAccessServer)) {
      return super.equals(obj);
    }
    io.opentdf.platform.policy.attributes.AttributeKeyAccessServer other = (io.opentdf.platform.policy.attributes.AttributeKeyAccessServer) obj;

    if (!getAttributeId()
        .equals(other.getAttributeId())) return false;
    if (!getKeyAccessServerId()
        .equals(other.getKeyAccessServerId())) return false;
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
    hash = (37 * hash) + ATTRIBUTE_ID_FIELD_NUMBER;
    hash = (53 * hash) + getAttributeId().hashCode();
    hash = (37 * hash) + KEY_ACCESS_SERVER_ID_FIELD_NUMBER;
    hash = (53 * hash) + getKeyAccessServerId().hashCode();
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static io.opentdf.platform.policy.attributes.AttributeKeyAccessServer parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.attributes.AttributeKeyAccessServer parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.attributes.AttributeKeyAccessServer parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.attributes.AttributeKeyAccessServer parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.attributes.AttributeKeyAccessServer parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.attributes.AttributeKeyAccessServer parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.attributes.AttributeKeyAccessServer parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.policy.attributes.AttributeKeyAccessServer parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static io.opentdf.platform.policy.attributes.AttributeKeyAccessServer parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static io.opentdf.platform.policy.attributes.AttributeKeyAccessServer parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static io.opentdf.platform.policy.attributes.AttributeKeyAccessServer parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.policy.attributes.AttributeKeyAccessServer parseFrom(
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
  public static Builder newBuilder(io.opentdf.platform.policy.attributes.AttributeKeyAccessServer prototype) {
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
   * Protobuf type {@code policy.attributes.AttributeKeyAccessServer}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:policy.attributes.AttributeKeyAccessServer)
      io.opentdf.platform.policy.attributes.AttributeKeyAccessServerOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return io.opentdf.platform.policy.attributes.AttributesProto.internal_static_policy_attributes_AttributeKeyAccessServer_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return io.opentdf.platform.policy.attributes.AttributesProto.internal_static_policy_attributes_AttributeKeyAccessServer_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              io.opentdf.platform.policy.attributes.AttributeKeyAccessServer.class, io.opentdf.platform.policy.attributes.AttributeKeyAccessServer.Builder.class);
    }

    // Construct using io.opentdf.platform.policy.attributes.AttributeKeyAccessServer.newBuilder()
    private Builder() {

    }

    private Builder(
        com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
      super(parent);

    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      bitField0_ = 0;
      attributeId_ = "";
      keyAccessServerId_ = "";
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return io.opentdf.platform.policy.attributes.AttributesProto.internal_static_policy_attributes_AttributeKeyAccessServer_descriptor;
    }

    @java.lang.Override
    public io.opentdf.platform.policy.attributes.AttributeKeyAccessServer getDefaultInstanceForType() {
      return io.opentdf.platform.policy.attributes.AttributeKeyAccessServer.getDefaultInstance();
    }

    @java.lang.Override
    public io.opentdf.platform.policy.attributes.AttributeKeyAccessServer build() {
      io.opentdf.platform.policy.attributes.AttributeKeyAccessServer result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public io.opentdf.platform.policy.attributes.AttributeKeyAccessServer buildPartial() {
      io.opentdf.platform.policy.attributes.AttributeKeyAccessServer result = new io.opentdf.platform.policy.attributes.AttributeKeyAccessServer(this);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartial0(io.opentdf.platform.policy.attributes.AttributeKeyAccessServer result) {
      int from_bitField0_ = bitField0_;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        result.attributeId_ = attributeId_;
      }
      if (((from_bitField0_ & 0x00000002) != 0)) {
        result.keyAccessServerId_ = keyAccessServerId_;
      }
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
      if (other instanceof io.opentdf.platform.policy.attributes.AttributeKeyAccessServer) {
        return mergeFrom((io.opentdf.platform.policy.attributes.AttributeKeyAccessServer)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(io.opentdf.platform.policy.attributes.AttributeKeyAccessServer other) {
      if (other == io.opentdf.platform.policy.attributes.AttributeKeyAccessServer.getDefaultInstance()) return this;
      if (!other.getAttributeId().isEmpty()) {
        attributeId_ = other.attributeId_;
        bitField0_ |= 0x00000001;
        onChanged();
      }
      if (!other.getKeyAccessServerId().isEmpty()) {
        keyAccessServerId_ = other.keyAccessServerId_;
        bitField0_ |= 0x00000002;
        onChanged();
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
              attributeId_ = input.readStringRequireUtf8();
              bitField0_ |= 0x00000001;
              break;
            } // case 10
            case 18: {
              keyAccessServerId_ = input.readStringRequireUtf8();
              bitField0_ |= 0x00000002;
              break;
            } // case 18
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

    private java.lang.Object attributeId_ = "";
    /**
     * <code>string attribute_id = 1 [json_name = "attributeId"];</code>
     * @return The attributeId.
     */
    public java.lang.String getAttributeId() {
      java.lang.Object ref = attributeId_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        attributeId_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>string attribute_id = 1 [json_name = "attributeId"];</code>
     * @return The bytes for attributeId.
     */
    public com.google.protobuf.ByteString
        getAttributeIdBytes() {
      java.lang.Object ref = attributeId_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        attributeId_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>string attribute_id = 1 [json_name = "attributeId"];</code>
     * @param value The attributeId to set.
     * @return This builder for chaining.
     */
    public Builder setAttributeId(
        java.lang.String value) {
      if (value == null) { throw new NullPointerException(); }
      attributeId_ = value;
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>string attribute_id = 1 [json_name = "attributeId"];</code>
     * @return This builder for chaining.
     */
    public Builder clearAttributeId() {
      attributeId_ = getDefaultInstance().getAttributeId();
      bitField0_ = (bitField0_ & ~0x00000001);
      onChanged();
      return this;
    }
    /**
     * <code>string attribute_id = 1 [json_name = "attributeId"];</code>
     * @param value The bytes for attributeId to set.
     * @return This builder for chaining.
     */
    public Builder setAttributeIdBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) { throw new NullPointerException(); }
      checkByteStringIsUtf8(value);
      attributeId_ = value;
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }

    private java.lang.Object keyAccessServerId_ = "";
    /**
     * <code>string key_access_server_id = 2 [json_name = "keyAccessServerId"];</code>
     * @return The keyAccessServerId.
     */
    public java.lang.String getKeyAccessServerId() {
      java.lang.Object ref = keyAccessServerId_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        keyAccessServerId_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>string key_access_server_id = 2 [json_name = "keyAccessServerId"];</code>
     * @return The bytes for keyAccessServerId.
     */
    public com.google.protobuf.ByteString
        getKeyAccessServerIdBytes() {
      java.lang.Object ref = keyAccessServerId_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        keyAccessServerId_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>string key_access_server_id = 2 [json_name = "keyAccessServerId"];</code>
     * @param value The keyAccessServerId to set.
     * @return This builder for chaining.
     */
    public Builder setKeyAccessServerId(
        java.lang.String value) {
      if (value == null) { throw new NullPointerException(); }
      keyAccessServerId_ = value;
      bitField0_ |= 0x00000002;
      onChanged();
      return this;
    }
    /**
     * <code>string key_access_server_id = 2 [json_name = "keyAccessServerId"];</code>
     * @return This builder for chaining.
     */
    public Builder clearKeyAccessServerId() {
      keyAccessServerId_ = getDefaultInstance().getKeyAccessServerId();
      bitField0_ = (bitField0_ & ~0x00000002);
      onChanged();
      return this;
    }
    /**
     * <code>string key_access_server_id = 2 [json_name = "keyAccessServerId"];</code>
     * @param value The bytes for keyAccessServerId to set.
     * @return This builder for chaining.
     */
    public Builder setKeyAccessServerIdBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) { throw new NullPointerException(); }
      checkByteStringIsUtf8(value);
      keyAccessServerId_ = value;
      bitField0_ |= 0x00000002;
      onChanged();
      return this;
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


    // @@protoc_insertion_point(builder_scope:policy.attributes.AttributeKeyAccessServer)
  }

  // @@protoc_insertion_point(class_scope:policy.attributes.AttributeKeyAccessServer)
  private static final io.opentdf.platform.policy.attributes.AttributeKeyAccessServer DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new io.opentdf.platform.policy.attributes.AttributeKeyAccessServer();
  }

  public static io.opentdf.platform.policy.attributes.AttributeKeyAccessServer getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<AttributeKeyAccessServer>
      PARSER = new com.google.protobuf.AbstractParser<AttributeKeyAccessServer>() {
    @java.lang.Override
    public AttributeKeyAccessServer parsePartialFrom(
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

  public static com.google.protobuf.Parser<AttributeKeyAccessServer> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<AttributeKeyAccessServer> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public io.opentdf.platform.policy.attributes.AttributeKeyAccessServer getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

