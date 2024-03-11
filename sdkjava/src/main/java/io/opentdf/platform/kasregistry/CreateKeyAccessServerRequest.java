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
    uri_ = "";
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
  public static final int URI_FIELD_NUMBER = 1;
  @SuppressWarnings("serial")
  private volatile java.lang.Object uri_ = "";
  /**
   * <pre>
   * Required
   * </pre>
   *
   * <code>string uri = 1 [json_name = "uri", (.buf.validate.field) = { ... }</code>
   * @return The uri.
   */
  @java.lang.Override
  public java.lang.String getUri() {
    java.lang.Object ref = uri_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      uri_ = s;
      return s;
    }
  }
  /**
   * <pre>
   * Required
   * </pre>
   *
   * <code>string uri = 1 [json_name = "uri", (.buf.validate.field) = { ... }</code>
   * @return The bytes for uri.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString
      getUriBytes() {
    java.lang.Object ref = uri_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      uri_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int PUBLIC_KEY_FIELD_NUMBER = 2;
  private io.opentdf.platform.kasregistry.PublicKey publicKey_;
  /**
   * <code>.kasregistry.PublicKey public_key = 2 [json_name = "publicKey", (.buf.validate.field) = { ... }</code>
   * @return Whether the publicKey field is set.
   */
  @java.lang.Override
  public boolean hasPublicKey() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <code>.kasregistry.PublicKey public_key = 2 [json_name = "publicKey", (.buf.validate.field) = { ... }</code>
   * @return The publicKey.
   */
  @java.lang.Override
  public io.opentdf.platform.kasregistry.PublicKey getPublicKey() {
    return publicKey_ == null ? io.opentdf.platform.kasregistry.PublicKey.getDefaultInstance() : publicKey_;
  }
  /**
   * <code>.kasregistry.PublicKey public_key = 2 [json_name = "publicKey", (.buf.validate.field) = { ... }</code>
   */
  @java.lang.Override
  public io.opentdf.platform.kasregistry.PublicKeyOrBuilder getPublicKeyOrBuilder() {
    return publicKey_ == null ? io.opentdf.platform.kasregistry.PublicKey.getDefaultInstance() : publicKey_;
  }

  public static final int METADATA_FIELD_NUMBER = 100;
  private io.opentdf.platform.common.MetadataMutable metadata_;
  /**
   * <pre>
   * Common metadata
   * </pre>
   *
   * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
   * @return Whether the metadata field is set.
   */
  @java.lang.Override
  public boolean hasMetadata() {
    return ((bitField0_ & 0x00000002) != 0);
  }
  /**
   * <pre>
   * Common metadata
   * </pre>
   *
   * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
   * @return The metadata.
   */
  @java.lang.Override
  public io.opentdf.platform.common.MetadataMutable getMetadata() {
    return metadata_ == null ? io.opentdf.platform.common.MetadataMutable.getDefaultInstance() : metadata_;
  }
  /**
   * <pre>
   * Common metadata
   * </pre>
   *
   * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
   */
  @java.lang.Override
  public io.opentdf.platform.common.MetadataMutableOrBuilder getMetadataOrBuilder() {
    return metadata_ == null ? io.opentdf.platform.common.MetadataMutable.getDefaultInstance() : metadata_;
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
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(uri_)) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 1, uri_);
    }
    if (((bitField0_ & 0x00000001) != 0)) {
      output.writeMessage(2, getPublicKey());
    }
    if (((bitField0_ & 0x00000002) != 0)) {
      output.writeMessage(100, getMetadata());
    }
    getUnknownFields().writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(uri_)) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(1, uri_);
    }
    if (((bitField0_ & 0x00000001) != 0)) {
      size += com.google.protobuf.CodedOutputStream
        .computeMessageSize(2, getPublicKey());
    }
    if (((bitField0_ & 0x00000002) != 0)) {
      size += com.google.protobuf.CodedOutputStream
        .computeMessageSize(100, getMetadata());
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

    if (!getUri()
        .equals(other.getUri())) return false;
    if (hasPublicKey() != other.hasPublicKey()) return false;
    if (hasPublicKey()) {
      if (!getPublicKey()
          .equals(other.getPublicKey())) return false;
    }
    if (hasMetadata() != other.hasMetadata()) return false;
    if (hasMetadata()) {
      if (!getMetadata()
          .equals(other.getMetadata())) return false;
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
    hash = (37 * hash) + URI_FIELD_NUMBER;
    hash = (53 * hash) + getUri().hashCode();
    if (hasPublicKey()) {
      hash = (37 * hash) + PUBLIC_KEY_FIELD_NUMBER;
      hash = (53 * hash) + getPublicKey().hashCode();
    }
    if (hasMetadata()) {
      hash = (37 * hash) + METADATA_FIELD_NUMBER;
      hash = (53 * hash) + getMetadata().hashCode();
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
        getPublicKeyFieldBuilder();
        getMetadataFieldBuilder();
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      bitField0_ = 0;
      uri_ = "";
      publicKey_ = null;
      if (publicKeyBuilder_ != null) {
        publicKeyBuilder_.dispose();
        publicKeyBuilder_ = null;
      }
      metadata_ = null;
      if (metadataBuilder_ != null) {
        metadataBuilder_.dispose();
        metadataBuilder_ = null;
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
      if (((from_bitField0_ & 0x00000001) != 0)) {
        result.uri_ = uri_;
      }
      int to_bitField0_ = 0;
      if (((from_bitField0_ & 0x00000002) != 0)) {
        result.publicKey_ = publicKeyBuilder_ == null
            ? publicKey_
            : publicKeyBuilder_.build();
        to_bitField0_ |= 0x00000001;
      }
      if (((from_bitField0_ & 0x00000004) != 0)) {
        result.metadata_ = metadataBuilder_ == null
            ? metadata_
            : metadataBuilder_.build();
        to_bitField0_ |= 0x00000002;
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
      if (!other.getUri().isEmpty()) {
        uri_ = other.uri_;
        bitField0_ |= 0x00000001;
        onChanged();
      }
      if (other.hasPublicKey()) {
        mergePublicKey(other.getPublicKey());
      }
      if (other.hasMetadata()) {
        mergeMetadata(other.getMetadata());
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
              uri_ = input.readStringRequireUtf8();
              bitField0_ |= 0x00000001;
              break;
            } // case 10
            case 18: {
              input.readMessage(
                  getPublicKeyFieldBuilder().getBuilder(),
                  extensionRegistry);
              bitField0_ |= 0x00000002;
              break;
            } // case 18
            case 802: {
              input.readMessage(
                  getMetadataFieldBuilder().getBuilder(),
                  extensionRegistry);
              bitField0_ |= 0x00000004;
              break;
            } // case 802
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

    private java.lang.Object uri_ = "";
    /**
     * <pre>
     * Required
     * </pre>
     *
     * <code>string uri = 1 [json_name = "uri", (.buf.validate.field) = { ... }</code>
     * @return The uri.
     */
    public java.lang.String getUri() {
      java.lang.Object ref = uri_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        uri_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <pre>
     * Required
     * </pre>
     *
     * <code>string uri = 1 [json_name = "uri", (.buf.validate.field) = { ... }</code>
     * @return The bytes for uri.
     */
    public com.google.protobuf.ByteString
        getUriBytes() {
      java.lang.Object ref = uri_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        uri_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <pre>
     * Required
     * </pre>
     *
     * <code>string uri = 1 [json_name = "uri", (.buf.validate.field) = { ... }</code>
     * @param value The uri to set.
     * @return This builder for chaining.
     */
    public Builder setUri(
        java.lang.String value) {
      if (value == null) { throw new NullPointerException(); }
      uri_ = value;
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Required
     * </pre>
     *
     * <code>string uri = 1 [json_name = "uri", (.buf.validate.field) = { ... }</code>
     * @return This builder for chaining.
     */
    public Builder clearUri() {
      uri_ = getDefaultInstance().getUri();
      bitField0_ = (bitField0_ & ~0x00000001);
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Required
     * </pre>
     *
     * <code>string uri = 1 [json_name = "uri", (.buf.validate.field) = { ... }</code>
     * @param value The bytes for uri to set.
     * @return This builder for chaining.
     */
    public Builder setUriBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) { throw new NullPointerException(); }
      checkByteStringIsUtf8(value);
      uri_ = value;
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }

    private io.opentdf.platform.kasregistry.PublicKey publicKey_;
    private com.google.protobuf.SingleFieldBuilderV3<
        io.opentdf.platform.kasregistry.PublicKey, io.opentdf.platform.kasregistry.PublicKey.Builder, io.opentdf.platform.kasregistry.PublicKeyOrBuilder> publicKeyBuilder_;
    /**
     * <code>.kasregistry.PublicKey public_key = 2 [json_name = "publicKey", (.buf.validate.field) = { ... }</code>
     * @return Whether the publicKey field is set.
     */
    public boolean hasPublicKey() {
      return ((bitField0_ & 0x00000002) != 0);
    }
    /**
     * <code>.kasregistry.PublicKey public_key = 2 [json_name = "publicKey", (.buf.validate.field) = { ... }</code>
     * @return The publicKey.
     */
    public io.opentdf.platform.kasregistry.PublicKey getPublicKey() {
      if (publicKeyBuilder_ == null) {
        return publicKey_ == null ? io.opentdf.platform.kasregistry.PublicKey.getDefaultInstance() : publicKey_;
      } else {
        return publicKeyBuilder_.getMessage();
      }
    }
    /**
     * <code>.kasregistry.PublicKey public_key = 2 [json_name = "publicKey", (.buf.validate.field) = { ... }</code>
     */
    public Builder setPublicKey(io.opentdf.platform.kasregistry.PublicKey value) {
      if (publicKeyBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        publicKey_ = value;
      } else {
        publicKeyBuilder_.setMessage(value);
      }
      bitField0_ |= 0x00000002;
      onChanged();
      return this;
    }
    /**
     * <code>.kasregistry.PublicKey public_key = 2 [json_name = "publicKey", (.buf.validate.field) = { ... }</code>
     */
    public Builder setPublicKey(
        io.opentdf.platform.kasregistry.PublicKey.Builder builderForValue) {
      if (publicKeyBuilder_ == null) {
        publicKey_ = builderForValue.build();
      } else {
        publicKeyBuilder_.setMessage(builderForValue.build());
      }
      bitField0_ |= 0x00000002;
      onChanged();
      return this;
    }
    /**
     * <code>.kasregistry.PublicKey public_key = 2 [json_name = "publicKey", (.buf.validate.field) = { ... }</code>
     */
    public Builder mergePublicKey(io.opentdf.platform.kasregistry.PublicKey value) {
      if (publicKeyBuilder_ == null) {
        if (((bitField0_ & 0x00000002) != 0) &&
          publicKey_ != null &&
          publicKey_ != io.opentdf.platform.kasregistry.PublicKey.getDefaultInstance()) {
          getPublicKeyBuilder().mergeFrom(value);
        } else {
          publicKey_ = value;
        }
      } else {
        publicKeyBuilder_.mergeFrom(value);
      }
      if (publicKey_ != null) {
        bitField0_ |= 0x00000002;
        onChanged();
      }
      return this;
    }
    /**
     * <code>.kasregistry.PublicKey public_key = 2 [json_name = "publicKey", (.buf.validate.field) = { ... }</code>
     */
    public Builder clearPublicKey() {
      bitField0_ = (bitField0_ & ~0x00000002);
      publicKey_ = null;
      if (publicKeyBuilder_ != null) {
        publicKeyBuilder_.dispose();
        publicKeyBuilder_ = null;
      }
      onChanged();
      return this;
    }
    /**
     * <code>.kasregistry.PublicKey public_key = 2 [json_name = "publicKey", (.buf.validate.field) = { ... }</code>
     */
    public io.opentdf.platform.kasregistry.PublicKey.Builder getPublicKeyBuilder() {
      bitField0_ |= 0x00000002;
      onChanged();
      return getPublicKeyFieldBuilder().getBuilder();
    }
    /**
     * <code>.kasregistry.PublicKey public_key = 2 [json_name = "publicKey", (.buf.validate.field) = { ... }</code>
     */
    public io.opentdf.platform.kasregistry.PublicKeyOrBuilder getPublicKeyOrBuilder() {
      if (publicKeyBuilder_ != null) {
        return publicKeyBuilder_.getMessageOrBuilder();
      } else {
        return publicKey_ == null ?
            io.opentdf.platform.kasregistry.PublicKey.getDefaultInstance() : publicKey_;
      }
    }
    /**
     * <code>.kasregistry.PublicKey public_key = 2 [json_name = "publicKey", (.buf.validate.field) = { ... }</code>
     */
    private com.google.protobuf.SingleFieldBuilderV3<
        io.opentdf.platform.kasregistry.PublicKey, io.opentdf.platform.kasregistry.PublicKey.Builder, io.opentdf.platform.kasregistry.PublicKeyOrBuilder> 
        getPublicKeyFieldBuilder() {
      if (publicKeyBuilder_ == null) {
        publicKeyBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
            io.opentdf.platform.kasregistry.PublicKey, io.opentdf.platform.kasregistry.PublicKey.Builder, io.opentdf.platform.kasregistry.PublicKeyOrBuilder>(
                getPublicKey(),
                getParentForChildren(),
                isClean());
        publicKey_ = null;
      }
      return publicKeyBuilder_;
    }

    private io.opentdf.platform.common.MetadataMutable metadata_;
    private com.google.protobuf.SingleFieldBuilderV3<
        io.opentdf.platform.common.MetadataMutable, io.opentdf.platform.common.MetadataMutable.Builder, io.opentdf.platform.common.MetadataMutableOrBuilder> metadataBuilder_;
    /**
     * <pre>
     * Common metadata
     * </pre>
     *
     * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
     * @return Whether the metadata field is set.
     */
    public boolean hasMetadata() {
      return ((bitField0_ & 0x00000004) != 0);
    }
    /**
     * <pre>
     * Common metadata
     * </pre>
     *
     * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
     * @return The metadata.
     */
    public io.opentdf.platform.common.MetadataMutable getMetadata() {
      if (metadataBuilder_ == null) {
        return metadata_ == null ? io.opentdf.platform.common.MetadataMutable.getDefaultInstance() : metadata_;
      } else {
        return metadataBuilder_.getMessage();
      }
    }
    /**
     * <pre>
     * Common metadata
     * </pre>
     *
     * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
     */
    public Builder setMetadata(io.opentdf.platform.common.MetadataMutable value) {
      if (metadataBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        metadata_ = value;
      } else {
        metadataBuilder_.setMessage(value);
      }
      bitField0_ |= 0x00000004;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Common metadata
     * </pre>
     *
     * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
     */
    public Builder setMetadata(
        io.opentdf.platform.common.MetadataMutable.Builder builderForValue) {
      if (metadataBuilder_ == null) {
        metadata_ = builderForValue.build();
      } else {
        metadataBuilder_.setMessage(builderForValue.build());
      }
      bitField0_ |= 0x00000004;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Common metadata
     * </pre>
     *
     * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
     */
    public Builder mergeMetadata(io.opentdf.platform.common.MetadataMutable value) {
      if (metadataBuilder_ == null) {
        if (((bitField0_ & 0x00000004) != 0) &&
          metadata_ != null &&
          metadata_ != io.opentdf.platform.common.MetadataMutable.getDefaultInstance()) {
          getMetadataBuilder().mergeFrom(value);
        } else {
          metadata_ = value;
        }
      } else {
        metadataBuilder_.mergeFrom(value);
      }
      if (metadata_ != null) {
        bitField0_ |= 0x00000004;
        onChanged();
      }
      return this;
    }
    /**
     * <pre>
     * Common metadata
     * </pre>
     *
     * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
     */
    public Builder clearMetadata() {
      bitField0_ = (bitField0_ & ~0x00000004);
      metadata_ = null;
      if (metadataBuilder_ != null) {
        metadataBuilder_.dispose();
        metadataBuilder_ = null;
      }
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Common metadata
     * </pre>
     *
     * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
     */
    public io.opentdf.platform.common.MetadataMutable.Builder getMetadataBuilder() {
      bitField0_ |= 0x00000004;
      onChanged();
      return getMetadataFieldBuilder().getBuilder();
    }
    /**
     * <pre>
     * Common metadata
     * </pre>
     *
     * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
     */
    public io.opentdf.platform.common.MetadataMutableOrBuilder getMetadataOrBuilder() {
      if (metadataBuilder_ != null) {
        return metadataBuilder_.getMessageOrBuilder();
      } else {
        return metadata_ == null ?
            io.opentdf.platform.common.MetadataMutable.getDefaultInstance() : metadata_;
      }
    }
    /**
     * <pre>
     * Common metadata
     * </pre>
     *
     * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
     */
    private com.google.protobuf.SingleFieldBuilderV3<
        io.opentdf.platform.common.MetadataMutable, io.opentdf.platform.common.MetadataMutable.Builder, io.opentdf.platform.common.MetadataMutableOrBuilder> 
        getMetadataFieldBuilder() {
      if (metadataBuilder_ == null) {
        metadataBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
            io.opentdf.platform.common.MetadataMutable, io.opentdf.platform.common.MetadataMutable.Builder, io.opentdf.platform.common.MetadataMutableOrBuilder>(
                getMetadata(),
                getParentForChildren(),
                isClean());
        metadata_ = null;
      }
      return metadataBuilder_;
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

