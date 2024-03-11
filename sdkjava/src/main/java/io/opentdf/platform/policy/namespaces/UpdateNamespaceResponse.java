// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/namespaces/namespaces.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.namespaces;

/**
 * Protobuf type {@code policy.namespaces.UpdateNamespaceResponse}
 */
public final class UpdateNamespaceResponse extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:policy.namespaces.UpdateNamespaceResponse)
    UpdateNamespaceResponseOrBuilder {
private static final long serialVersionUID = 0L;
  // Use UpdateNamespaceResponse.newBuilder() to construct.
  private UpdateNamespaceResponse(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private UpdateNamespaceResponse() {
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new UpdateNamespaceResponse();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return io.opentdf.platform.policy.namespaces.NamespacesProto.internal_static_policy_namespaces_UpdateNamespaceResponse_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return io.opentdf.platform.policy.namespaces.NamespacesProto.internal_static_policy_namespaces_UpdateNamespaceResponse_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse.class, io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse.Builder.class);
  }

  private int bitField0_;
  public static final int NAMESPACE_FIELD_NUMBER = 1;
  private io.opentdf.platform.policy.namespaces.Namespace namespace_;
  /**
   * <code>.policy.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
   * @return Whether the namespace field is set.
   */
  @java.lang.Override
  public boolean hasNamespace() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <code>.policy.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
   * @return The namespace.
   */
  @java.lang.Override
  public io.opentdf.platform.policy.namespaces.Namespace getNamespace() {
    return namespace_ == null ? io.opentdf.platform.policy.namespaces.Namespace.getDefaultInstance() : namespace_;
  }
  /**
   * <code>.policy.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
   */
  @java.lang.Override
  public io.opentdf.platform.policy.namespaces.NamespaceOrBuilder getNamespaceOrBuilder() {
    return namespace_ == null ? io.opentdf.platform.policy.namespaces.Namespace.getDefaultInstance() : namespace_;
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
      output.writeMessage(1, getNamespace());
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
        .computeMessageSize(1, getNamespace());
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
    if (!(obj instanceof io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse)) {
      return super.equals(obj);
    }
    io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse other = (io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse) obj;

    if (hasNamespace() != other.hasNamespace()) return false;
    if (hasNamespace()) {
      if (!getNamespace()
          .equals(other.getNamespace())) return false;
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
    if (hasNamespace()) {
      hash = (37 * hash) + NAMESPACE_FIELD_NUMBER;
      hash = (53 * hash) + getNamespace().hashCode();
    }
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse parseFrom(
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
  public static Builder newBuilder(io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse prototype) {
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
   * Protobuf type {@code policy.namespaces.UpdateNamespaceResponse}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:policy.namespaces.UpdateNamespaceResponse)
      io.opentdf.platform.policy.namespaces.UpdateNamespaceResponseOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return io.opentdf.platform.policy.namespaces.NamespacesProto.internal_static_policy_namespaces_UpdateNamespaceResponse_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return io.opentdf.platform.policy.namespaces.NamespacesProto.internal_static_policy_namespaces_UpdateNamespaceResponse_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse.class, io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse.Builder.class);
    }

    // Construct using io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse.newBuilder()
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
        getNamespaceFieldBuilder();
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      bitField0_ = 0;
      namespace_ = null;
      if (namespaceBuilder_ != null) {
        namespaceBuilder_.dispose();
        namespaceBuilder_ = null;
      }
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return io.opentdf.platform.policy.namespaces.NamespacesProto.internal_static_policy_namespaces_UpdateNamespaceResponse_descriptor;
    }

    @java.lang.Override
    public io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse getDefaultInstanceForType() {
      return io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse.getDefaultInstance();
    }

    @java.lang.Override
    public io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse build() {
      io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse buildPartial() {
      io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse result = new io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse(this);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartial0(io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse result) {
      int from_bitField0_ = bitField0_;
      int to_bitField0_ = 0;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        result.namespace_ = namespaceBuilder_ == null
            ? namespace_
            : namespaceBuilder_.build();
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
      if (other instanceof io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse) {
        return mergeFrom((io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse other) {
      if (other == io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse.getDefaultInstance()) return this;
      if (other.hasNamespace()) {
        mergeNamespace(other.getNamespace());
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
                  getNamespaceFieldBuilder().getBuilder(),
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

    private io.opentdf.platform.policy.namespaces.Namespace namespace_;
    private com.google.protobuf.SingleFieldBuilderV3<
        io.opentdf.platform.policy.namespaces.Namespace, io.opentdf.platform.policy.namespaces.Namespace.Builder, io.opentdf.platform.policy.namespaces.NamespaceOrBuilder> namespaceBuilder_;
    /**
     * <code>.policy.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
     * @return Whether the namespace field is set.
     */
    public boolean hasNamespace() {
      return ((bitField0_ & 0x00000001) != 0);
    }
    /**
     * <code>.policy.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
     * @return The namespace.
     */
    public io.opentdf.platform.policy.namespaces.Namespace getNamespace() {
      if (namespaceBuilder_ == null) {
        return namespace_ == null ? io.opentdf.platform.policy.namespaces.Namespace.getDefaultInstance() : namespace_;
      } else {
        return namespaceBuilder_.getMessage();
      }
    }
    /**
     * <code>.policy.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
     */
    public Builder setNamespace(io.opentdf.platform.policy.namespaces.Namespace value) {
      if (namespaceBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        namespace_ = value;
      } else {
        namespaceBuilder_.setMessage(value);
      }
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>.policy.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
     */
    public Builder setNamespace(
        io.opentdf.platform.policy.namespaces.Namespace.Builder builderForValue) {
      if (namespaceBuilder_ == null) {
        namespace_ = builderForValue.build();
      } else {
        namespaceBuilder_.setMessage(builderForValue.build());
      }
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>.policy.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
     */
    public Builder mergeNamespace(io.opentdf.platform.policy.namespaces.Namespace value) {
      if (namespaceBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0) &&
          namespace_ != null &&
          namespace_ != io.opentdf.platform.policy.namespaces.Namespace.getDefaultInstance()) {
          getNamespaceBuilder().mergeFrom(value);
        } else {
          namespace_ = value;
        }
      } else {
        namespaceBuilder_.mergeFrom(value);
      }
      if (namespace_ != null) {
        bitField0_ |= 0x00000001;
        onChanged();
      }
      return this;
    }
    /**
     * <code>.policy.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
     */
    public Builder clearNamespace() {
      bitField0_ = (bitField0_ & ~0x00000001);
      namespace_ = null;
      if (namespaceBuilder_ != null) {
        namespaceBuilder_.dispose();
        namespaceBuilder_ = null;
      }
      onChanged();
      return this;
    }
    /**
     * <code>.policy.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
     */
    public io.opentdf.platform.policy.namespaces.Namespace.Builder getNamespaceBuilder() {
      bitField0_ |= 0x00000001;
      onChanged();
      return getNamespaceFieldBuilder().getBuilder();
    }
    /**
     * <code>.policy.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
     */
    public io.opentdf.platform.policy.namespaces.NamespaceOrBuilder getNamespaceOrBuilder() {
      if (namespaceBuilder_ != null) {
        return namespaceBuilder_.getMessageOrBuilder();
      } else {
        return namespace_ == null ?
            io.opentdf.platform.policy.namespaces.Namespace.getDefaultInstance() : namespace_;
      }
    }
    /**
     * <code>.policy.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
     */
    private com.google.protobuf.SingleFieldBuilderV3<
        io.opentdf.platform.policy.namespaces.Namespace, io.opentdf.platform.policy.namespaces.Namespace.Builder, io.opentdf.platform.policy.namespaces.NamespaceOrBuilder> 
        getNamespaceFieldBuilder() {
      if (namespaceBuilder_ == null) {
        namespaceBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
            io.opentdf.platform.policy.namespaces.Namespace, io.opentdf.platform.policy.namespaces.Namespace.Builder, io.opentdf.platform.policy.namespaces.NamespaceOrBuilder>(
                getNamespace(),
                getParentForChildren(),
                isClean());
        namespace_ = null;
      }
      return namespaceBuilder_;
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


    // @@protoc_insertion_point(builder_scope:policy.namespaces.UpdateNamespaceResponse)
  }

  // @@protoc_insertion_point(class_scope:policy.namespaces.UpdateNamespaceResponse)
  private static final io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse();
  }

  public static io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<UpdateNamespaceResponse>
      PARSER = new com.google.protobuf.AbstractParser<UpdateNamespaceResponse>() {
    @java.lang.Override
    public UpdateNamespaceResponse parsePartialFrom(
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

  public static com.google.protobuf.Parser<UpdateNamespaceResponse> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<UpdateNamespaceResponse> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public io.opentdf.platform.policy.namespaces.UpdateNamespaceResponse getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

