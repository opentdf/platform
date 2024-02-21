// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: namespaces/namespaces.proto

// Protobuf Java Version: 3.25.3
package com.namespaces;

/**
 * Protobuf type {@code namespaces.GetNamespaceResponse}
 */
public final class GetNamespaceResponse extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:namespaces.GetNamespaceResponse)
    GetNamespaceResponseOrBuilder {
private static final long serialVersionUID = 0L;
  // Use GetNamespaceResponse.newBuilder() to construct.
  private GetNamespaceResponse(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private GetNamespaceResponse() {
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new GetNamespaceResponse();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return com.namespaces.NamespacesProto.internal_static_namespaces_GetNamespaceResponse_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return com.namespaces.NamespacesProto.internal_static_namespaces_GetNamespaceResponse_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            com.namespaces.GetNamespaceResponse.class, com.namespaces.GetNamespaceResponse.Builder.class);
  }

  private int bitField0_;
  public static final int NAMESPACE_FIELD_NUMBER = 1;
  private com.namespaces.Namespace namespace_;
  /**
   * <code>.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
   * @return Whether the namespace field is set.
   */
  @java.lang.Override
  public boolean hasNamespace() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <code>.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
   * @return The namespace.
   */
  @java.lang.Override
  public com.namespaces.Namespace getNamespace() {
    return namespace_ == null ? com.namespaces.Namespace.getDefaultInstance() : namespace_;
  }
  /**
   * <code>.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
   */
  @java.lang.Override
  public com.namespaces.NamespaceOrBuilder getNamespaceOrBuilder() {
    return namespace_ == null ? com.namespaces.Namespace.getDefaultInstance() : namespace_;
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
    if (!(obj instanceof com.namespaces.GetNamespaceResponse)) {
      return super.equals(obj);
    }
    com.namespaces.GetNamespaceResponse other = (com.namespaces.GetNamespaceResponse) obj;

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

  public static com.namespaces.GetNamespaceResponse parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.namespaces.GetNamespaceResponse parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.namespaces.GetNamespaceResponse parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.namespaces.GetNamespaceResponse parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.namespaces.GetNamespaceResponse parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.namespaces.GetNamespaceResponse parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.namespaces.GetNamespaceResponse parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.namespaces.GetNamespaceResponse parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static com.namespaces.GetNamespaceResponse parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static com.namespaces.GetNamespaceResponse parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static com.namespaces.GetNamespaceResponse parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.namespaces.GetNamespaceResponse parseFrom(
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
  public static Builder newBuilder(com.namespaces.GetNamespaceResponse prototype) {
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
   * Protobuf type {@code namespaces.GetNamespaceResponse}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:namespaces.GetNamespaceResponse)
      com.namespaces.GetNamespaceResponseOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return com.namespaces.NamespacesProto.internal_static_namespaces_GetNamespaceResponse_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return com.namespaces.NamespacesProto.internal_static_namespaces_GetNamespaceResponse_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              com.namespaces.GetNamespaceResponse.class, com.namespaces.GetNamespaceResponse.Builder.class);
    }

    // Construct using com.namespaces.GetNamespaceResponse.newBuilder()
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
      return com.namespaces.NamespacesProto.internal_static_namespaces_GetNamespaceResponse_descriptor;
    }

    @java.lang.Override
    public com.namespaces.GetNamespaceResponse getDefaultInstanceForType() {
      return com.namespaces.GetNamespaceResponse.getDefaultInstance();
    }

    @java.lang.Override
    public com.namespaces.GetNamespaceResponse build() {
      com.namespaces.GetNamespaceResponse result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public com.namespaces.GetNamespaceResponse buildPartial() {
      com.namespaces.GetNamespaceResponse result = new com.namespaces.GetNamespaceResponse(this);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartial0(com.namespaces.GetNamespaceResponse result) {
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
      if (other instanceof com.namespaces.GetNamespaceResponse) {
        return mergeFrom((com.namespaces.GetNamespaceResponse)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(com.namespaces.GetNamespaceResponse other) {
      if (other == com.namespaces.GetNamespaceResponse.getDefaultInstance()) return this;
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

    private com.namespaces.Namespace namespace_;
    private com.google.protobuf.SingleFieldBuilderV3<
        com.namespaces.Namespace, com.namespaces.Namespace.Builder, com.namespaces.NamespaceOrBuilder> namespaceBuilder_;
    /**
     * <code>.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
     * @return Whether the namespace field is set.
     */
    public boolean hasNamespace() {
      return ((bitField0_ & 0x00000001) != 0);
    }
    /**
     * <code>.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
     * @return The namespace.
     */
    public com.namespaces.Namespace getNamespace() {
      if (namespaceBuilder_ == null) {
        return namespace_ == null ? com.namespaces.Namespace.getDefaultInstance() : namespace_;
      } else {
        return namespaceBuilder_.getMessage();
      }
    }
    /**
     * <code>.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
     */
    public Builder setNamespace(com.namespaces.Namespace value) {
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
     * <code>.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
     */
    public Builder setNamespace(
        com.namespaces.Namespace.Builder builderForValue) {
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
     * <code>.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
     */
    public Builder mergeNamespace(com.namespaces.Namespace value) {
      if (namespaceBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0) &&
          namespace_ != null &&
          namespace_ != com.namespaces.Namespace.getDefaultInstance()) {
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
     * <code>.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
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
     * <code>.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
     */
    public com.namespaces.Namespace.Builder getNamespaceBuilder() {
      bitField0_ |= 0x00000001;
      onChanged();
      return getNamespaceFieldBuilder().getBuilder();
    }
    /**
     * <code>.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
     */
    public com.namespaces.NamespaceOrBuilder getNamespaceOrBuilder() {
      if (namespaceBuilder_ != null) {
        return namespaceBuilder_.getMessageOrBuilder();
      } else {
        return namespace_ == null ?
            com.namespaces.Namespace.getDefaultInstance() : namespace_;
      }
    }
    /**
     * <code>.namespaces.Namespace namespace = 1 [json_name = "namespace"];</code>
     */
    private com.google.protobuf.SingleFieldBuilderV3<
        com.namespaces.Namespace, com.namespaces.Namespace.Builder, com.namespaces.NamespaceOrBuilder> 
        getNamespaceFieldBuilder() {
      if (namespaceBuilder_ == null) {
        namespaceBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
            com.namespaces.Namespace, com.namespaces.Namespace.Builder, com.namespaces.NamespaceOrBuilder>(
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


    // @@protoc_insertion_point(builder_scope:namespaces.GetNamespaceResponse)
  }

  // @@protoc_insertion_point(class_scope:namespaces.GetNamespaceResponse)
  private static final com.namespaces.GetNamespaceResponse DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new com.namespaces.GetNamespaceResponse();
  }

  public static com.namespaces.GetNamespaceResponse getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<GetNamespaceResponse>
      PARSER = new com.google.protobuf.AbstractParser<GetNamespaceResponse>() {
    @java.lang.Override
    public GetNamespaceResponse parsePartialFrom(
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

  public static com.google.protobuf.Parser<GetNamespaceResponse> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<GetNamespaceResponse> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public com.namespaces.GetNamespaceResponse getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

