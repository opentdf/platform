// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/namespaces/namespaces.proto

// Protobuf Java Version: 3.25.3
package com.policy.namespaces;

/**
 * Protobuf type {@code policy.namespaces.ListNamespacesResponse}
 */
public final class ListNamespacesResponse extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:policy.namespaces.ListNamespacesResponse)
    ListNamespacesResponseOrBuilder {
private static final long serialVersionUID = 0L;
  // Use ListNamespacesResponse.newBuilder() to construct.
  private ListNamespacesResponse(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private ListNamespacesResponse() {
    namespaces_ = java.util.Collections.emptyList();
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new ListNamespacesResponse();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return com.policy.namespaces.NamespacesProto.internal_static_policy_namespaces_ListNamespacesResponse_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return com.policy.namespaces.NamespacesProto.internal_static_policy_namespaces_ListNamespacesResponse_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            com.policy.namespaces.ListNamespacesResponse.class, com.policy.namespaces.ListNamespacesResponse.Builder.class);
  }

  public static final int NAMESPACES_FIELD_NUMBER = 1;
  @SuppressWarnings("serial")
  private java.util.List<com.policy.namespaces.Namespace> namespaces_;
  /**
   * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
   */
  @java.lang.Override
  public java.util.List<com.policy.namespaces.Namespace> getNamespacesList() {
    return namespaces_;
  }
  /**
   * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
   */
  @java.lang.Override
  public java.util.List<? extends com.policy.namespaces.NamespaceOrBuilder> 
      getNamespacesOrBuilderList() {
    return namespaces_;
  }
  /**
   * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
   */
  @java.lang.Override
  public int getNamespacesCount() {
    return namespaces_.size();
  }
  /**
   * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
   */
  @java.lang.Override
  public com.policy.namespaces.Namespace getNamespaces(int index) {
    return namespaces_.get(index);
  }
  /**
   * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
   */
  @java.lang.Override
  public com.policy.namespaces.NamespaceOrBuilder getNamespacesOrBuilder(
      int index) {
    return namespaces_.get(index);
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
    for (int i = 0; i < namespaces_.size(); i++) {
      output.writeMessage(1, namespaces_.get(i));
    }
    getUnknownFields().writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    for (int i = 0; i < namespaces_.size(); i++) {
      size += com.google.protobuf.CodedOutputStream
        .computeMessageSize(1, namespaces_.get(i));
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
    if (!(obj instanceof com.policy.namespaces.ListNamespacesResponse)) {
      return super.equals(obj);
    }
    com.policy.namespaces.ListNamespacesResponse other = (com.policy.namespaces.ListNamespacesResponse) obj;

    if (!getNamespacesList()
        .equals(other.getNamespacesList())) return false;
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
    if (getNamespacesCount() > 0) {
      hash = (37 * hash) + NAMESPACES_FIELD_NUMBER;
      hash = (53 * hash) + getNamespacesList().hashCode();
    }
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static com.policy.namespaces.ListNamespacesResponse parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.policy.namespaces.ListNamespacesResponse parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.policy.namespaces.ListNamespacesResponse parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.policy.namespaces.ListNamespacesResponse parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.policy.namespaces.ListNamespacesResponse parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.policy.namespaces.ListNamespacesResponse parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.policy.namespaces.ListNamespacesResponse parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.policy.namespaces.ListNamespacesResponse parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static com.policy.namespaces.ListNamespacesResponse parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static com.policy.namespaces.ListNamespacesResponse parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static com.policy.namespaces.ListNamespacesResponse parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.policy.namespaces.ListNamespacesResponse parseFrom(
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
  public static Builder newBuilder(com.policy.namespaces.ListNamespacesResponse prototype) {
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
   * Protobuf type {@code policy.namespaces.ListNamespacesResponse}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:policy.namespaces.ListNamespacesResponse)
      com.policy.namespaces.ListNamespacesResponseOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return com.policy.namespaces.NamespacesProto.internal_static_policy_namespaces_ListNamespacesResponse_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return com.policy.namespaces.NamespacesProto.internal_static_policy_namespaces_ListNamespacesResponse_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              com.policy.namespaces.ListNamespacesResponse.class, com.policy.namespaces.ListNamespacesResponse.Builder.class);
    }

    // Construct using com.policy.namespaces.ListNamespacesResponse.newBuilder()
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
      if (namespacesBuilder_ == null) {
        namespaces_ = java.util.Collections.emptyList();
      } else {
        namespaces_ = null;
        namespacesBuilder_.clear();
      }
      bitField0_ = (bitField0_ & ~0x00000001);
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return com.policy.namespaces.NamespacesProto.internal_static_policy_namespaces_ListNamespacesResponse_descriptor;
    }

    @java.lang.Override
    public com.policy.namespaces.ListNamespacesResponse getDefaultInstanceForType() {
      return com.policy.namespaces.ListNamespacesResponse.getDefaultInstance();
    }

    @java.lang.Override
    public com.policy.namespaces.ListNamespacesResponse build() {
      com.policy.namespaces.ListNamespacesResponse result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public com.policy.namespaces.ListNamespacesResponse buildPartial() {
      com.policy.namespaces.ListNamespacesResponse result = new com.policy.namespaces.ListNamespacesResponse(this);
      buildPartialRepeatedFields(result);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartialRepeatedFields(com.policy.namespaces.ListNamespacesResponse result) {
      if (namespacesBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0)) {
          namespaces_ = java.util.Collections.unmodifiableList(namespaces_);
          bitField0_ = (bitField0_ & ~0x00000001);
        }
        result.namespaces_ = namespaces_;
      } else {
        result.namespaces_ = namespacesBuilder_.build();
      }
    }

    private void buildPartial0(com.policy.namespaces.ListNamespacesResponse result) {
      int from_bitField0_ = bitField0_;
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
      if (other instanceof com.policy.namespaces.ListNamespacesResponse) {
        return mergeFrom((com.policy.namespaces.ListNamespacesResponse)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(com.policy.namespaces.ListNamespacesResponse other) {
      if (other == com.policy.namespaces.ListNamespacesResponse.getDefaultInstance()) return this;
      if (namespacesBuilder_ == null) {
        if (!other.namespaces_.isEmpty()) {
          if (namespaces_.isEmpty()) {
            namespaces_ = other.namespaces_;
            bitField0_ = (bitField0_ & ~0x00000001);
          } else {
            ensureNamespacesIsMutable();
            namespaces_.addAll(other.namespaces_);
          }
          onChanged();
        }
      } else {
        if (!other.namespaces_.isEmpty()) {
          if (namespacesBuilder_.isEmpty()) {
            namespacesBuilder_.dispose();
            namespacesBuilder_ = null;
            namespaces_ = other.namespaces_;
            bitField0_ = (bitField0_ & ~0x00000001);
            namespacesBuilder_ = 
              com.google.protobuf.GeneratedMessageV3.alwaysUseFieldBuilders ?
                 getNamespacesFieldBuilder() : null;
          } else {
            namespacesBuilder_.addAllMessages(other.namespaces_);
          }
        }
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
              com.policy.namespaces.Namespace m =
                  input.readMessage(
                      com.policy.namespaces.Namespace.parser(),
                      extensionRegistry);
              if (namespacesBuilder_ == null) {
                ensureNamespacesIsMutable();
                namespaces_.add(m);
              } else {
                namespacesBuilder_.addMessage(m);
              }
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

    private java.util.List<com.policy.namespaces.Namespace> namespaces_ =
      java.util.Collections.emptyList();
    private void ensureNamespacesIsMutable() {
      if (!((bitField0_ & 0x00000001) != 0)) {
        namespaces_ = new java.util.ArrayList<com.policy.namespaces.Namespace>(namespaces_);
        bitField0_ |= 0x00000001;
       }
    }

    private com.google.protobuf.RepeatedFieldBuilderV3<
        com.policy.namespaces.Namespace, com.policy.namespaces.Namespace.Builder, com.policy.namespaces.NamespaceOrBuilder> namespacesBuilder_;

    /**
     * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
     */
    public java.util.List<com.policy.namespaces.Namespace> getNamespacesList() {
      if (namespacesBuilder_ == null) {
        return java.util.Collections.unmodifiableList(namespaces_);
      } else {
        return namespacesBuilder_.getMessageList();
      }
    }
    /**
     * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
     */
    public int getNamespacesCount() {
      if (namespacesBuilder_ == null) {
        return namespaces_.size();
      } else {
        return namespacesBuilder_.getCount();
      }
    }
    /**
     * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
     */
    public com.policy.namespaces.Namespace getNamespaces(int index) {
      if (namespacesBuilder_ == null) {
        return namespaces_.get(index);
      } else {
        return namespacesBuilder_.getMessage(index);
      }
    }
    /**
     * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
     */
    public Builder setNamespaces(
        int index, com.policy.namespaces.Namespace value) {
      if (namespacesBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureNamespacesIsMutable();
        namespaces_.set(index, value);
        onChanged();
      } else {
        namespacesBuilder_.setMessage(index, value);
      }
      return this;
    }
    /**
     * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
     */
    public Builder setNamespaces(
        int index, com.policy.namespaces.Namespace.Builder builderForValue) {
      if (namespacesBuilder_ == null) {
        ensureNamespacesIsMutable();
        namespaces_.set(index, builderForValue.build());
        onChanged();
      } else {
        namespacesBuilder_.setMessage(index, builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
     */
    public Builder addNamespaces(com.policy.namespaces.Namespace value) {
      if (namespacesBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureNamespacesIsMutable();
        namespaces_.add(value);
        onChanged();
      } else {
        namespacesBuilder_.addMessage(value);
      }
      return this;
    }
    /**
     * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
     */
    public Builder addNamespaces(
        int index, com.policy.namespaces.Namespace value) {
      if (namespacesBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureNamespacesIsMutable();
        namespaces_.add(index, value);
        onChanged();
      } else {
        namespacesBuilder_.addMessage(index, value);
      }
      return this;
    }
    /**
     * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
     */
    public Builder addNamespaces(
        com.policy.namespaces.Namespace.Builder builderForValue) {
      if (namespacesBuilder_ == null) {
        ensureNamespacesIsMutable();
        namespaces_.add(builderForValue.build());
        onChanged();
      } else {
        namespacesBuilder_.addMessage(builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
     */
    public Builder addNamespaces(
        int index, com.policy.namespaces.Namespace.Builder builderForValue) {
      if (namespacesBuilder_ == null) {
        ensureNamespacesIsMutable();
        namespaces_.add(index, builderForValue.build());
        onChanged();
      } else {
        namespacesBuilder_.addMessage(index, builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
     */
    public Builder addAllNamespaces(
        java.lang.Iterable<? extends com.policy.namespaces.Namespace> values) {
      if (namespacesBuilder_ == null) {
        ensureNamespacesIsMutable();
        com.google.protobuf.AbstractMessageLite.Builder.addAll(
            values, namespaces_);
        onChanged();
      } else {
        namespacesBuilder_.addAllMessages(values);
      }
      return this;
    }
    /**
     * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
     */
    public Builder clearNamespaces() {
      if (namespacesBuilder_ == null) {
        namespaces_ = java.util.Collections.emptyList();
        bitField0_ = (bitField0_ & ~0x00000001);
        onChanged();
      } else {
        namespacesBuilder_.clear();
      }
      return this;
    }
    /**
     * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
     */
    public Builder removeNamespaces(int index) {
      if (namespacesBuilder_ == null) {
        ensureNamespacesIsMutable();
        namespaces_.remove(index);
        onChanged();
      } else {
        namespacesBuilder_.remove(index);
      }
      return this;
    }
    /**
     * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
     */
    public com.policy.namespaces.Namespace.Builder getNamespacesBuilder(
        int index) {
      return getNamespacesFieldBuilder().getBuilder(index);
    }
    /**
     * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
     */
    public com.policy.namespaces.NamespaceOrBuilder getNamespacesOrBuilder(
        int index) {
      if (namespacesBuilder_ == null) {
        return namespaces_.get(index);  } else {
        return namespacesBuilder_.getMessageOrBuilder(index);
      }
    }
    /**
     * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
     */
    public java.util.List<? extends com.policy.namespaces.NamespaceOrBuilder> 
         getNamespacesOrBuilderList() {
      if (namespacesBuilder_ != null) {
        return namespacesBuilder_.getMessageOrBuilderList();
      } else {
        return java.util.Collections.unmodifiableList(namespaces_);
      }
    }
    /**
     * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
     */
    public com.policy.namespaces.Namespace.Builder addNamespacesBuilder() {
      return getNamespacesFieldBuilder().addBuilder(
          com.policy.namespaces.Namespace.getDefaultInstance());
    }
    /**
     * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
     */
    public com.policy.namespaces.Namespace.Builder addNamespacesBuilder(
        int index) {
      return getNamespacesFieldBuilder().addBuilder(
          index, com.policy.namespaces.Namespace.getDefaultInstance());
    }
    /**
     * <code>repeated .policy.namespaces.Namespace namespaces = 1 [json_name = "namespaces"];</code>
     */
    public java.util.List<com.policy.namespaces.Namespace.Builder> 
         getNamespacesBuilderList() {
      return getNamespacesFieldBuilder().getBuilderList();
    }
    private com.google.protobuf.RepeatedFieldBuilderV3<
        com.policy.namespaces.Namespace, com.policy.namespaces.Namespace.Builder, com.policy.namespaces.NamespaceOrBuilder> 
        getNamespacesFieldBuilder() {
      if (namespacesBuilder_ == null) {
        namespacesBuilder_ = new com.google.protobuf.RepeatedFieldBuilderV3<
            com.policy.namespaces.Namespace, com.policy.namespaces.Namespace.Builder, com.policy.namespaces.NamespaceOrBuilder>(
                namespaces_,
                ((bitField0_ & 0x00000001) != 0),
                getParentForChildren(),
                isClean());
        namespaces_ = null;
      }
      return namespacesBuilder_;
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


    // @@protoc_insertion_point(builder_scope:policy.namespaces.ListNamespacesResponse)
  }

  // @@protoc_insertion_point(class_scope:policy.namespaces.ListNamespacesResponse)
  private static final com.policy.namespaces.ListNamespacesResponse DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new com.policy.namespaces.ListNamespacesResponse();
  }

  public static com.policy.namespaces.ListNamespacesResponse getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<ListNamespacesResponse>
      PARSER = new com.google.protobuf.AbstractParser<ListNamespacesResponse>() {
    @java.lang.Override
    public ListNamespacesResponse parsePartialFrom(
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

  public static com.google.protobuf.Parser<ListNamespacesResponse> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<ListNamespacesResponse> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public com.policy.namespaces.ListNamespacesResponse getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

