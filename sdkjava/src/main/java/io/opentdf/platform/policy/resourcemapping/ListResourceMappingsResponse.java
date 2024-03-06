// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/resourcemapping/resource_mapping.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.resourcemapping;

/**
 * Protobuf type {@code policy.resourcemapping.ListResourceMappingsResponse}
 */
public final class ListResourceMappingsResponse extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:policy.resourcemapping.ListResourceMappingsResponse)
    ListResourceMappingsResponseOrBuilder {
private static final long serialVersionUID = 0L;
  // Use ListResourceMappingsResponse.newBuilder() to construct.
  private ListResourceMappingsResponse(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private ListResourceMappingsResponse() {
    resourceMappings_ = java.util.Collections.emptyList();
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new ListResourceMappingsResponse();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return io.opentdf.platform.policy.resourcemapping.ResourceMappingProto.internal_static_policy_resourcemapping_ListResourceMappingsResponse_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return io.opentdf.platform.policy.resourcemapping.ResourceMappingProto.internal_static_policy_resourcemapping_ListResourceMappingsResponse_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse.class, io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse.Builder.class);
  }

  public static final int RESOURCE_MAPPINGS_FIELD_NUMBER = 1;
  @SuppressWarnings("serial")
  private java.util.List<io.opentdf.platform.policy.resourcemapping.ResourceMapping> resourceMappings_;
  /**
   * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
   */
  @java.lang.Override
  public java.util.List<io.opentdf.platform.policy.resourcemapping.ResourceMapping> getResourceMappingsList() {
    return resourceMappings_;
  }
  /**
   * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
   */
  @java.lang.Override
  public java.util.List<? extends io.opentdf.platform.policy.resourcemapping.ResourceMappingOrBuilder> 
      getResourceMappingsOrBuilderList() {
    return resourceMappings_;
  }
  /**
   * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
   */
  @java.lang.Override
  public int getResourceMappingsCount() {
    return resourceMappings_.size();
  }
  /**
   * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
   */
  @java.lang.Override
  public io.opentdf.platform.policy.resourcemapping.ResourceMapping getResourceMappings(int index) {
    return resourceMappings_.get(index);
  }
  /**
   * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
   */
  @java.lang.Override
  public io.opentdf.platform.policy.resourcemapping.ResourceMappingOrBuilder getResourceMappingsOrBuilder(
      int index) {
    return resourceMappings_.get(index);
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
    for (int i = 0; i < resourceMappings_.size(); i++) {
      output.writeMessage(1, resourceMappings_.get(i));
    }
    getUnknownFields().writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    for (int i = 0; i < resourceMappings_.size(); i++) {
      size += com.google.protobuf.CodedOutputStream
        .computeMessageSize(1, resourceMappings_.get(i));
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
    if (!(obj instanceof io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse)) {
      return super.equals(obj);
    }
    io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse other = (io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse) obj;

    if (!getResourceMappingsList()
        .equals(other.getResourceMappingsList())) return false;
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
    if (getResourceMappingsCount() > 0) {
      hash = (37 * hash) + RESOURCE_MAPPINGS_FIELD_NUMBER;
      hash = (53 * hash) + getResourceMappingsList().hashCode();
    }
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse parseFrom(
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
  public static Builder newBuilder(io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse prototype) {
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
   * Protobuf type {@code policy.resourcemapping.ListResourceMappingsResponse}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:policy.resourcemapping.ListResourceMappingsResponse)
      io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponseOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return io.opentdf.platform.policy.resourcemapping.ResourceMappingProto.internal_static_policy_resourcemapping_ListResourceMappingsResponse_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return io.opentdf.platform.policy.resourcemapping.ResourceMappingProto.internal_static_policy_resourcemapping_ListResourceMappingsResponse_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse.class, io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse.Builder.class);
    }

    // Construct using io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse.newBuilder()
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
      if (resourceMappingsBuilder_ == null) {
        resourceMappings_ = java.util.Collections.emptyList();
      } else {
        resourceMappings_ = null;
        resourceMappingsBuilder_.clear();
      }
      bitField0_ = (bitField0_ & ~0x00000001);
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return io.opentdf.platform.policy.resourcemapping.ResourceMappingProto.internal_static_policy_resourcemapping_ListResourceMappingsResponse_descriptor;
    }

    @java.lang.Override
    public io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse getDefaultInstanceForType() {
      return io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse.getDefaultInstance();
    }

    @java.lang.Override
    public io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse build() {
      io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse buildPartial() {
      io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse result = new io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse(this);
      buildPartialRepeatedFields(result);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartialRepeatedFields(io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse result) {
      if (resourceMappingsBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0)) {
          resourceMappings_ = java.util.Collections.unmodifiableList(resourceMappings_);
          bitField0_ = (bitField0_ & ~0x00000001);
        }
        result.resourceMappings_ = resourceMappings_;
      } else {
        result.resourceMappings_ = resourceMappingsBuilder_.build();
      }
    }

    private void buildPartial0(io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse result) {
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
      if (other instanceof io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse) {
        return mergeFrom((io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse other) {
      if (other == io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse.getDefaultInstance()) return this;
      if (resourceMappingsBuilder_ == null) {
        if (!other.resourceMappings_.isEmpty()) {
          if (resourceMappings_.isEmpty()) {
            resourceMappings_ = other.resourceMappings_;
            bitField0_ = (bitField0_ & ~0x00000001);
          } else {
            ensureResourceMappingsIsMutable();
            resourceMappings_.addAll(other.resourceMappings_);
          }
          onChanged();
        }
      } else {
        if (!other.resourceMappings_.isEmpty()) {
          if (resourceMappingsBuilder_.isEmpty()) {
            resourceMappingsBuilder_.dispose();
            resourceMappingsBuilder_ = null;
            resourceMappings_ = other.resourceMappings_;
            bitField0_ = (bitField0_ & ~0x00000001);
            resourceMappingsBuilder_ = 
              com.google.protobuf.GeneratedMessageV3.alwaysUseFieldBuilders ?
                 getResourceMappingsFieldBuilder() : null;
          } else {
            resourceMappingsBuilder_.addAllMessages(other.resourceMappings_);
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
              io.opentdf.platform.policy.resourcemapping.ResourceMapping m =
                  input.readMessage(
                      io.opentdf.platform.policy.resourcemapping.ResourceMapping.parser(),
                      extensionRegistry);
              if (resourceMappingsBuilder_ == null) {
                ensureResourceMappingsIsMutable();
                resourceMappings_.add(m);
              } else {
                resourceMappingsBuilder_.addMessage(m);
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

    private java.util.List<io.opentdf.platform.policy.resourcemapping.ResourceMapping> resourceMappings_ =
      java.util.Collections.emptyList();
    private void ensureResourceMappingsIsMutable() {
      if (!((bitField0_ & 0x00000001) != 0)) {
        resourceMappings_ = new java.util.ArrayList<io.opentdf.platform.policy.resourcemapping.ResourceMapping>(resourceMappings_);
        bitField0_ |= 0x00000001;
       }
    }

    private com.google.protobuf.RepeatedFieldBuilderV3<
        io.opentdf.platform.policy.resourcemapping.ResourceMapping, io.opentdf.platform.policy.resourcemapping.ResourceMapping.Builder, io.opentdf.platform.policy.resourcemapping.ResourceMappingOrBuilder> resourceMappingsBuilder_;

    /**
     * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
     */
    public java.util.List<io.opentdf.platform.policy.resourcemapping.ResourceMapping> getResourceMappingsList() {
      if (resourceMappingsBuilder_ == null) {
        return java.util.Collections.unmodifiableList(resourceMappings_);
      } else {
        return resourceMappingsBuilder_.getMessageList();
      }
    }
    /**
     * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
     */
    public int getResourceMappingsCount() {
      if (resourceMappingsBuilder_ == null) {
        return resourceMappings_.size();
      } else {
        return resourceMappingsBuilder_.getCount();
      }
    }
    /**
     * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
     */
    public io.opentdf.platform.policy.resourcemapping.ResourceMapping getResourceMappings(int index) {
      if (resourceMappingsBuilder_ == null) {
        return resourceMappings_.get(index);
      } else {
        return resourceMappingsBuilder_.getMessage(index);
      }
    }
    /**
     * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
     */
    public Builder setResourceMappings(
        int index, io.opentdf.platform.policy.resourcemapping.ResourceMapping value) {
      if (resourceMappingsBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureResourceMappingsIsMutable();
        resourceMappings_.set(index, value);
        onChanged();
      } else {
        resourceMappingsBuilder_.setMessage(index, value);
      }
      return this;
    }
    /**
     * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
     */
    public Builder setResourceMappings(
        int index, io.opentdf.platform.policy.resourcemapping.ResourceMapping.Builder builderForValue) {
      if (resourceMappingsBuilder_ == null) {
        ensureResourceMappingsIsMutable();
        resourceMappings_.set(index, builderForValue.build());
        onChanged();
      } else {
        resourceMappingsBuilder_.setMessage(index, builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
     */
    public Builder addResourceMappings(io.opentdf.platform.policy.resourcemapping.ResourceMapping value) {
      if (resourceMappingsBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureResourceMappingsIsMutable();
        resourceMappings_.add(value);
        onChanged();
      } else {
        resourceMappingsBuilder_.addMessage(value);
      }
      return this;
    }
    /**
     * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
     */
    public Builder addResourceMappings(
        int index, io.opentdf.platform.policy.resourcemapping.ResourceMapping value) {
      if (resourceMappingsBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureResourceMappingsIsMutable();
        resourceMappings_.add(index, value);
        onChanged();
      } else {
        resourceMappingsBuilder_.addMessage(index, value);
      }
      return this;
    }
    /**
     * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
     */
    public Builder addResourceMappings(
        io.opentdf.platform.policy.resourcemapping.ResourceMapping.Builder builderForValue) {
      if (resourceMappingsBuilder_ == null) {
        ensureResourceMappingsIsMutable();
        resourceMappings_.add(builderForValue.build());
        onChanged();
      } else {
        resourceMappingsBuilder_.addMessage(builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
     */
    public Builder addResourceMappings(
        int index, io.opentdf.platform.policy.resourcemapping.ResourceMapping.Builder builderForValue) {
      if (resourceMappingsBuilder_ == null) {
        ensureResourceMappingsIsMutable();
        resourceMappings_.add(index, builderForValue.build());
        onChanged();
      } else {
        resourceMappingsBuilder_.addMessage(index, builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
     */
    public Builder addAllResourceMappings(
        java.lang.Iterable<? extends io.opentdf.platform.policy.resourcemapping.ResourceMapping> values) {
      if (resourceMappingsBuilder_ == null) {
        ensureResourceMappingsIsMutable();
        com.google.protobuf.AbstractMessageLite.Builder.addAll(
            values, resourceMappings_);
        onChanged();
      } else {
        resourceMappingsBuilder_.addAllMessages(values);
      }
      return this;
    }
    /**
     * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
     */
    public Builder clearResourceMappings() {
      if (resourceMappingsBuilder_ == null) {
        resourceMappings_ = java.util.Collections.emptyList();
        bitField0_ = (bitField0_ & ~0x00000001);
        onChanged();
      } else {
        resourceMappingsBuilder_.clear();
      }
      return this;
    }
    /**
     * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
     */
    public Builder removeResourceMappings(int index) {
      if (resourceMappingsBuilder_ == null) {
        ensureResourceMappingsIsMutable();
        resourceMappings_.remove(index);
        onChanged();
      } else {
        resourceMappingsBuilder_.remove(index);
      }
      return this;
    }
    /**
     * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
     */
    public io.opentdf.platform.policy.resourcemapping.ResourceMapping.Builder getResourceMappingsBuilder(
        int index) {
      return getResourceMappingsFieldBuilder().getBuilder(index);
    }
    /**
     * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
     */
    public io.opentdf.platform.policy.resourcemapping.ResourceMappingOrBuilder getResourceMappingsOrBuilder(
        int index) {
      if (resourceMappingsBuilder_ == null) {
        return resourceMappings_.get(index);  } else {
        return resourceMappingsBuilder_.getMessageOrBuilder(index);
      }
    }
    /**
     * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
     */
    public java.util.List<? extends io.opentdf.platform.policy.resourcemapping.ResourceMappingOrBuilder> 
         getResourceMappingsOrBuilderList() {
      if (resourceMappingsBuilder_ != null) {
        return resourceMappingsBuilder_.getMessageOrBuilderList();
      } else {
        return java.util.Collections.unmodifiableList(resourceMappings_);
      }
    }
    /**
     * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
     */
    public io.opentdf.platform.policy.resourcemapping.ResourceMapping.Builder addResourceMappingsBuilder() {
      return getResourceMappingsFieldBuilder().addBuilder(
          io.opentdf.platform.policy.resourcemapping.ResourceMapping.getDefaultInstance());
    }
    /**
     * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
     */
    public io.opentdf.platform.policy.resourcemapping.ResourceMapping.Builder addResourceMappingsBuilder(
        int index) {
      return getResourceMappingsFieldBuilder().addBuilder(
          index, io.opentdf.platform.policy.resourcemapping.ResourceMapping.getDefaultInstance());
    }
    /**
     * <code>repeated .policy.resourcemapping.ResourceMapping resource_mappings = 1 [json_name = "resourceMappings"];</code>
     */
    public java.util.List<io.opentdf.platform.policy.resourcemapping.ResourceMapping.Builder> 
         getResourceMappingsBuilderList() {
      return getResourceMappingsFieldBuilder().getBuilderList();
    }
    private com.google.protobuf.RepeatedFieldBuilderV3<
        io.opentdf.platform.policy.resourcemapping.ResourceMapping, io.opentdf.platform.policy.resourcemapping.ResourceMapping.Builder, io.opentdf.platform.policy.resourcemapping.ResourceMappingOrBuilder> 
        getResourceMappingsFieldBuilder() {
      if (resourceMappingsBuilder_ == null) {
        resourceMappingsBuilder_ = new com.google.protobuf.RepeatedFieldBuilderV3<
            io.opentdf.platform.policy.resourcemapping.ResourceMapping, io.opentdf.platform.policy.resourcemapping.ResourceMapping.Builder, io.opentdf.platform.policy.resourcemapping.ResourceMappingOrBuilder>(
                resourceMappings_,
                ((bitField0_ & 0x00000001) != 0),
                getParentForChildren(),
                isClean());
        resourceMappings_ = null;
      }
      return resourceMappingsBuilder_;
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


    // @@protoc_insertion_point(builder_scope:policy.resourcemapping.ListResourceMappingsResponse)
  }

  // @@protoc_insertion_point(class_scope:policy.resourcemapping.ListResourceMappingsResponse)
  private static final io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse();
  }

  public static io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<ListResourceMappingsResponse>
      PARSER = new com.google.protobuf.AbstractParser<ListResourceMappingsResponse>() {
    @java.lang.Override
    public ListResourceMappingsResponse parsePartialFrom(
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

  public static com.google.protobuf.Parser<ListResourceMappingsResponse> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<ListResourceMappingsResponse> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public io.opentdf.platform.policy.resourcemapping.ListResourceMappingsResponse getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

