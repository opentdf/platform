// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/resourcemapping/resource_mapping.proto

// Protobuf Java Version: 3.25.3
package com.policy.resourcemapping;

/**
 * Protobuf type {@code policy.resourcemapping.UpdateResourceMappingResponse}
 */
public final class UpdateResourceMappingResponse extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:policy.resourcemapping.UpdateResourceMappingResponse)
    UpdateResourceMappingResponseOrBuilder {
private static final long serialVersionUID = 0L;
  // Use UpdateResourceMappingResponse.newBuilder() to construct.
  private UpdateResourceMappingResponse(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private UpdateResourceMappingResponse() {
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new UpdateResourceMappingResponse();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return com.policy.resourcemapping.ResourceMappingProto.internal_static_policy_resourcemapping_UpdateResourceMappingResponse_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return com.policy.resourcemapping.ResourceMappingProto.internal_static_policy_resourcemapping_UpdateResourceMappingResponse_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            com.policy.resourcemapping.UpdateResourceMappingResponse.class, com.policy.resourcemapping.UpdateResourceMappingResponse.Builder.class);
  }

  private int bitField0_;
  public static final int RESOURCE_MAPPING_FIELD_NUMBER = 1;
  private com.policy.resourcemapping.ResourceMapping resourceMapping_;
  /**
   * <code>.policy.resourcemapping.ResourceMapping resource_mapping = 1 [json_name = "resourceMapping"];</code>
   * @return Whether the resourceMapping field is set.
   */
  @java.lang.Override
  public boolean hasResourceMapping() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <code>.policy.resourcemapping.ResourceMapping resource_mapping = 1 [json_name = "resourceMapping"];</code>
   * @return The resourceMapping.
   */
  @java.lang.Override
  public com.policy.resourcemapping.ResourceMapping getResourceMapping() {
    return resourceMapping_ == null ? com.policy.resourcemapping.ResourceMapping.getDefaultInstance() : resourceMapping_;
  }
  /**
   * <code>.policy.resourcemapping.ResourceMapping resource_mapping = 1 [json_name = "resourceMapping"];</code>
   */
  @java.lang.Override
  public com.policy.resourcemapping.ResourceMappingOrBuilder getResourceMappingOrBuilder() {
    return resourceMapping_ == null ? com.policy.resourcemapping.ResourceMapping.getDefaultInstance() : resourceMapping_;
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
      output.writeMessage(1, getResourceMapping());
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
        .computeMessageSize(1, getResourceMapping());
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
    if (!(obj instanceof com.policy.resourcemapping.UpdateResourceMappingResponse)) {
      return super.equals(obj);
    }
    com.policy.resourcemapping.UpdateResourceMappingResponse other = (com.policy.resourcemapping.UpdateResourceMappingResponse) obj;

    if (hasResourceMapping() != other.hasResourceMapping()) return false;
    if (hasResourceMapping()) {
      if (!getResourceMapping()
          .equals(other.getResourceMapping())) return false;
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
    if (hasResourceMapping()) {
      hash = (37 * hash) + RESOURCE_MAPPING_FIELD_NUMBER;
      hash = (53 * hash) + getResourceMapping().hashCode();
    }
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static com.policy.resourcemapping.UpdateResourceMappingResponse parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.policy.resourcemapping.UpdateResourceMappingResponse parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.policy.resourcemapping.UpdateResourceMappingResponse parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.policy.resourcemapping.UpdateResourceMappingResponse parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.policy.resourcemapping.UpdateResourceMappingResponse parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.policy.resourcemapping.UpdateResourceMappingResponse parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.policy.resourcemapping.UpdateResourceMappingResponse parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.policy.resourcemapping.UpdateResourceMappingResponse parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static com.policy.resourcemapping.UpdateResourceMappingResponse parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static com.policy.resourcemapping.UpdateResourceMappingResponse parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static com.policy.resourcemapping.UpdateResourceMappingResponse parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.policy.resourcemapping.UpdateResourceMappingResponse parseFrom(
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
  public static Builder newBuilder(com.policy.resourcemapping.UpdateResourceMappingResponse prototype) {
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
   * Protobuf type {@code policy.resourcemapping.UpdateResourceMappingResponse}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:policy.resourcemapping.UpdateResourceMappingResponse)
      com.policy.resourcemapping.UpdateResourceMappingResponseOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return com.policy.resourcemapping.ResourceMappingProto.internal_static_policy_resourcemapping_UpdateResourceMappingResponse_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return com.policy.resourcemapping.ResourceMappingProto.internal_static_policy_resourcemapping_UpdateResourceMappingResponse_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              com.policy.resourcemapping.UpdateResourceMappingResponse.class, com.policy.resourcemapping.UpdateResourceMappingResponse.Builder.class);
    }

    // Construct using com.policy.resourcemapping.UpdateResourceMappingResponse.newBuilder()
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
        getResourceMappingFieldBuilder();
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      bitField0_ = 0;
      resourceMapping_ = null;
      if (resourceMappingBuilder_ != null) {
        resourceMappingBuilder_.dispose();
        resourceMappingBuilder_ = null;
      }
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return com.policy.resourcemapping.ResourceMappingProto.internal_static_policy_resourcemapping_UpdateResourceMappingResponse_descriptor;
    }

    @java.lang.Override
    public com.policy.resourcemapping.UpdateResourceMappingResponse getDefaultInstanceForType() {
      return com.policy.resourcemapping.UpdateResourceMappingResponse.getDefaultInstance();
    }

    @java.lang.Override
    public com.policy.resourcemapping.UpdateResourceMappingResponse build() {
      com.policy.resourcemapping.UpdateResourceMappingResponse result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public com.policy.resourcemapping.UpdateResourceMappingResponse buildPartial() {
      com.policy.resourcemapping.UpdateResourceMappingResponse result = new com.policy.resourcemapping.UpdateResourceMappingResponse(this);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartial0(com.policy.resourcemapping.UpdateResourceMappingResponse result) {
      int from_bitField0_ = bitField0_;
      int to_bitField0_ = 0;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        result.resourceMapping_ = resourceMappingBuilder_ == null
            ? resourceMapping_
            : resourceMappingBuilder_.build();
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
      if (other instanceof com.policy.resourcemapping.UpdateResourceMappingResponse) {
        return mergeFrom((com.policy.resourcemapping.UpdateResourceMappingResponse)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(com.policy.resourcemapping.UpdateResourceMappingResponse other) {
      if (other == com.policy.resourcemapping.UpdateResourceMappingResponse.getDefaultInstance()) return this;
      if (other.hasResourceMapping()) {
        mergeResourceMapping(other.getResourceMapping());
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
                  getResourceMappingFieldBuilder().getBuilder(),
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

    private com.policy.resourcemapping.ResourceMapping resourceMapping_;
    private com.google.protobuf.SingleFieldBuilderV3<
        com.policy.resourcemapping.ResourceMapping, com.policy.resourcemapping.ResourceMapping.Builder, com.policy.resourcemapping.ResourceMappingOrBuilder> resourceMappingBuilder_;
    /**
     * <code>.policy.resourcemapping.ResourceMapping resource_mapping = 1 [json_name = "resourceMapping"];</code>
     * @return Whether the resourceMapping field is set.
     */
    public boolean hasResourceMapping() {
      return ((bitField0_ & 0x00000001) != 0);
    }
    /**
     * <code>.policy.resourcemapping.ResourceMapping resource_mapping = 1 [json_name = "resourceMapping"];</code>
     * @return The resourceMapping.
     */
    public com.policy.resourcemapping.ResourceMapping getResourceMapping() {
      if (resourceMappingBuilder_ == null) {
        return resourceMapping_ == null ? com.policy.resourcemapping.ResourceMapping.getDefaultInstance() : resourceMapping_;
      } else {
        return resourceMappingBuilder_.getMessage();
      }
    }
    /**
     * <code>.policy.resourcemapping.ResourceMapping resource_mapping = 1 [json_name = "resourceMapping"];</code>
     */
    public Builder setResourceMapping(com.policy.resourcemapping.ResourceMapping value) {
      if (resourceMappingBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        resourceMapping_ = value;
      } else {
        resourceMappingBuilder_.setMessage(value);
      }
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>.policy.resourcemapping.ResourceMapping resource_mapping = 1 [json_name = "resourceMapping"];</code>
     */
    public Builder setResourceMapping(
        com.policy.resourcemapping.ResourceMapping.Builder builderForValue) {
      if (resourceMappingBuilder_ == null) {
        resourceMapping_ = builderForValue.build();
      } else {
        resourceMappingBuilder_.setMessage(builderForValue.build());
      }
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>.policy.resourcemapping.ResourceMapping resource_mapping = 1 [json_name = "resourceMapping"];</code>
     */
    public Builder mergeResourceMapping(com.policy.resourcemapping.ResourceMapping value) {
      if (resourceMappingBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0) &&
          resourceMapping_ != null &&
          resourceMapping_ != com.policy.resourcemapping.ResourceMapping.getDefaultInstance()) {
          getResourceMappingBuilder().mergeFrom(value);
        } else {
          resourceMapping_ = value;
        }
      } else {
        resourceMappingBuilder_.mergeFrom(value);
      }
      if (resourceMapping_ != null) {
        bitField0_ |= 0x00000001;
        onChanged();
      }
      return this;
    }
    /**
     * <code>.policy.resourcemapping.ResourceMapping resource_mapping = 1 [json_name = "resourceMapping"];</code>
     */
    public Builder clearResourceMapping() {
      bitField0_ = (bitField0_ & ~0x00000001);
      resourceMapping_ = null;
      if (resourceMappingBuilder_ != null) {
        resourceMappingBuilder_.dispose();
        resourceMappingBuilder_ = null;
      }
      onChanged();
      return this;
    }
    /**
     * <code>.policy.resourcemapping.ResourceMapping resource_mapping = 1 [json_name = "resourceMapping"];</code>
     */
    public com.policy.resourcemapping.ResourceMapping.Builder getResourceMappingBuilder() {
      bitField0_ |= 0x00000001;
      onChanged();
      return getResourceMappingFieldBuilder().getBuilder();
    }
    /**
     * <code>.policy.resourcemapping.ResourceMapping resource_mapping = 1 [json_name = "resourceMapping"];</code>
     */
    public com.policy.resourcemapping.ResourceMappingOrBuilder getResourceMappingOrBuilder() {
      if (resourceMappingBuilder_ != null) {
        return resourceMappingBuilder_.getMessageOrBuilder();
      } else {
        return resourceMapping_ == null ?
            com.policy.resourcemapping.ResourceMapping.getDefaultInstance() : resourceMapping_;
      }
    }
    /**
     * <code>.policy.resourcemapping.ResourceMapping resource_mapping = 1 [json_name = "resourceMapping"];</code>
     */
    private com.google.protobuf.SingleFieldBuilderV3<
        com.policy.resourcemapping.ResourceMapping, com.policy.resourcemapping.ResourceMapping.Builder, com.policy.resourcemapping.ResourceMappingOrBuilder> 
        getResourceMappingFieldBuilder() {
      if (resourceMappingBuilder_ == null) {
        resourceMappingBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
            com.policy.resourcemapping.ResourceMapping, com.policy.resourcemapping.ResourceMapping.Builder, com.policy.resourcemapping.ResourceMappingOrBuilder>(
                getResourceMapping(),
                getParentForChildren(),
                isClean());
        resourceMapping_ = null;
      }
      return resourceMappingBuilder_;
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


    // @@protoc_insertion_point(builder_scope:policy.resourcemapping.UpdateResourceMappingResponse)
  }

  // @@protoc_insertion_point(class_scope:policy.resourcemapping.UpdateResourceMappingResponse)
  private static final com.policy.resourcemapping.UpdateResourceMappingResponse DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new com.policy.resourcemapping.UpdateResourceMappingResponse();
  }

  public static com.policy.resourcemapping.UpdateResourceMappingResponse getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<UpdateResourceMappingResponse>
      PARSER = new com.google.protobuf.AbstractParser<UpdateResourceMappingResponse>() {
    @java.lang.Override
    public UpdateResourceMappingResponse parsePartialFrom(
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

  public static com.google.protobuf.Parser<UpdateResourceMappingResponse> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<UpdateResourceMappingResponse> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public com.policy.resourcemapping.UpdateResourceMappingResponse getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

