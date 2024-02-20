// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/resourcemapping/resource_mapping.proto

// Protobuf Java Version: 3.25.3
package com.policy.resourcemapping;

/**
 * Protobuf type {@code policy.resourcemapping.ResourceMappingCreateUpdate}
 */
public final class ResourceMappingCreateUpdate extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:policy.resourcemapping.ResourceMappingCreateUpdate)
    ResourceMappingCreateUpdateOrBuilder {
private static final long serialVersionUID = 0L;
  // Use ResourceMappingCreateUpdate.newBuilder() to construct.
  private ResourceMappingCreateUpdate(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private ResourceMappingCreateUpdate() {
    attributeValueId_ = "";
    terms_ =
        com.google.protobuf.LazyStringArrayList.emptyList();
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new ResourceMappingCreateUpdate();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return com.policy.resourcemapping.ResourceMappingProto.internal_static_policy_resourcemapping_ResourceMappingCreateUpdate_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return com.policy.resourcemapping.ResourceMappingProto.internal_static_policy_resourcemapping_ResourceMappingCreateUpdate_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            com.policy.resourcemapping.ResourceMappingCreateUpdate.class, com.policy.resourcemapping.ResourceMappingCreateUpdate.Builder.class);
  }

  private int bitField0_;
  public static final int METADATA_FIELD_NUMBER = 1;
  private com.common.MetadataMutable metadata_;
  /**
   * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
   * @return Whether the metadata field is set.
   */
  @java.lang.Override
  public boolean hasMetadata() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
   * @return The metadata.
   */
  @java.lang.Override
  public com.common.MetadataMutable getMetadata() {
    return metadata_ == null ? com.common.MetadataMutable.getDefaultInstance() : metadata_;
  }
  /**
   * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
   */
  @java.lang.Override
  public com.common.MetadataMutableOrBuilder getMetadataOrBuilder() {
    return metadata_ == null ? com.common.MetadataMutable.getDefaultInstance() : metadata_;
  }

  public static final int ATTRIBUTE_VALUE_ID_FIELD_NUMBER = 2;
  @SuppressWarnings("serial")
  private volatile java.lang.Object attributeValueId_ = "";
  /**
   * <code>string attribute_value_id = 2 [json_name = "attributeValueId"];</code>
   * @return The attributeValueId.
   */
  @java.lang.Override
  public java.lang.String getAttributeValueId() {
    java.lang.Object ref = attributeValueId_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      attributeValueId_ = s;
      return s;
    }
  }
  /**
   * <code>string attribute_value_id = 2 [json_name = "attributeValueId"];</code>
   * @return The bytes for attributeValueId.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString
      getAttributeValueIdBytes() {
    java.lang.Object ref = attributeValueId_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      attributeValueId_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int TERMS_FIELD_NUMBER = 3;
  @SuppressWarnings("serial")
  private com.google.protobuf.LazyStringArrayList terms_ =
      com.google.protobuf.LazyStringArrayList.emptyList();
  /**
   * <code>repeated string terms = 3 [json_name = "terms"];</code>
   * @return A list containing the terms.
   */
  public com.google.protobuf.ProtocolStringList
      getTermsList() {
    return terms_;
  }
  /**
   * <code>repeated string terms = 3 [json_name = "terms"];</code>
   * @return The count of terms.
   */
  public int getTermsCount() {
    return terms_.size();
  }
  /**
   * <code>repeated string terms = 3 [json_name = "terms"];</code>
   * @param index The index of the element to return.
   * @return The terms at the given index.
   */
  public java.lang.String getTerms(int index) {
    return terms_.get(index);
  }
  /**
   * <code>repeated string terms = 3 [json_name = "terms"];</code>
   * @param index The index of the value to return.
   * @return The bytes of the terms at the given index.
   */
  public com.google.protobuf.ByteString
      getTermsBytes(int index) {
    return terms_.getByteString(index);
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
      output.writeMessage(1, getMetadata());
    }
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(attributeValueId_)) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 2, attributeValueId_);
    }
    for (int i = 0; i < terms_.size(); i++) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 3, terms_.getRaw(i));
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
        .computeMessageSize(1, getMetadata());
    }
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(attributeValueId_)) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(2, attributeValueId_);
    }
    {
      int dataSize = 0;
      for (int i = 0; i < terms_.size(); i++) {
        dataSize += computeStringSizeNoTag(terms_.getRaw(i));
      }
      size += dataSize;
      size += 1 * getTermsList().size();
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
    if (!(obj instanceof com.policy.resourcemapping.ResourceMappingCreateUpdate)) {
      return super.equals(obj);
    }
    com.policy.resourcemapping.ResourceMappingCreateUpdate other = (com.policy.resourcemapping.ResourceMappingCreateUpdate) obj;

    if (hasMetadata() != other.hasMetadata()) return false;
    if (hasMetadata()) {
      if (!getMetadata()
          .equals(other.getMetadata())) return false;
    }
    if (!getAttributeValueId()
        .equals(other.getAttributeValueId())) return false;
    if (!getTermsList()
        .equals(other.getTermsList())) return false;
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
    if (hasMetadata()) {
      hash = (37 * hash) + METADATA_FIELD_NUMBER;
      hash = (53 * hash) + getMetadata().hashCode();
    }
    hash = (37 * hash) + ATTRIBUTE_VALUE_ID_FIELD_NUMBER;
    hash = (53 * hash) + getAttributeValueId().hashCode();
    if (getTermsCount() > 0) {
      hash = (37 * hash) + TERMS_FIELD_NUMBER;
      hash = (53 * hash) + getTermsList().hashCode();
    }
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static com.policy.resourcemapping.ResourceMappingCreateUpdate parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.policy.resourcemapping.ResourceMappingCreateUpdate parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.policy.resourcemapping.ResourceMappingCreateUpdate parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.policy.resourcemapping.ResourceMappingCreateUpdate parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.policy.resourcemapping.ResourceMappingCreateUpdate parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.policy.resourcemapping.ResourceMappingCreateUpdate parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.policy.resourcemapping.ResourceMappingCreateUpdate parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.policy.resourcemapping.ResourceMappingCreateUpdate parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static com.policy.resourcemapping.ResourceMappingCreateUpdate parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static com.policy.resourcemapping.ResourceMappingCreateUpdate parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static com.policy.resourcemapping.ResourceMappingCreateUpdate parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.policy.resourcemapping.ResourceMappingCreateUpdate parseFrom(
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
  public static Builder newBuilder(com.policy.resourcemapping.ResourceMappingCreateUpdate prototype) {
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
   * Protobuf type {@code policy.resourcemapping.ResourceMappingCreateUpdate}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:policy.resourcemapping.ResourceMappingCreateUpdate)
      com.policy.resourcemapping.ResourceMappingCreateUpdateOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return com.policy.resourcemapping.ResourceMappingProto.internal_static_policy_resourcemapping_ResourceMappingCreateUpdate_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return com.policy.resourcemapping.ResourceMappingProto.internal_static_policy_resourcemapping_ResourceMappingCreateUpdate_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              com.policy.resourcemapping.ResourceMappingCreateUpdate.class, com.policy.resourcemapping.ResourceMappingCreateUpdate.Builder.class);
    }

    // Construct using com.policy.resourcemapping.ResourceMappingCreateUpdate.newBuilder()
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
        getMetadataFieldBuilder();
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      bitField0_ = 0;
      metadata_ = null;
      if (metadataBuilder_ != null) {
        metadataBuilder_.dispose();
        metadataBuilder_ = null;
      }
      attributeValueId_ = "";
      terms_ =
          com.google.protobuf.LazyStringArrayList.emptyList();
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return com.policy.resourcemapping.ResourceMappingProto.internal_static_policy_resourcemapping_ResourceMappingCreateUpdate_descriptor;
    }

    @java.lang.Override
    public com.policy.resourcemapping.ResourceMappingCreateUpdate getDefaultInstanceForType() {
      return com.policy.resourcemapping.ResourceMappingCreateUpdate.getDefaultInstance();
    }

    @java.lang.Override
    public com.policy.resourcemapping.ResourceMappingCreateUpdate build() {
      com.policy.resourcemapping.ResourceMappingCreateUpdate result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public com.policy.resourcemapping.ResourceMappingCreateUpdate buildPartial() {
      com.policy.resourcemapping.ResourceMappingCreateUpdate result = new com.policy.resourcemapping.ResourceMappingCreateUpdate(this);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartial0(com.policy.resourcemapping.ResourceMappingCreateUpdate result) {
      int from_bitField0_ = bitField0_;
      int to_bitField0_ = 0;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        result.metadata_ = metadataBuilder_ == null
            ? metadata_
            : metadataBuilder_.build();
        to_bitField0_ |= 0x00000001;
      }
      if (((from_bitField0_ & 0x00000002) != 0)) {
        result.attributeValueId_ = attributeValueId_;
      }
      if (((from_bitField0_ & 0x00000004) != 0)) {
        terms_.makeImmutable();
        result.terms_ = terms_;
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
      if (other instanceof com.policy.resourcemapping.ResourceMappingCreateUpdate) {
        return mergeFrom((com.policy.resourcemapping.ResourceMappingCreateUpdate)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(com.policy.resourcemapping.ResourceMappingCreateUpdate other) {
      if (other == com.policy.resourcemapping.ResourceMappingCreateUpdate.getDefaultInstance()) return this;
      if (other.hasMetadata()) {
        mergeMetadata(other.getMetadata());
      }
      if (!other.getAttributeValueId().isEmpty()) {
        attributeValueId_ = other.attributeValueId_;
        bitField0_ |= 0x00000002;
        onChanged();
      }
      if (!other.terms_.isEmpty()) {
        if (terms_.isEmpty()) {
          terms_ = other.terms_;
          bitField0_ |= 0x00000004;
        } else {
          ensureTermsIsMutable();
          terms_.addAll(other.terms_);
        }
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
              input.readMessage(
                  getMetadataFieldBuilder().getBuilder(),
                  extensionRegistry);
              bitField0_ |= 0x00000001;
              break;
            } // case 10
            case 18: {
              attributeValueId_ = input.readStringRequireUtf8();
              bitField0_ |= 0x00000002;
              break;
            } // case 18
            case 26: {
              java.lang.String s = input.readStringRequireUtf8();
              ensureTermsIsMutable();
              terms_.add(s);
              break;
            } // case 26
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

    private com.common.MetadataMutable metadata_;
    private com.google.protobuf.SingleFieldBuilderV3<
        com.common.MetadataMutable, com.common.MetadataMutable.Builder, com.common.MetadataMutableOrBuilder> metadataBuilder_;
    /**
     * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
     * @return Whether the metadata field is set.
     */
    public boolean hasMetadata() {
      return ((bitField0_ & 0x00000001) != 0);
    }
    /**
     * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
     * @return The metadata.
     */
    public com.common.MetadataMutable getMetadata() {
      if (metadataBuilder_ == null) {
        return metadata_ == null ? com.common.MetadataMutable.getDefaultInstance() : metadata_;
      } else {
        return metadataBuilder_.getMessage();
      }
    }
    /**
     * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
     */
    public Builder setMetadata(com.common.MetadataMutable value) {
      if (metadataBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        metadata_ = value;
      } else {
        metadataBuilder_.setMessage(value);
      }
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
     */
    public Builder setMetadata(
        com.common.MetadataMutable.Builder builderForValue) {
      if (metadataBuilder_ == null) {
        metadata_ = builderForValue.build();
      } else {
        metadataBuilder_.setMessage(builderForValue.build());
      }
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
     */
    public Builder mergeMetadata(com.common.MetadataMutable value) {
      if (metadataBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0) &&
          metadata_ != null &&
          metadata_ != com.common.MetadataMutable.getDefaultInstance()) {
          getMetadataBuilder().mergeFrom(value);
        } else {
          metadata_ = value;
        }
      } else {
        metadataBuilder_.mergeFrom(value);
      }
      if (metadata_ != null) {
        bitField0_ |= 0x00000001;
        onChanged();
      }
      return this;
    }
    /**
     * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
     */
    public Builder clearMetadata() {
      bitField0_ = (bitField0_ & ~0x00000001);
      metadata_ = null;
      if (metadataBuilder_ != null) {
        metadataBuilder_.dispose();
        metadataBuilder_ = null;
      }
      onChanged();
      return this;
    }
    /**
     * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
     */
    public com.common.MetadataMutable.Builder getMetadataBuilder() {
      bitField0_ |= 0x00000001;
      onChanged();
      return getMetadataFieldBuilder().getBuilder();
    }
    /**
     * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
     */
    public com.common.MetadataMutableOrBuilder getMetadataOrBuilder() {
      if (metadataBuilder_ != null) {
        return metadataBuilder_.getMessageOrBuilder();
      } else {
        return metadata_ == null ?
            com.common.MetadataMutable.getDefaultInstance() : metadata_;
      }
    }
    /**
     * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
     */
    private com.google.protobuf.SingleFieldBuilderV3<
        com.common.MetadataMutable, com.common.MetadataMutable.Builder, com.common.MetadataMutableOrBuilder> 
        getMetadataFieldBuilder() {
      if (metadataBuilder_ == null) {
        metadataBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
            com.common.MetadataMutable, com.common.MetadataMutable.Builder, com.common.MetadataMutableOrBuilder>(
                getMetadata(),
                getParentForChildren(),
                isClean());
        metadata_ = null;
      }
      return metadataBuilder_;
    }

    private java.lang.Object attributeValueId_ = "";
    /**
     * <code>string attribute_value_id = 2 [json_name = "attributeValueId"];</code>
     * @return The attributeValueId.
     */
    public java.lang.String getAttributeValueId() {
      java.lang.Object ref = attributeValueId_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        attributeValueId_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>string attribute_value_id = 2 [json_name = "attributeValueId"];</code>
     * @return The bytes for attributeValueId.
     */
    public com.google.protobuf.ByteString
        getAttributeValueIdBytes() {
      java.lang.Object ref = attributeValueId_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        attributeValueId_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>string attribute_value_id = 2 [json_name = "attributeValueId"];</code>
     * @param value The attributeValueId to set.
     * @return This builder for chaining.
     */
    public Builder setAttributeValueId(
        java.lang.String value) {
      if (value == null) { throw new NullPointerException(); }
      attributeValueId_ = value;
      bitField0_ |= 0x00000002;
      onChanged();
      return this;
    }
    /**
     * <code>string attribute_value_id = 2 [json_name = "attributeValueId"];</code>
     * @return This builder for chaining.
     */
    public Builder clearAttributeValueId() {
      attributeValueId_ = getDefaultInstance().getAttributeValueId();
      bitField0_ = (bitField0_ & ~0x00000002);
      onChanged();
      return this;
    }
    /**
     * <code>string attribute_value_id = 2 [json_name = "attributeValueId"];</code>
     * @param value The bytes for attributeValueId to set.
     * @return This builder for chaining.
     */
    public Builder setAttributeValueIdBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) { throw new NullPointerException(); }
      checkByteStringIsUtf8(value);
      attributeValueId_ = value;
      bitField0_ |= 0x00000002;
      onChanged();
      return this;
    }

    private com.google.protobuf.LazyStringArrayList terms_ =
        com.google.protobuf.LazyStringArrayList.emptyList();
    private void ensureTermsIsMutable() {
      if (!terms_.isModifiable()) {
        terms_ = new com.google.protobuf.LazyStringArrayList(terms_);
      }
      bitField0_ |= 0x00000004;
    }
    /**
     * <code>repeated string terms = 3 [json_name = "terms"];</code>
     * @return A list containing the terms.
     */
    public com.google.protobuf.ProtocolStringList
        getTermsList() {
      terms_.makeImmutable();
      return terms_;
    }
    /**
     * <code>repeated string terms = 3 [json_name = "terms"];</code>
     * @return The count of terms.
     */
    public int getTermsCount() {
      return terms_.size();
    }
    /**
     * <code>repeated string terms = 3 [json_name = "terms"];</code>
     * @param index The index of the element to return.
     * @return The terms at the given index.
     */
    public java.lang.String getTerms(int index) {
      return terms_.get(index);
    }
    /**
     * <code>repeated string terms = 3 [json_name = "terms"];</code>
     * @param index The index of the value to return.
     * @return The bytes of the terms at the given index.
     */
    public com.google.protobuf.ByteString
        getTermsBytes(int index) {
      return terms_.getByteString(index);
    }
    /**
     * <code>repeated string terms = 3 [json_name = "terms"];</code>
     * @param index The index to set the value at.
     * @param value The terms to set.
     * @return This builder for chaining.
     */
    public Builder setTerms(
        int index, java.lang.String value) {
      if (value == null) { throw new NullPointerException(); }
      ensureTermsIsMutable();
      terms_.set(index, value);
      bitField0_ |= 0x00000004;
      onChanged();
      return this;
    }
    /**
     * <code>repeated string terms = 3 [json_name = "terms"];</code>
     * @param value The terms to add.
     * @return This builder for chaining.
     */
    public Builder addTerms(
        java.lang.String value) {
      if (value == null) { throw new NullPointerException(); }
      ensureTermsIsMutable();
      terms_.add(value);
      bitField0_ |= 0x00000004;
      onChanged();
      return this;
    }
    /**
     * <code>repeated string terms = 3 [json_name = "terms"];</code>
     * @param values The terms to add.
     * @return This builder for chaining.
     */
    public Builder addAllTerms(
        java.lang.Iterable<java.lang.String> values) {
      ensureTermsIsMutable();
      com.google.protobuf.AbstractMessageLite.Builder.addAll(
          values, terms_);
      bitField0_ |= 0x00000004;
      onChanged();
      return this;
    }
    /**
     * <code>repeated string terms = 3 [json_name = "terms"];</code>
     * @return This builder for chaining.
     */
    public Builder clearTerms() {
      terms_ =
        com.google.protobuf.LazyStringArrayList.emptyList();
      bitField0_ = (bitField0_ & ~0x00000004);;
      onChanged();
      return this;
    }
    /**
     * <code>repeated string terms = 3 [json_name = "terms"];</code>
     * @param value The bytes of the terms to add.
     * @return This builder for chaining.
     */
    public Builder addTermsBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) { throw new NullPointerException(); }
      checkByteStringIsUtf8(value);
      ensureTermsIsMutable();
      terms_.add(value);
      bitField0_ |= 0x00000004;
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


    // @@protoc_insertion_point(builder_scope:policy.resourcemapping.ResourceMappingCreateUpdate)
  }

  // @@protoc_insertion_point(class_scope:policy.resourcemapping.ResourceMappingCreateUpdate)
  private static final com.policy.resourcemapping.ResourceMappingCreateUpdate DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new com.policy.resourcemapping.ResourceMappingCreateUpdate();
  }

  public static com.policy.resourcemapping.ResourceMappingCreateUpdate getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<ResourceMappingCreateUpdate>
      PARSER = new com.google.protobuf.AbstractParser<ResourceMappingCreateUpdate>() {
    @java.lang.Override
    public ResourceMappingCreateUpdate parsePartialFrom(
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

  public static com.google.protobuf.Parser<ResourceMappingCreateUpdate> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<ResourceMappingCreateUpdate> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public com.policy.resourcemapping.ResourceMappingCreateUpdate getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

