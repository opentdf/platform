// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: attributes/attributes.proto

// Protobuf Java Version: 3.25.2
package com.attributes;

/**
 * Protobuf type {@code attributes.ValueCreateUpdate}
 */
public final class ValueCreateUpdate extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:attributes.ValueCreateUpdate)
    ValueCreateUpdateOrBuilder {
private static final long serialVersionUID = 0L;
  // Use ValueCreateUpdate.newBuilder() to construct.
  private ValueCreateUpdate(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private ValueCreateUpdate() {
    value_ = "";
    members_ =
        com.google.protobuf.LazyStringArrayList.emptyList();
    fqn_ = "";
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new ValueCreateUpdate();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return com.attributes.AttributesProto.internal_static_attributes_ValueCreateUpdate_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return com.attributes.AttributesProto.internal_static_attributes_ValueCreateUpdate_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            com.attributes.ValueCreateUpdate.class, com.attributes.ValueCreateUpdate.Builder.class);
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

  public static final int VALUE_FIELD_NUMBER = 2;
  @SuppressWarnings("serial")
  private volatile java.lang.Object value_ = "";
  /**
   * <code>string value = 2 [json_name = "value"];</code>
   * @return The value.
   */
  @java.lang.Override
  public java.lang.String getValue() {
    java.lang.Object ref = value_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      value_ = s;
      return s;
    }
  }
  /**
   * <code>string value = 2 [json_name = "value"];</code>
   * @return The bytes for value.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString
      getValueBytes() {
    java.lang.Object ref = value_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      value_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int MEMBERS_FIELD_NUMBER = 3;
  @SuppressWarnings("serial")
  private com.google.protobuf.LazyStringArrayList members_ =
      com.google.protobuf.LazyStringArrayList.emptyList();
  /**
   * <pre>
   * list of attribute values that this value is related to (attribute group)
   * </pre>
   *
   * <code>repeated string members = 3 [json_name = "members"];</code>
   * @return A list containing the members.
   */
  public com.google.protobuf.ProtocolStringList
      getMembersList() {
    return members_;
  }
  /**
   * <pre>
   * list of attribute values that this value is related to (attribute group)
   * </pre>
   *
   * <code>repeated string members = 3 [json_name = "members"];</code>
   * @return The count of members.
   */
  public int getMembersCount() {
    return members_.size();
  }
  /**
   * <pre>
   * list of attribute values that this value is related to (attribute group)
   * </pre>
   *
   * <code>repeated string members = 3 [json_name = "members"];</code>
   * @param index The index of the element to return.
   * @return The members at the given index.
   */
  public java.lang.String getMembers(int index) {
    return members_.get(index);
  }
  /**
   * <pre>
   * list of attribute values that this value is related to (attribute group)
   * </pre>
   *
   * <code>repeated string members = 3 [json_name = "members"];</code>
   * @param index The index of the value to return.
   * @return The bytes of the members at the given index.
   */
  public com.google.protobuf.ByteString
      getMembersBytes(int index) {
    return members_.getByteString(index);
  }

  public static final int FQN_FIELD_NUMBER = 7;
  @SuppressWarnings("serial")
  private volatile java.lang.Object fqn_ = "";
  /**
   * <code>string fqn = 7 [json_name = "fqn"];</code>
   * @return The fqn.
   */
  @java.lang.Override
  public java.lang.String getFqn() {
    java.lang.Object ref = fqn_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      fqn_ = s;
      return s;
    }
  }
  /**
   * <code>string fqn = 7 [json_name = "fqn"];</code>
   * @return The bytes for fqn.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString
      getFqnBytes() {
    java.lang.Object ref = fqn_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      fqn_ = b;
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
    if (((bitField0_ & 0x00000001) != 0)) {
      output.writeMessage(1, getMetadata());
    }
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(value_)) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 2, value_);
    }
    for (int i = 0; i < members_.size(); i++) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 3, members_.getRaw(i));
    }
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(fqn_)) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 7, fqn_);
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
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(value_)) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(2, value_);
    }
    {
      int dataSize = 0;
      for (int i = 0; i < members_.size(); i++) {
        dataSize += computeStringSizeNoTag(members_.getRaw(i));
      }
      size += dataSize;
      size += 1 * getMembersList().size();
    }
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(fqn_)) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(7, fqn_);
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
    if (!(obj instanceof com.attributes.ValueCreateUpdate)) {
      return super.equals(obj);
    }
    com.attributes.ValueCreateUpdate other = (com.attributes.ValueCreateUpdate) obj;

    if (hasMetadata() != other.hasMetadata()) return false;
    if (hasMetadata()) {
      if (!getMetadata()
          .equals(other.getMetadata())) return false;
    }
    if (!getValue()
        .equals(other.getValue())) return false;
    if (!getMembersList()
        .equals(other.getMembersList())) return false;
    if (!getFqn()
        .equals(other.getFqn())) return false;
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
    hash = (37 * hash) + VALUE_FIELD_NUMBER;
    hash = (53 * hash) + getValue().hashCode();
    if (getMembersCount() > 0) {
      hash = (37 * hash) + MEMBERS_FIELD_NUMBER;
      hash = (53 * hash) + getMembersList().hashCode();
    }
    hash = (37 * hash) + FQN_FIELD_NUMBER;
    hash = (53 * hash) + getFqn().hashCode();
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static com.attributes.ValueCreateUpdate parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.attributes.ValueCreateUpdate parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.attributes.ValueCreateUpdate parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.attributes.ValueCreateUpdate parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.attributes.ValueCreateUpdate parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.attributes.ValueCreateUpdate parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.attributes.ValueCreateUpdate parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.attributes.ValueCreateUpdate parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static com.attributes.ValueCreateUpdate parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static com.attributes.ValueCreateUpdate parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static com.attributes.ValueCreateUpdate parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.attributes.ValueCreateUpdate parseFrom(
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
  public static Builder newBuilder(com.attributes.ValueCreateUpdate prototype) {
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
   * Protobuf type {@code attributes.ValueCreateUpdate}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:attributes.ValueCreateUpdate)
      com.attributes.ValueCreateUpdateOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return com.attributes.AttributesProto.internal_static_attributes_ValueCreateUpdate_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return com.attributes.AttributesProto.internal_static_attributes_ValueCreateUpdate_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              com.attributes.ValueCreateUpdate.class, com.attributes.ValueCreateUpdate.Builder.class);
    }

    // Construct using com.attributes.ValueCreateUpdate.newBuilder()
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
      value_ = "";
      members_ =
          com.google.protobuf.LazyStringArrayList.emptyList();
      fqn_ = "";
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return com.attributes.AttributesProto.internal_static_attributes_ValueCreateUpdate_descriptor;
    }

    @java.lang.Override
    public com.attributes.ValueCreateUpdate getDefaultInstanceForType() {
      return com.attributes.ValueCreateUpdate.getDefaultInstance();
    }

    @java.lang.Override
    public com.attributes.ValueCreateUpdate build() {
      com.attributes.ValueCreateUpdate result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public com.attributes.ValueCreateUpdate buildPartial() {
      com.attributes.ValueCreateUpdate result = new com.attributes.ValueCreateUpdate(this);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartial0(com.attributes.ValueCreateUpdate result) {
      int from_bitField0_ = bitField0_;
      int to_bitField0_ = 0;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        result.metadata_ = metadataBuilder_ == null
            ? metadata_
            : metadataBuilder_.build();
        to_bitField0_ |= 0x00000001;
      }
      if (((from_bitField0_ & 0x00000002) != 0)) {
        result.value_ = value_;
      }
      if (((from_bitField0_ & 0x00000004) != 0)) {
        members_.makeImmutable();
        result.members_ = members_;
      }
      if (((from_bitField0_ & 0x00000008) != 0)) {
        result.fqn_ = fqn_;
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
      if (other instanceof com.attributes.ValueCreateUpdate) {
        return mergeFrom((com.attributes.ValueCreateUpdate)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(com.attributes.ValueCreateUpdate other) {
      if (other == com.attributes.ValueCreateUpdate.getDefaultInstance()) return this;
      if (other.hasMetadata()) {
        mergeMetadata(other.getMetadata());
      }
      if (!other.getValue().isEmpty()) {
        value_ = other.value_;
        bitField0_ |= 0x00000002;
        onChanged();
      }
      if (!other.members_.isEmpty()) {
        if (members_.isEmpty()) {
          members_ = other.members_;
          bitField0_ |= 0x00000004;
        } else {
          ensureMembersIsMutable();
          members_.addAll(other.members_);
        }
        onChanged();
      }
      if (!other.getFqn().isEmpty()) {
        fqn_ = other.fqn_;
        bitField0_ |= 0x00000008;
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
              value_ = input.readStringRequireUtf8();
              bitField0_ |= 0x00000002;
              break;
            } // case 18
            case 26: {
              java.lang.String s = input.readStringRequireUtf8();
              ensureMembersIsMutable();
              members_.add(s);
              break;
            } // case 26
            case 58: {
              fqn_ = input.readStringRequireUtf8();
              bitField0_ |= 0x00000008;
              break;
            } // case 58
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

    private java.lang.Object value_ = "";
    /**
     * <code>string value = 2 [json_name = "value"];</code>
     * @return The value.
     */
    public java.lang.String getValue() {
      java.lang.Object ref = value_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        value_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>string value = 2 [json_name = "value"];</code>
     * @return The bytes for value.
     */
    public com.google.protobuf.ByteString
        getValueBytes() {
      java.lang.Object ref = value_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        value_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>string value = 2 [json_name = "value"];</code>
     * @param value The value to set.
     * @return This builder for chaining.
     */
    public Builder setValue(
        java.lang.String value) {
      if (value == null) { throw new NullPointerException(); }
      value_ = value;
      bitField0_ |= 0x00000002;
      onChanged();
      return this;
    }
    /**
     * <code>string value = 2 [json_name = "value"];</code>
     * @return This builder for chaining.
     */
    public Builder clearValue() {
      value_ = getDefaultInstance().getValue();
      bitField0_ = (bitField0_ & ~0x00000002);
      onChanged();
      return this;
    }
    /**
     * <code>string value = 2 [json_name = "value"];</code>
     * @param value The bytes for value to set.
     * @return This builder for chaining.
     */
    public Builder setValueBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) { throw new NullPointerException(); }
      checkByteStringIsUtf8(value);
      value_ = value;
      bitField0_ |= 0x00000002;
      onChanged();
      return this;
    }

    private com.google.protobuf.LazyStringArrayList members_ =
        com.google.protobuf.LazyStringArrayList.emptyList();
    private void ensureMembersIsMutable() {
      if (!members_.isModifiable()) {
        members_ = new com.google.protobuf.LazyStringArrayList(members_);
      }
      bitField0_ |= 0x00000004;
    }
    /**
     * <pre>
     * list of attribute values that this value is related to (attribute group)
     * </pre>
     *
     * <code>repeated string members = 3 [json_name = "members"];</code>
     * @return A list containing the members.
     */
    public com.google.protobuf.ProtocolStringList
        getMembersList() {
      members_.makeImmutable();
      return members_;
    }
    /**
     * <pre>
     * list of attribute values that this value is related to (attribute group)
     * </pre>
     *
     * <code>repeated string members = 3 [json_name = "members"];</code>
     * @return The count of members.
     */
    public int getMembersCount() {
      return members_.size();
    }
    /**
     * <pre>
     * list of attribute values that this value is related to (attribute group)
     * </pre>
     *
     * <code>repeated string members = 3 [json_name = "members"];</code>
     * @param index The index of the element to return.
     * @return The members at the given index.
     */
    public java.lang.String getMembers(int index) {
      return members_.get(index);
    }
    /**
     * <pre>
     * list of attribute values that this value is related to (attribute group)
     * </pre>
     *
     * <code>repeated string members = 3 [json_name = "members"];</code>
     * @param index The index of the value to return.
     * @return The bytes of the members at the given index.
     */
    public com.google.protobuf.ByteString
        getMembersBytes(int index) {
      return members_.getByteString(index);
    }
    /**
     * <pre>
     * list of attribute values that this value is related to (attribute group)
     * </pre>
     *
     * <code>repeated string members = 3 [json_name = "members"];</code>
     * @param index The index to set the value at.
     * @param value The members to set.
     * @return This builder for chaining.
     */
    public Builder setMembers(
        int index, java.lang.String value) {
      if (value == null) { throw new NullPointerException(); }
      ensureMembersIsMutable();
      members_.set(index, value);
      bitField0_ |= 0x00000004;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * list of attribute values that this value is related to (attribute group)
     * </pre>
     *
     * <code>repeated string members = 3 [json_name = "members"];</code>
     * @param value The members to add.
     * @return This builder for chaining.
     */
    public Builder addMembers(
        java.lang.String value) {
      if (value == null) { throw new NullPointerException(); }
      ensureMembersIsMutable();
      members_.add(value);
      bitField0_ |= 0x00000004;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * list of attribute values that this value is related to (attribute group)
     * </pre>
     *
     * <code>repeated string members = 3 [json_name = "members"];</code>
     * @param values The members to add.
     * @return This builder for chaining.
     */
    public Builder addAllMembers(
        java.lang.Iterable<java.lang.String> values) {
      ensureMembersIsMutable();
      com.google.protobuf.AbstractMessageLite.Builder.addAll(
          values, members_);
      bitField0_ |= 0x00000004;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * list of attribute values that this value is related to (attribute group)
     * </pre>
     *
     * <code>repeated string members = 3 [json_name = "members"];</code>
     * @return This builder for chaining.
     */
    public Builder clearMembers() {
      members_ =
        com.google.protobuf.LazyStringArrayList.emptyList();
      bitField0_ = (bitField0_ & ~0x00000004);;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * list of attribute values that this value is related to (attribute group)
     * </pre>
     *
     * <code>repeated string members = 3 [json_name = "members"];</code>
     * @param value The bytes of the members to add.
     * @return This builder for chaining.
     */
    public Builder addMembersBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) { throw new NullPointerException(); }
      checkByteStringIsUtf8(value);
      ensureMembersIsMutable();
      members_.add(value);
      bitField0_ |= 0x00000004;
      onChanged();
      return this;
    }

    private java.lang.Object fqn_ = "";
    /**
     * <code>string fqn = 7 [json_name = "fqn"];</code>
     * @return The fqn.
     */
    public java.lang.String getFqn() {
      java.lang.Object ref = fqn_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        fqn_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>string fqn = 7 [json_name = "fqn"];</code>
     * @return The bytes for fqn.
     */
    public com.google.protobuf.ByteString
        getFqnBytes() {
      java.lang.Object ref = fqn_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        fqn_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>string fqn = 7 [json_name = "fqn"];</code>
     * @param value The fqn to set.
     * @return This builder for chaining.
     */
    public Builder setFqn(
        java.lang.String value) {
      if (value == null) { throw new NullPointerException(); }
      fqn_ = value;
      bitField0_ |= 0x00000008;
      onChanged();
      return this;
    }
    /**
     * <code>string fqn = 7 [json_name = "fqn"];</code>
     * @return This builder for chaining.
     */
    public Builder clearFqn() {
      fqn_ = getDefaultInstance().getFqn();
      bitField0_ = (bitField0_ & ~0x00000008);
      onChanged();
      return this;
    }
    /**
     * <code>string fqn = 7 [json_name = "fqn"];</code>
     * @param value The bytes for fqn to set.
     * @return This builder for chaining.
     */
    public Builder setFqnBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) { throw new NullPointerException(); }
      checkByteStringIsUtf8(value);
      fqn_ = value;
      bitField0_ |= 0x00000008;
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


    // @@protoc_insertion_point(builder_scope:attributes.ValueCreateUpdate)
  }

  // @@protoc_insertion_point(class_scope:attributes.ValueCreateUpdate)
  private static final com.attributes.ValueCreateUpdate DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new com.attributes.ValueCreateUpdate();
  }

  public static com.attributes.ValueCreateUpdate getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<ValueCreateUpdate>
      PARSER = new com.google.protobuf.AbstractParser<ValueCreateUpdate>() {
    @java.lang.Override
    public ValueCreateUpdate parsePartialFrom(
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

  public static com.google.protobuf.Parser<ValueCreateUpdate> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<ValueCreateUpdate> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public com.attributes.ValueCreateUpdate getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

