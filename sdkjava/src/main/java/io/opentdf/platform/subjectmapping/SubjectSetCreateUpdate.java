// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/subjectmapping/subject_mapping.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.subjectmapping;

/**
 * Protobuf type {@code subjectmapping.SubjectSetCreateUpdate}
 */
public final class SubjectSetCreateUpdate extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:subjectmapping.SubjectSetCreateUpdate)
    SubjectSetCreateUpdateOrBuilder {
private static final long serialVersionUID = 0L;
  // Use SubjectSetCreateUpdate.newBuilder() to construct.
  private SubjectSetCreateUpdate(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private SubjectSetCreateUpdate() {
    conditionGroups_ = java.util.Collections.emptyList();
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new SubjectSetCreateUpdate();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return io.opentdf.platform.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_SubjectSetCreateUpdate_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return io.opentdf.platform.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_SubjectSetCreateUpdate_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate.class, io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate.Builder.class);
  }

  private int bitField0_;
  public static final int METADATA_FIELD_NUMBER = 1;
  private io.opentdf.platform.common.MetadataMutable metadata_;
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
  public io.opentdf.platform.common.MetadataMutable getMetadata() {
    return metadata_ == null ? io.opentdf.platform.common.MetadataMutable.getDefaultInstance() : metadata_;
  }
  /**
   * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
   */
  @java.lang.Override
  public io.opentdf.platform.common.MetadataMutableOrBuilder getMetadataOrBuilder() {
    return metadata_ == null ? io.opentdf.platform.common.MetadataMutable.getDefaultInstance() : metadata_;
  }

  public static final int CONDITION_GROUPS_FIELD_NUMBER = 2;
  @SuppressWarnings("serial")
  private java.util.List<io.opentdf.platform.subjectmapping.ConditionGroup> conditionGroups_;
  /**
   * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
   */
  @java.lang.Override
  public java.util.List<io.opentdf.platform.subjectmapping.ConditionGroup> getConditionGroupsList() {
    return conditionGroups_;
  }
  /**
   * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
   */
  @java.lang.Override
  public java.util.List<? extends io.opentdf.platform.subjectmapping.ConditionGroupOrBuilder> 
      getConditionGroupsOrBuilderList() {
    return conditionGroups_;
  }
  /**
   * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
   */
  @java.lang.Override
  public int getConditionGroupsCount() {
    return conditionGroups_.size();
  }
  /**
   * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
   */
  @java.lang.Override
  public io.opentdf.platform.subjectmapping.ConditionGroup getConditionGroups(int index) {
    return conditionGroups_.get(index);
  }
  /**
   * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
   */
  @java.lang.Override
  public io.opentdf.platform.subjectmapping.ConditionGroupOrBuilder getConditionGroupsOrBuilder(
      int index) {
    return conditionGroups_.get(index);
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
    for (int i = 0; i < conditionGroups_.size(); i++) {
      output.writeMessage(2, conditionGroups_.get(i));
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
    for (int i = 0; i < conditionGroups_.size(); i++) {
      size += com.google.protobuf.CodedOutputStream
        .computeMessageSize(2, conditionGroups_.get(i));
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
    if (!(obj instanceof io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate)) {
      return super.equals(obj);
    }
    io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate other = (io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate) obj;

    if (hasMetadata() != other.hasMetadata()) return false;
    if (hasMetadata()) {
      if (!getMetadata()
          .equals(other.getMetadata())) return false;
    }
    if (!getConditionGroupsList()
        .equals(other.getConditionGroupsList())) return false;
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
    if (getConditionGroupsCount() > 0) {
      hash = (37 * hash) + CONDITION_GROUPS_FIELD_NUMBER;
      hash = (53 * hash) + getConditionGroupsList().hashCode();
    }
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate parseFrom(
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
  public static Builder newBuilder(io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate prototype) {
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
   * Protobuf type {@code subjectmapping.SubjectSetCreateUpdate}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:subjectmapping.SubjectSetCreateUpdate)
      io.opentdf.platform.subjectmapping.SubjectSetCreateUpdateOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return io.opentdf.platform.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_SubjectSetCreateUpdate_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return io.opentdf.platform.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_SubjectSetCreateUpdate_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate.class, io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate.Builder.class);
    }

    // Construct using io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate.newBuilder()
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
        getConditionGroupsFieldBuilder();
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
      if (conditionGroupsBuilder_ == null) {
        conditionGroups_ = java.util.Collections.emptyList();
      } else {
        conditionGroups_ = null;
        conditionGroupsBuilder_.clear();
      }
      bitField0_ = (bitField0_ & ~0x00000002);
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return io.opentdf.platform.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_SubjectSetCreateUpdate_descriptor;
    }

    @java.lang.Override
    public io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate getDefaultInstanceForType() {
      return io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate.getDefaultInstance();
    }

    @java.lang.Override
    public io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate build() {
      io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate buildPartial() {
      io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate result = new io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate(this);
      buildPartialRepeatedFields(result);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartialRepeatedFields(io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate result) {
      if (conditionGroupsBuilder_ == null) {
        if (((bitField0_ & 0x00000002) != 0)) {
          conditionGroups_ = java.util.Collections.unmodifiableList(conditionGroups_);
          bitField0_ = (bitField0_ & ~0x00000002);
        }
        result.conditionGroups_ = conditionGroups_;
      } else {
        result.conditionGroups_ = conditionGroupsBuilder_.build();
      }
    }

    private void buildPartial0(io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate result) {
      int from_bitField0_ = bitField0_;
      int to_bitField0_ = 0;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        result.metadata_ = metadataBuilder_ == null
            ? metadata_
            : metadataBuilder_.build();
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
      if (other instanceof io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate) {
        return mergeFrom((io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate other) {
      if (other == io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate.getDefaultInstance()) return this;
      if (other.hasMetadata()) {
        mergeMetadata(other.getMetadata());
      }
      if (conditionGroupsBuilder_ == null) {
        if (!other.conditionGroups_.isEmpty()) {
          if (conditionGroups_.isEmpty()) {
            conditionGroups_ = other.conditionGroups_;
            bitField0_ = (bitField0_ & ~0x00000002);
          } else {
            ensureConditionGroupsIsMutable();
            conditionGroups_.addAll(other.conditionGroups_);
          }
          onChanged();
        }
      } else {
        if (!other.conditionGroups_.isEmpty()) {
          if (conditionGroupsBuilder_.isEmpty()) {
            conditionGroupsBuilder_.dispose();
            conditionGroupsBuilder_ = null;
            conditionGroups_ = other.conditionGroups_;
            bitField0_ = (bitField0_ & ~0x00000002);
            conditionGroupsBuilder_ = 
              com.google.protobuf.GeneratedMessageV3.alwaysUseFieldBuilders ?
                 getConditionGroupsFieldBuilder() : null;
          } else {
            conditionGroupsBuilder_.addAllMessages(other.conditionGroups_);
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
              input.readMessage(
                  getMetadataFieldBuilder().getBuilder(),
                  extensionRegistry);
              bitField0_ |= 0x00000001;
              break;
            } // case 10
            case 18: {
              io.opentdf.platform.subjectmapping.ConditionGroup m =
                  input.readMessage(
                      io.opentdf.platform.subjectmapping.ConditionGroup.parser(),
                      extensionRegistry);
              if (conditionGroupsBuilder_ == null) {
                ensureConditionGroupsIsMutable();
                conditionGroups_.add(m);
              } else {
                conditionGroupsBuilder_.addMessage(m);
              }
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

    private io.opentdf.platform.common.MetadataMutable metadata_;
    private com.google.protobuf.SingleFieldBuilderV3<
        io.opentdf.platform.common.MetadataMutable, io.opentdf.platform.common.MetadataMutable.Builder, io.opentdf.platform.common.MetadataMutableOrBuilder> metadataBuilder_;
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
    public io.opentdf.platform.common.MetadataMutable getMetadata() {
      if (metadataBuilder_ == null) {
        return metadata_ == null ? io.opentdf.platform.common.MetadataMutable.getDefaultInstance() : metadata_;
      } else {
        return metadataBuilder_.getMessage();
      }
    }
    /**
     * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
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
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
     */
    public Builder setMetadata(
        io.opentdf.platform.common.MetadataMutable.Builder builderForValue) {
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
    public Builder mergeMetadata(io.opentdf.platform.common.MetadataMutable value) {
      if (metadataBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0) &&
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
    public io.opentdf.platform.common.MetadataMutable.Builder getMetadataBuilder() {
      bitField0_ |= 0x00000001;
      onChanged();
      return getMetadataFieldBuilder().getBuilder();
    }
    /**
     * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
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
     * <code>.common.MetadataMutable metadata = 1 [json_name = "metadata"];</code>
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

    private java.util.List<io.opentdf.platform.subjectmapping.ConditionGroup> conditionGroups_ =
      java.util.Collections.emptyList();
    private void ensureConditionGroupsIsMutable() {
      if (!((bitField0_ & 0x00000002) != 0)) {
        conditionGroups_ = new java.util.ArrayList<io.opentdf.platform.subjectmapping.ConditionGroup>(conditionGroups_);
        bitField0_ |= 0x00000002;
       }
    }

    private com.google.protobuf.RepeatedFieldBuilderV3<
        io.opentdf.platform.subjectmapping.ConditionGroup, io.opentdf.platform.subjectmapping.ConditionGroup.Builder, io.opentdf.platform.subjectmapping.ConditionGroupOrBuilder> conditionGroupsBuilder_;

    /**
     * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
     */
    public java.util.List<io.opentdf.platform.subjectmapping.ConditionGroup> getConditionGroupsList() {
      if (conditionGroupsBuilder_ == null) {
        return java.util.Collections.unmodifiableList(conditionGroups_);
      } else {
        return conditionGroupsBuilder_.getMessageList();
      }
    }
    /**
     * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
     */
    public int getConditionGroupsCount() {
      if (conditionGroupsBuilder_ == null) {
        return conditionGroups_.size();
      } else {
        return conditionGroupsBuilder_.getCount();
      }
    }
    /**
     * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
     */
    public io.opentdf.platform.subjectmapping.ConditionGroup getConditionGroups(int index) {
      if (conditionGroupsBuilder_ == null) {
        return conditionGroups_.get(index);
      } else {
        return conditionGroupsBuilder_.getMessage(index);
      }
    }
    /**
     * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
     */
    public Builder setConditionGroups(
        int index, io.opentdf.platform.subjectmapping.ConditionGroup value) {
      if (conditionGroupsBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureConditionGroupsIsMutable();
        conditionGroups_.set(index, value);
        onChanged();
      } else {
        conditionGroupsBuilder_.setMessage(index, value);
      }
      return this;
    }
    /**
     * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
     */
    public Builder setConditionGroups(
        int index, io.opentdf.platform.subjectmapping.ConditionGroup.Builder builderForValue) {
      if (conditionGroupsBuilder_ == null) {
        ensureConditionGroupsIsMutable();
        conditionGroups_.set(index, builderForValue.build());
        onChanged();
      } else {
        conditionGroupsBuilder_.setMessage(index, builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
     */
    public Builder addConditionGroups(io.opentdf.platform.subjectmapping.ConditionGroup value) {
      if (conditionGroupsBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureConditionGroupsIsMutable();
        conditionGroups_.add(value);
        onChanged();
      } else {
        conditionGroupsBuilder_.addMessage(value);
      }
      return this;
    }
    /**
     * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
     */
    public Builder addConditionGroups(
        int index, io.opentdf.platform.subjectmapping.ConditionGroup value) {
      if (conditionGroupsBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureConditionGroupsIsMutable();
        conditionGroups_.add(index, value);
        onChanged();
      } else {
        conditionGroupsBuilder_.addMessage(index, value);
      }
      return this;
    }
    /**
     * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
     */
    public Builder addConditionGroups(
        io.opentdf.platform.subjectmapping.ConditionGroup.Builder builderForValue) {
      if (conditionGroupsBuilder_ == null) {
        ensureConditionGroupsIsMutable();
        conditionGroups_.add(builderForValue.build());
        onChanged();
      } else {
        conditionGroupsBuilder_.addMessage(builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
     */
    public Builder addConditionGroups(
        int index, io.opentdf.platform.subjectmapping.ConditionGroup.Builder builderForValue) {
      if (conditionGroupsBuilder_ == null) {
        ensureConditionGroupsIsMutable();
        conditionGroups_.add(index, builderForValue.build());
        onChanged();
      } else {
        conditionGroupsBuilder_.addMessage(index, builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
     */
    public Builder addAllConditionGroups(
        java.lang.Iterable<? extends io.opentdf.platform.subjectmapping.ConditionGroup> values) {
      if (conditionGroupsBuilder_ == null) {
        ensureConditionGroupsIsMutable();
        com.google.protobuf.AbstractMessageLite.Builder.addAll(
            values, conditionGroups_);
        onChanged();
      } else {
        conditionGroupsBuilder_.addAllMessages(values);
      }
      return this;
    }
    /**
     * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
     */
    public Builder clearConditionGroups() {
      if (conditionGroupsBuilder_ == null) {
        conditionGroups_ = java.util.Collections.emptyList();
        bitField0_ = (bitField0_ & ~0x00000002);
        onChanged();
      } else {
        conditionGroupsBuilder_.clear();
      }
      return this;
    }
    /**
     * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
     */
    public Builder removeConditionGroups(int index) {
      if (conditionGroupsBuilder_ == null) {
        ensureConditionGroupsIsMutable();
        conditionGroups_.remove(index);
        onChanged();
      } else {
        conditionGroupsBuilder_.remove(index);
      }
      return this;
    }
    /**
     * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
     */
    public io.opentdf.platform.subjectmapping.ConditionGroup.Builder getConditionGroupsBuilder(
        int index) {
      return getConditionGroupsFieldBuilder().getBuilder(index);
    }
    /**
     * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
     */
    public io.opentdf.platform.subjectmapping.ConditionGroupOrBuilder getConditionGroupsOrBuilder(
        int index) {
      if (conditionGroupsBuilder_ == null) {
        return conditionGroups_.get(index);  } else {
        return conditionGroupsBuilder_.getMessageOrBuilder(index);
      }
    }
    /**
     * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
     */
    public java.util.List<? extends io.opentdf.platform.subjectmapping.ConditionGroupOrBuilder> 
         getConditionGroupsOrBuilderList() {
      if (conditionGroupsBuilder_ != null) {
        return conditionGroupsBuilder_.getMessageOrBuilderList();
      } else {
        return java.util.Collections.unmodifiableList(conditionGroups_);
      }
    }
    /**
     * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
     */
    public io.opentdf.platform.subjectmapping.ConditionGroup.Builder addConditionGroupsBuilder() {
      return getConditionGroupsFieldBuilder().addBuilder(
          io.opentdf.platform.subjectmapping.ConditionGroup.getDefaultInstance());
    }
    /**
     * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
     */
    public io.opentdf.platform.subjectmapping.ConditionGroup.Builder addConditionGroupsBuilder(
        int index) {
      return getConditionGroupsFieldBuilder().addBuilder(
          index, io.opentdf.platform.subjectmapping.ConditionGroup.getDefaultInstance());
    }
    /**
     * <code>repeated .subjectmapping.ConditionGroup condition_groups = 2 [json_name = "conditionGroups"];</code>
     */
    public java.util.List<io.opentdf.platform.subjectmapping.ConditionGroup.Builder> 
         getConditionGroupsBuilderList() {
      return getConditionGroupsFieldBuilder().getBuilderList();
    }
    private com.google.protobuf.RepeatedFieldBuilderV3<
        io.opentdf.platform.subjectmapping.ConditionGroup, io.opentdf.platform.subjectmapping.ConditionGroup.Builder, io.opentdf.platform.subjectmapping.ConditionGroupOrBuilder> 
        getConditionGroupsFieldBuilder() {
      if (conditionGroupsBuilder_ == null) {
        conditionGroupsBuilder_ = new com.google.protobuf.RepeatedFieldBuilderV3<
            io.opentdf.platform.subjectmapping.ConditionGroup, io.opentdf.platform.subjectmapping.ConditionGroup.Builder, io.opentdf.platform.subjectmapping.ConditionGroupOrBuilder>(
                conditionGroups_,
                ((bitField0_ & 0x00000002) != 0),
                getParentForChildren(),
                isClean());
        conditionGroups_ = null;
      }
      return conditionGroupsBuilder_;
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


    // @@protoc_insertion_point(builder_scope:subjectmapping.SubjectSetCreateUpdate)
  }

  // @@protoc_insertion_point(class_scope:subjectmapping.SubjectSetCreateUpdate)
  private static final io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate();
  }

  public static io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<SubjectSetCreateUpdate>
      PARSER = new com.google.protobuf.AbstractParser<SubjectSetCreateUpdate>() {
    @java.lang.Override
    public SubjectSetCreateUpdate parsePartialFrom(
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

  public static com.google.protobuf.Parser<SubjectSetCreateUpdate> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<SubjectSetCreateUpdate> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public io.opentdf.platform.subjectmapping.SubjectSetCreateUpdate getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

