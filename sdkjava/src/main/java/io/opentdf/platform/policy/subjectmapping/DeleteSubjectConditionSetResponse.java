// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/subjectmapping/subject_mapping.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.subjectmapping;

/**
 * Protobuf type {@code policy.subjectmapping.DeleteSubjectConditionSetResponse}
 */
public final class DeleteSubjectConditionSetResponse extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:policy.subjectmapping.DeleteSubjectConditionSetResponse)
    DeleteSubjectConditionSetResponseOrBuilder {
private static final long serialVersionUID = 0L;
  // Use DeleteSubjectConditionSetResponse.newBuilder() to construct.
  private DeleteSubjectConditionSetResponse(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private DeleteSubjectConditionSetResponse() {
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new DeleteSubjectConditionSetResponse();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return io.opentdf.platform.policy.subjectmapping.SubjectMappingProto.internal_static_policy_subjectmapping_DeleteSubjectConditionSetResponse_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return io.opentdf.platform.policy.subjectmapping.SubjectMappingProto.internal_static_policy_subjectmapping_DeleteSubjectConditionSetResponse_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse.class, io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse.Builder.class);
  }

  private int bitField0_;
  public static final int SUBJECT_CONDITION_SET_FIELD_NUMBER = 1;
  private io.opentdf.platform.policy.SubjectConditionSet subjectConditionSet_;
  /**
   * <pre>
   * Only ID of deleted Subject Condition Set provided
   * </pre>
   *
   * <code>.policy.SubjectConditionSet subject_condition_set = 1 [json_name = "subjectConditionSet"];</code>
   * @return Whether the subjectConditionSet field is set.
   */
  @java.lang.Override
  public boolean hasSubjectConditionSet() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <pre>
   * Only ID of deleted Subject Condition Set provided
   * </pre>
   *
   * <code>.policy.SubjectConditionSet subject_condition_set = 1 [json_name = "subjectConditionSet"];</code>
   * @return The subjectConditionSet.
   */
  @java.lang.Override
  public io.opentdf.platform.policy.SubjectConditionSet getSubjectConditionSet() {
    return subjectConditionSet_ == null ? io.opentdf.platform.policy.SubjectConditionSet.getDefaultInstance() : subjectConditionSet_;
  }
  /**
   * <pre>
   * Only ID of deleted Subject Condition Set provided
   * </pre>
   *
   * <code>.policy.SubjectConditionSet subject_condition_set = 1 [json_name = "subjectConditionSet"];</code>
   */
  @java.lang.Override
  public io.opentdf.platform.policy.SubjectConditionSetOrBuilder getSubjectConditionSetOrBuilder() {
    return subjectConditionSet_ == null ? io.opentdf.platform.policy.SubjectConditionSet.getDefaultInstance() : subjectConditionSet_;
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
      output.writeMessage(1, getSubjectConditionSet());
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
        .computeMessageSize(1, getSubjectConditionSet());
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
    if (!(obj instanceof io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse)) {
      return super.equals(obj);
    }
    io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse other = (io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse) obj;

    if (hasSubjectConditionSet() != other.hasSubjectConditionSet()) return false;
    if (hasSubjectConditionSet()) {
      if (!getSubjectConditionSet()
          .equals(other.getSubjectConditionSet())) return false;
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
    if (hasSubjectConditionSet()) {
      hash = (37 * hash) + SUBJECT_CONDITION_SET_FIELD_NUMBER;
      hash = (53 * hash) + getSubjectConditionSet().hashCode();
    }
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse parseFrom(
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
  public static Builder newBuilder(io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse prototype) {
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
   * Protobuf type {@code policy.subjectmapping.DeleteSubjectConditionSetResponse}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:policy.subjectmapping.DeleteSubjectConditionSetResponse)
      io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponseOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return io.opentdf.platform.policy.subjectmapping.SubjectMappingProto.internal_static_policy_subjectmapping_DeleteSubjectConditionSetResponse_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return io.opentdf.platform.policy.subjectmapping.SubjectMappingProto.internal_static_policy_subjectmapping_DeleteSubjectConditionSetResponse_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse.class, io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse.Builder.class);
    }

    // Construct using io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse.newBuilder()
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
        getSubjectConditionSetFieldBuilder();
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      bitField0_ = 0;
      subjectConditionSet_ = null;
      if (subjectConditionSetBuilder_ != null) {
        subjectConditionSetBuilder_.dispose();
        subjectConditionSetBuilder_ = null;
      }
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return io.opentdf.platform.policy.subjectmapping.SubjectMappingProto.internal_static_policy_subjectmapping_DeleteSubjectConditionSetResponse_descriptor;
    }

    @java.lang.Override
    public io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse getDefaultInstanceForType() {
      return io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse.getDefaultInstance();
    }

    @java.lang.Override
    public io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse build() {
      io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse buildPartial() {
      io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse result = new io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse(this);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartial0(io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse result) {
      int from_bitField0_ = bitField0_;
      int to_bitField0_ = 0;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        result.subjectConditionSet_ = subjectConditionSetBuilder_ == null
            ? subjectConditionSet_
            : subjectConditionSetBuilder_.build();
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
      if (other instanceof io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse) {
        return mergeFrom((io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse other) {
      if (other == io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse.getDefaultInstance()) return this;
      if (other.hasSubjectConditionSet()) {
        mergeSubjectConditionSet(other.getSubjectConditionSet());
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
                  getSubjectConditionSetFieldBuilder().getBuilder(),
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

    private io.opentdf.platform.policy.SubjectConditionSet subjectConditionSet_;
    private com.google.protobuf.SingleFieldBuilderV3<
        io.opentdf.platform.policy.SubjectConditionSet, io.opentdf.platform.policy.SubjectConditionSet.Builder, io.opentdf.platform.policy.SubjectConditionSetOrBuilder> subjectConditionSetBuilder_;
    /**
     * <pre>
     * Only ID of deleted Subject Condition Set provided
     * </pre>
     *
     * <code>.policy.SubjectConditionSet subject_condition_set = 1 [json_name = "subjectConditionSet"];</code>
     * @return Whether the subjectConditionSet field is set.
     */
    public boolean hasSubjectConditionSet() {
      return ((bitField0_ & 0x00000001) != 0);
    }
    /**
     * <pre>
     * Only ID of deleted Subject Condition Set provided
     * </pre>
     *
     * <code>.policy.SubjectConditionSet subject_condition_set = 1 [json_name = "subjectConditionSet"];</code>
     * @return The subjectConditionSet.
     */
    public io.opentdf.platform.policy.SubjectConditionSet getSubjectConditionSet() {
      if (subjectConditionSetBuilder_ == null) {
        return subjectConditionSet_ == null ? io.opentdf.platform.policy.SubjectConditionSet.getDefaultInstance() : subjectConditionSet_;
      } else {
        return subjectConditionSetBuilder_.getMessage();
      }
    }
    /**
     * <pre>
     * Only ID of deleted Subject Condition Set provided
     * </pre>
     *
     * <code>.policy.SubjectConditionSet subject_condition_set = 1 [json_name = "subjectConditionSet"];</code>
     */
    public Builder setSubjectConditionSet(io.opentdf.platform.policy.SubjectConditionSet value) {
      if (subjectConditionSetBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        subjectConditionSet_ = value;
      } else {
        subjectConditionSetBuilder_.setMessage(value);
      }
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Only ID of deleted Subject Condition Set provided
     * </pre>
     *
     * <code>.policy.SubjectConditionSet subject_condition_set = 1 [json_name = "subjectConditionSet"];</code>
     */
    public Builder setSubjectConditionSet(
        io.opentdf.platform.policy.SubjectConditionSet.Builder builderForValue) {
      if (subjectConditionSetBuilder_ == null) {
        subjectConditionSet_ = builderForValue.build();
      } else {
        subjectConditionSetBuilder_.setMessage(builderForValue.build());
      }
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Only ID of deleted Subject Condition Set provided
     * </pre>
     *
     * <code>.policy.SubjectConditionSet subject_condition_set = 1 [json_name = "subjectConditionSet"];</code>
     */
    public Builder mergeSubjectConditionSet(io.opentdf.platform.policy.SubjectConditionSet value) {
      if (subjectConditionSetBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0) &&
          subjectConditionSet_ != null &&
          subjectConditionSet_ != io.opentdf.platform.policy.SubjectConditionSet.getDefaultInstance()) {
          getSubjectConditionSetBuilder().mergeFrom(value);
        } else {
          subjectConditionSet_ = value;
        }
      } else {
        subjectConditionSetBuilder_.mergeFrom(value);
      }
      if (subjectConditionSet_ != null) {
        bitField0_ |= 0x00000001;
        onChanged();
      }
      return this;
    }
    /**
     * <pre>
     * Only ID of deleted Subject Condition Set provided
     * </pre>
     *
     * <code>.policy.SubjectConditionSet subject_condition_set = 1 [json_name = "subjectConditionSet"];</code>
     */
    public Builder clearSubjectConditionSet() {
      bitField0_ = (bitField0_ & ~0x00000001);
      subjectConditionSet_ = null;
      if (subjectConditionSetBuilder_ != null) {
        subjectConditionSetBuilder_.dispose();
        subjectConditionSetBuilder_ = null;
      }
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Only ID of deleted Subject Condition Set provided
     * </pre>
     *
     * <code>.policy.SubjectConditionSet subject_condition_set = 1 [json_name = "subjectConditionSet"];</code>
     */
    public io.opentdf.platform.policy.SubjectConditionSet.Builder getSubjectConditionSetBuilder() {
      bitField0_ |= 0x00000001;
      onChanged();
      return getSubjectConditionSetFieldBuilder().getBuilder();
    }
    /**
     * <pre>
     * Only ID of deleted Subject Condition Set provided
     * </pre>
     *
     * <code>.policy.SubjectConditionSet subject_condition_set = 1 [json_name = "subjectConditionSet"];</code>
     */
    public io.opentdf.platform.policy.SubjectConditionSetOrBuilder getSubjectConditionSetOrBuilder() {
      if (subjectConditionSetBuilder_ != null) {
        return subjectConditionSetBuilder_.getMessageOrBuilder();
      } else {
        return subjectConditionSet_ == null ?
            io.opentdf.platform.policy.SubjectConditionSet.getDefaultInstance() : subjectConditionSet_;
      }
    }
    /**
     * <pre>
     * Only ID of deleted Subject Condition Set provided
     * </pre>
     *
     * <code>.policy.SubjectConditionSet subject_condition_set = 1 [json_name = "subjectConditionSet"];</code>
     */
    private com.google.protobuf.SingleFieldBuilderV3<
        io.opentdf.platform.policy.SubjectConditionSet, io.opentdf.platform.policy.SubjectConditionSet.Builder, io.opentdf.platform.policy.SubjectConditionSetOrBuilder> 
        getSubjectConditionSetFieldBuilder() {
      if (subjectConditionSetBuilder_ == null) {
        subjectConditionSetBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
            io.opentdf.platform.policy.SubjectConditionSet, io.opentdf.platform.policy.SubjectConditionSet.Builder, io.opentdf.platform.policy.SubjectConditionSetOrBuilder>(
                getSubjectConditionSet(),
                getParentForChildren(),
                isClean());
        subjectConditionSet_ = null;
      }
      return subjectConditionSetBuilder_;
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


    // @@protoc_insertion_point(builder_scope:policy.subjectmapping.DeleteSubjectConditionSetResponse)
  }

  // @@protoc_insertion_point(class_scope:policy.subjectmapping.DeleteSubjectConditionSetResponse)
  private static final io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse();
  }

  public static io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<DeleteSubjectConditionSetResponse>
      PARSER = new com.google.protobuf.AbstractParser<DeleteSubjectConditionSetResponse>() {
    @java.lang.Override
    public DeleteSubjectConditionSetResponse parsePartialFrom(
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

  public static com.google.protobuf.Parser<DeleteSubjectConditionSetResponse> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<DeleteSubjectConditionSetResponse> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public io.opentdf.platform.policy.subjectmapping.DeleteSubjectConditionSetResponse getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

