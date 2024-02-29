// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/subjectmapping/subject_mapping.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.subjectmapping;

/**
 * Protobuf type {@code policy.subjectmapping.GetSubjectSetResponse}
 */
public final class GetSubjectSetResponse extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:policy.subjectmapping.GetSubjectSetResponse)
    GetSubjectSetResponseOrBuilder {
private static final long serialVersionUID = 0L;
  // Use GetSubjectSetResponse.newBuilder() to construct.
  private GetSubjectSetResponse(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private GetSubjectSetResponse() {
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new GetSubjectSetResponse();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return io.opentdf.platform.policy.subjectmapping.SubjectMappingProto.internal_static_policy_subjectmapping_GetSubjectSetResponse_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return io.opentdf.platform.policy.subjectmapping.SubjectMappingProto.internal_static_policy_subjectmapping_GetSubjectSetResponse_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse.class, io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse.Builder.class);
  }

  private int bitField0_;
  public static final int SUBJECT_SET_FIELD_NUMBER = 1;
  private io.opentdf.platform.policy.subjectmapping.SubjectSet subjectSet_;
  /**
   * <code>.policy.subjectmapping.SubjectSet subject_set = 1 [json_name = "subjectSet"];</code>
   * @return Whether the subjectSet field is set.
   */
  @java.lang.Override
  public boolean hasSubjectSet() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <code>.policy.subjectmapping.SubjectSet subject_set = 1 [json_name = "subjectSet"];</code>
   * @return The subjectSet.
   */
  @java.lang.Override
  public io.opentdf.platform.policy.subjectmapping.SubjectSet getSubjectSet() {
    return subjectSet_ == null ? io.opentdf.platform.policy.subjectmapping.SubjectSet.getDefaultInstance() : subjectSet_;
  }
  /**
   * <code>.policy.subjectmapping.SubjectSet subject_set = 1 [json_name = "subjectSet"];</code>
   */
  @java.lang.Override
  public io.opentdf.platform.policy.subjectmapping.SubjectSetOrBuilder getSubjectSetOrBuilder() {
    return subjectSet_ == null ? io.opentdf.platform.policy.subjectmapping.SubjectSet.getDefaultInstance() : subjectSet_;
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
      output.writeMessage(1, getSubjectSet());
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
        .computeMessageSize(1, getSubjectSet());
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
    if (!(obj instanceof io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse)) {
      return super.equals(obj);
    }
    io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse other = (io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse) obj;

    if (hasSubjectSet() != other.hasSubjectSet()) return false;
    if (hasSubjectSet()) {
      if (!getSubjectSet()
          .equals(other.getSubjectSet())) return false;
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
    if (hasSubjectSet()) {
      hash = (37 * hash) + SUBJECT_SET_FIELD_NUMBER;
      hash = (53 * hash) + getSubjectSet().hashCode();
    }
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse parseFrom(
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
  public static Builder newBuilder(io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse prototype) {
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
   * Protobuf type {@code policy.subjectmapping.GetSubjectSetResponse}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:policy.subjectmapping.GetSubjectSetResponse)
      io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponseOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return io.opentdf.platform.policy.subjectmapping.SubjectMappingProto.internal_static_policy_subjectmapping_GetSubjectSetResponse_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return io.opentdf.platform.policy.subjectmapping.SubjectMappingProto.internal_static_policy_subjectmapping_GetSubjectSetResponse_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse.class, io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse.Builder.class);
    }

    // Construct using io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse.newBuilder()
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
        getSubjectSetFieldBuilder();
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      bitField0_ = 0;
      subjectSet_ = null;
      if (subjectSetBuilder_ != null) {
        subjectSetBuilder_.dispose();
        subjectSetBuilder_ = null;
      }
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return io.opentdf.platform.policy.subjectmapping.SubjectMappingProto.internal_static_policy_subjectmapping_GetSubjectSetResponse_descriptor;
    }

    @java.lang.Override
    public io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse getDefaultInstanceForType() {
      return io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse.getDefaultInstance();
    }

    @java.lang.Override
    public io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse build() {
      io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse buildPartial() {
      io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse result = new io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse(this);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartial0(io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse result) {
      int from_bitField0_ = bitField0_;
      int to_bitField0_ = 0;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        result.subjectSet_ = subjectSetBuilder_ == null
            ? subjectSet_
            : subjectSetBuilder_.build();
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
      if (other instanceof io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse) {
        return mergeFrom((io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse other) {
      if (other == io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse.getDefaultInstance()) return this;
      if (other.hasSubjectSet()) {
        mergeSubjectSet(other.getSubjectSet());
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
                  getSubjectSetFieldBuilder().getBuilder(),
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

    private io.opentdf.platform.policy.subjectmapping.SubjectSet subjectSet_;
    private com.google.protobuf.SingleFieldBuilderV3<
        io.opentdf.platform.policy.subjectmapping.SubjectSet, io.opentdf.platform.policy.subjectmapping.SubjectSet.Builder, io.opentdf.platform.policy.subjectmapping.SubjectSetOrBuilder> subjectSetBuilder_;
    /**
     * <code>.policy.subjectmapping.SubjectSet subject_set = 1 [json_name = "subjectSet"];</code>
     * @return Whether the subjectSet field is set.
     */
    public boolean hasSubjectSet() {
      return ((bitField0_ & 0x00000001) != 0);
    }
    /**
     * <code>.policy.subjectmapping.SubjectSet subject_set = 1 [json_name = "subjectSet"];</code>
     * @return The subjectSet.
     */
    public io.opentdf.platform.policy.subjectmapping.SubjectSet getSubjectSet() {
      if (subjectSetBuilder_ == null) {
        return subjectSet_ == null ? io.opentdf.platform.policy.subjectmapping.SubjectSet.getDefaultInstance() : subjectSet_;
      } else {
        return subjectSetBuilder_.getMessage();
      }
    }
    /**
     * <code>.policy.subjectmapping.SubjectSet subject_set = 1 [json_name = "subjectSet"];</code>
     */
    public Builder setSubjectSet(io.opentdf.platform.policy.subjectmapping.SubjectSet value) {
      if (subjectSetBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        subjectSet_ = value;
      } else {
        subjectSetBuilder_.setMessage(value);
      }
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>.policy.subjectmapping.SubjectSet subject_set = 1 [json_name = "subjectSet"];</code>
     */
    public Builder setSubjectSet(
        io.opentdf.platform.policy.subjectmapping.SubjectSet.Builder builderForValue) {
      if (subjectSetBuilder_ == null) {
        subjectSet_ = builderForValue.build();
      } else {
        subjectSetBuilder_.setMessage(builderForValue.build());
      }
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>.policy.subjectmapping.SubjectSet subject_set = 1 [json_name = "subjectSet"];</code>
     */
    public Builder mergeSubjectSet(io.opentdf.platform.policy.subjectmapping.SubjectSet value) {
      if (subjectSetBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0) &&
          subjectSet_ != null &&
          subjectSet_ != io.opentdf.platform.policy.subjectmapping.SubjectSet.getDefaultInstance()) {
          getSubjectSetBuilder().mergeFrom(value);
        } else {
          subjectSet_ = value;
        }
      } else {
        subjectSetBuilder_.mergeFrom(value);
      }
      if (subjectSet_ != null) {
        bitField0_ |= 0x00000001;
        onChanged();
      }
      return this;
    }
    /**
     * <code>.policy.subjectmapping.SubjectSet subject_set = 1 [json_name = "subjectSet"];</code>
     */
    public Builder clearSubjectSet() {
      bitField0_ = (bitField0_ & ~0x00000001);
      subjectSet_ = null;
      if (subjectSetBuilder_ != null) {
        subjectSetBuilder_.dispose();
        subjectSetBuilder_ = null;
      }
      onChanged();
      return this;
    }
    /**
     * <code>.policy.subjectmapping.SubjectSet subject_set = 1 [json_name = "subjectSet"];</code>
     */
    public io.opentdf.platform.policy.subjectmapping.SubjectSet.Builder getSubjectSetBuilder() {
      bitField0_ |= 0x00000001;
      onChanged();
      return getSubjectSetFieldBuilder().getBuilder();
    }
    /**
     * <code>.policy.subjectmapping.SubjectSet subject_set = 1 [json_name = "subjectSet"];</code>
     */
    public io.opentdf.platform.policy.subjectmapping.SubjectSetOrBuilder getSubjectSetOrBuilder() {
      if (subjectSetBuilder_ != null) {
        return subjectSetBuilder_.getMessageOrBuilder();
      } else {
        return subjectSet_ == null ?
            io.opentdf.platform.policy.subjectmapping.SubjectSet.getDefaultInstance() : subjectSet_;
      }
    }
    /**
     * <code>.policy.subjectmapping.SubjectSet subject_set = 1 [json_name = "subjectSet"];</code>
     */
    private com.google.protobuf.SingleFieldBuilderV3<
        io.opentdf.platform.policy.subjectmapping.SubjectSet, io.opentdf.platform.policy.subjectmapping.SubjectSet.Builder, io.opentdf.platform.policy.subjectmapping.SubjectSetOrBuilder> 
        getSubjectSetFieldBuilder() {
      if (subjectSetBuilder_ == null) {
        subjectSetBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
            io.opentdf.platform.policy.subjectmapping.SubjectSet, io.opentdf.platform.policy.subjectmapping.SubjectSet.Builder, io.opentdf.platform.policy.subjectmapping.SubjectSetOrBuilder>(
                getSubjectSet(),
                getParentForChildren(),
                isClean());
        subjectSet_ = null;
      }
      return subjectSetBuilder_;
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


    // @@protoc_insertion_point(builder_scope:policy.subjectmapping.GetSubjectSetResponse)
  }

  // @@protoc_insertion_point(class_scope:policy.subjectmapping.GetSubjectSetResponse)
  private static final io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse();
  }

  public static io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<GetSubjectSetResponse>
      PARSER = new com.google.protobuf.AbstractParser<GetSubjectSetResponse>() {
    @java.lang.Override
    public GetSubjectSetResponse parsePartialFrom(
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

  public static com.google.protobuf.Parser<GetSubjectSetResponse> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<GetSubjectSetResponse> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public io.opentdf.platform.policy.subjectmapping.GetSubjectSetResponse getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

