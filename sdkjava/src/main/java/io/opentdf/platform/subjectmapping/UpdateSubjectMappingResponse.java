// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/subjectmapping/subject_mapping.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.subjectmapping;

/**
 * Protobuf type {@code subjectmapping.UpdateSubjectMappingResponse}
 */
public final class UpdateSubjectMappingResponse extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:subjectmapping.UpdateSubjectMappingResponse)
    UpdateSubjectMappingResponseOrBuilder {
private static final long serialVersionUID = 0L;
  // Use UpdateSubjectMappingResponse.newBuilder() to construct.
  private UpdateSubjectMappingResponse(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private UpdateSubjectMappingResponse() {
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new UpdateSubjectMappingResponse();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return io.opentdf.platform.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_UpdateSubjectMappingResponse_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return io.opentdf.platform.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_UpdateSubjectMappingResponse_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse.class, io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse.Builder.class);
  }

  private int bitField0_;
  public static final int SUBJECT_MAPPING_FIELD_NUMBER = 1;
  private io.opentdf.platform.subjectmapping.SubjectMapping subjectMapping_;
  /**
   * <code>.subjectmapping.SubjectMapping subject_mapping = 1 [json_name = "subjectMapping"];</code>
   * @return Whether the subjectMapping field is set.
   */
  @java.lang.Override
  public boolean hasSubjectMapping() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <code>.subjectmapping.SubjectMapping subject_mapping = 1 [json_name = "subjectMapping"];</code>
   * @return The subjectMapping.
   */
  @java.lang.Override
  public io.opentdf.platform.subjectmapping.SubjectMapping getSubjectMapping() {
    return subjectMapping_ == null ? io.opentdf.platform.subjectmapping.SubjectMapping.getDefaultInstance() : subjectMapping_;
  }
  /**
   * <code>.subjectmapping.SubjectMapping subject_mapping = 1 [json_name = "subjectMapping"];</code>
   */
  @java.lang.Override
  public io.opentdf.platform.subjectmapping.SubjectMappingOrBuilder getSubjectMappingOrBuilder() {
    return subjectMapping_ == null ? io.opentdf.platform.subjectmapping.SubjectMapping.getDefaultInstance() : subjectMapping_;
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
      output.writeMessage(1, getSubjectMapping());
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
        .computeMessageSize(1, getSubjectMapping());
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
    if (!(obj instanceof io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse)) {
      return super.equals(obj);
    }
    io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse other = (io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse) obj;

    if (hasSubjectMapping() != other.hasSubjectMapping()) return false;
    if (hasSubjectMapping()) {
      if (!getSubjectMapping()
          .equals(other.getSubjectMapping())) return false;
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
    if (hasSubjectMapping()) {
      hash = (37 * hash) + SUBJECT_MAPPING_FIELD_NUMBER;
      hash = (53 * hash) + getSubjectMapping().hashCode();
    }
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse parseFrom(
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
  public static Builder newBuilder(io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse prototype) {
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
   * Protobuf type {@code subjectmapping.UpdateSubjectMappingResponse}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:subjectmapping.UpdateSubjectMappingResponse)
      io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponseOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return io.opentdf.platform.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_UpdateSubjectMappingResponse_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return io.opentdf.platform.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_UpdateSubjectMappingResponse_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse.class, io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse.Builder.class);
    }

    // Construct using io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse.newBuilder()
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
        getSubjectMappingFieldBuilder();
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      bitField0_ = 0;
      subjectMapping_ = null;
      if (subjectMappingBuilder_ != null) {
        subjectMappingBuilder_.dispose();
        subjectMappingBuilder_ = null;
      }
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return io.opentdf.platform.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_UpdateSubjectMappingResponse_descriptor;
    }

    @java.lang.Override
    public io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse getDefaultInstanceForType() {
      return io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse.getDefaultInstance();
    }

    @java.lang.Override
    public io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse build() {
      io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse buildPartial() {
      io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse result = new io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse(this);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartial0(io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse result) {
      int from_bitField0_ = bitField0_;
      int to_bitField0_ = 0;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        result.subjectMapping_ = subjectMappingBuilder_ == null
            ? subjectMapping_
            : subjectMappingBuilder_.build();
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
      if (other instanceof io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse) {
        return mergeFrom((io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse other) {
      if (other == io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse.getDefaultInstance()) return this;
      if (other.hasSubjectMapping()) {
        mergeSubjectMapping(other.getSubjectMapping());
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
                  getSubjectMappingFieldBuilder().getBuilder(),
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

    private io.opentdf.platform.subjectmapping.SubjectMapping subjectMapping_;
    private com.google.protobuf.SingleFieldBuilderV3<
        io.opentdf.platform.subjectmapping.SubjectMapping, io.opentdf.platform.subjectmapping.SubjectMapping.Builder, io.opentdf.platform.subjectmapping.SubjectMappingOrBuilder> subjectMappingBuilder_;
    /**
     * <code>.subjectmapping.SubjectMapping subject_mapping = 1 [json_name = "subjectMapping"];</code>
     * @return Whether the subjectMapping field is set.
     */
    public boolean hasSubjectMapping() {
      return ((bitField0_ & 0x00000001) != 0);
    }
    /**
     * <code>.subjectmapping.SubjectMapping subject_mapping = 1 [json_name = "subjectMapping"];</code>
     * @return The subjectMapping.
     */
    public io.opentdf.platform.subjectmapping.SubjectMapping getSubjectMapping() {
      if (subjectMappingBuilder_ == null) {
        return subjectMapping_ == null ? io.opentdf.platform.subjectmapping.SubjectMapping.getDefaultInstance() : subjectMapping_;
      } else {
        return subjectMappingBuilder_.getMessage();
      }
    }
    /**
     * <code>.subjectmapping.SubjectMapping subject_mapping = 1 [json_name = "subjectMapping"];</code>
     */
    public Builder setSubjectMapping(io.opentdf.platform.subjectmapping.SubjectMapping value) {
      if (subjectMappingBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        subjectMapping_ = value;
      } else {
        subjectMappingBuilder_.setMessage(value);
      }
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>.subjectmapping.SubjectMapping subject_mapping = 1 [json_name = "subjectMapping"];</code>
     */
    public Builder setSubjectMapping(
        io.opentdf.platform.subjectmapping.SubjectMapping.Builder builderForValue) {
      if (subjectMappingBuilder_ == null) {
        subjectMapping_ = builderForValue.build();
      } else {
        subjectMappingBuilder_.setMessage(builderForValue.build());
      }
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>.subjectmapping.SubjectMapping subject_mapping = 1 [json_name = "subjectMapping"];</code>
     */
    public Builder mergeSubjectMapping(io.opentdf.platform.subjectmapping.SubjectMapping value) {
      if (subjectMappingBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0) &&
          subjectMapping_ != null &&
          subjectMapping_ != io.opentdf.platform.subjectmapping.SubjectMapping.getDefaultInstance()) {
          getSubjectMappingBuilder().mergeFrom(value);
        } else {
          subjectMapping_ = value;
        }
      } else {
        subjectMappingBuilder_.mergeFrom(value);
      }
      if (subjectMapping_ != null) {
        bitField0_ |= 0x00000001;
        onChanged();
      }
      return this;
    }
    /**
     * <code>.subjectmapping.SubjectMapping subject_mapping = 1 [json_name = "subjectMapping"];</code>
     */
    public Builder clearSubjectMapping() {
      bitField0_ = (bitField0_ & ~0x00000001);
      subjectMapping_ = null;
      if (subjectMappingBuilder_ != null) {
        subjectMappingBuilder_.dispose();
        subjectMappingBuilder_ = null;
      }
      onChanged();
      return this;
    }
    /**
     * <code>.subjectmapping.SubjectMapping subject_mapping = 1 [json_name = "subjectMapping"];</code>
     */
    public io.opentdf.platform.subjectmapping.SubjectMapping.Builder getSubjectMappingBuilder() {
      bitField0_ |= 0x00000001;
      onChanged();
      return getSubjectMappingFieldBuilder().getBuilder();
    }
    /**
     * <code>.subjectmapping.SubjectMapping subject_mapping = 1 [json_name = "subjectMapping"];</code>
     */
    public io.opentdf.platform.subjectmapping.SubjectMappingOrBuilder getSubjectMappingOrBuilder() {
      if (subjectMappingBuilder_ != null) {
        return subjectMappingBuilder_.getMessageOrBuilder();
      } else {
        return subjectMapping_ == null ?
            io.opentdf.platform.subjectmapping.SubjectMapping.getDefaultInstance() : subjectMapping_;
      }
    }
    /**
     * <code>.subjectmapping.SubjectMapping subject_mapping = 1 [json_name = "subjectMapping"];</code>
     */
    private com.google.protobuf.SingleFieldBuilderV3<
        io.opentdf.platform.subjectmapping.SubjectMapping, io.opentdf.platform.subjectmapping.SubjectMapping.Builder, io.opentdf.platform.subjectmapping.SubjectMappingOrBuilder> 
        getSubjectMappingFieldBuilder() {
      if (subjectMappingBuilder_ == null) {
        subjectMappingBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
            io.opentdf.platform.subjectmapping.SubjectMapping, io.opentdf.platform.subjectmapping.SubjectMapping.Builder, io.opentdf.platform.subjectmapping.SubjectMappingOrBuilder>(
                getSubjectMapping(),
                getParentForChildren(),
                isClean());
        subjectMapping_ = null;
      }
      return subjectMappingBuilder_;
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


    // @@protoc_insertion_point(builder_scope:subjectmapping.UpdateSubjectMappingResponse)
  }

  // @@protoc_insertion_point(class_scope:subjectmapping.UpdateSubjectMappingResponse)
  private static final io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse();
  }

  public static io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<UpdateSubjectMappingResponse>
      PARSER = new com.google.protobuf.AbstractParser<UpdateSubjectMappingResponse>() {
    @java.lang.Override
    public UpdateSubjectMappingResponse parsePartialFrom(
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

  public static com.google.protobuf.Parser<UpdateSubjectMappingResponse> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<UpdateSubjectMappingResponse> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public io.opentdf.platform.subjectmapping.UpdateSubjectMappingResponse getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

