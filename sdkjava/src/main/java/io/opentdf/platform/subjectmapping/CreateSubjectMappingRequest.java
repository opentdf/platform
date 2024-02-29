// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/subjectmapping/subject_mapping.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.subjectmapping;

/**
 * Protobuf type {@code subjectmapping.CreateSubjectMappingRequest}
 */
public final class CreateSubjectMappingRequest extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:subjectmapping.CreateSubjectMappingRequest)
    CreateSubjectMappingRequestOrBuilder {
private static final long serialVersionUID = 0L;
  // Use CreateSubjectMappingRequest.newBuilder() to construct.
  private CreateSubjectMappingRequest(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private CreateSubjectMappingRequest() {
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new CreateSubjectMappingRequest();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return io.opentdf.platform.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_CreateSubjectMappingRequest_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return io.opentdf.platform.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_CreateSubjectMappingRequest_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest.class, io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest.Builder.class);
  }

  private int bitField0_;
  public static final int SUBJECT_MAPPING_FIELD_NUMBER = 1;
  private io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate subjectMapping_;
  /**
   * <code>.subjectmapping.SubjectMappingCreateUpdate subject_mapping = 1 [json_name = "subjectMapping", (.buf.validate.field) = { ... }</code>
   * @return Whether the subjectMapping field is set.
   */
  @java.lang.Override
  public boolean hasSubjectMapping() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <code>.subjectmapping.SubjectMappingCreateUpdate subject_mapping = 1 [json_name = "subjectMapping", (.buf.validate.field) = { ... }</code>
   * @return The subjectMapping.
   */
  @java.lang.Override
  public io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate getSubjectMapping() {
    return subjectMapping_ == null ? io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate.getDefaultInstance() : subjectMapping_;
  }
  /**
   * <code>.subjectmapping.SubjectMappingCreateUpdate subject_mapping = 1 [json_name = "subjectMapping", (.buf.validate.field) = { ... }</code>
   */
  @java.lang.Override
  public io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdateOrBuilder getSubjectMappingOrBuilder() {
    return subjectMapping_ == null ? io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate.getDefaultInstance() : subjectMapping_;
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
    if (!(obj instanceof io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest)) {
      return super.equals(obj);
    }
    io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest other = (io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest) obj;

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

  public static io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest parseFrom(
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
  public static Builder newBuilder(io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest prototype) {
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
   * Protobuf type {@code subjectmapping.CreateSubjectMappingRequest}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:subjectmapping.CreateSubjectMappingRequest)
      io.opentdf.platform.subjectmapping.CreateSubjectMappingRequestOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return io.opentdf.platform.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_CreateSubjectMappingRequest_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return io.opentdf.platform.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_CreateSubjectMappingRequest_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest.class, io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest.Builder.class);
    }

    // Construct using io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest.newBuilder()
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
      return io.opentdf.platform.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_CreateSubjectMappingRequest_descriptor;
    }

    @java.lang.Override
    public io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest getDefaultInstanceForType() {
      return io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest.getDefaultInstance();
    }

    @java.lang.Override
    public io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest build() {
      io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest buildPartial() {
      io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest result = new io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest(this);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartial0(io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest result) {
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
      if (other instanceof io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest) {
        return mergeFrom((io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest other) {
      if (other == io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest.getDefaultInstance()) return this;
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

    private io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate subjectMapping_;
    private com.google.protobuf.SingleFieldBuilderV3<
        io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate, io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate.Builder, io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdateOrBuilder> subjectMappingBuilder_;
    /**
     * <code>.subjectmapping.SubjectMappingCreateUpdate subject_mapping = 1 [json_name = "subjectMapping", (.buf.validate.field) = { ... }</code>
     * @return Whether the subjectMapping field is set.
     */
    public boolean hasSubjectMapping() {
      return ((bitField0_ & 0x00000001) != 0);
    }
    /**
     * <code>.subjectmapping.SubjectMappingCreateUpdate subject_mapping = 1 [json_name = "subjectMapping", (.buf.validate.field) = { ... }</code>
     * @return The subjectMapping.
     */
    public io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate getSubjectMapping() {
      if (subjectMappingBuilder_ == null) {
        return subjectMapping_ == null ? io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate.getDefaultInstance() : subjectMapping_;
      } else {
        return subjectMappingBuilder_.getMessage();
      }
    }
    /**
     * <code>.subjectmapping.SubjectMappingCreateUpdate subject_mapping = 1 [json_name = "subjectMapping", (.buf.validate.field) = { ... }</code>
     */
    public Builder setSubjectMapping(io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate value) {
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
     * <code>.subjectmapping.SubjectMappingCreateUpdate subject_mapping = 1 [json_name = "subjectMapping", (.buf.validate.field) = { ... }</code>
     */
    public Builder setSubjectMapping(
        io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate.Builder builderForValue) {
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
     * <code>.subjectmapping.SubjectMappingCreateUpdate subject_mapping = 1 [json_name = "subjectMapping", (.buf.validate.field) = { ... }</code>
     */
    public Builder mergeSubjectMapping(io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate value) {
      if (subjectMappingBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0) &&
          subjectMapping_ != null &&
          subjectMapping_ != io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate.getDefaultInstance()) {
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
     * <code>.subjectmapping.SubjectMappingCreateUpdate subject_mapping = 1 [json_name = "subjectMapping", (.buf.validate.field) = { ... }</code>
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
     * <code>.subjectmapping.SubjectMappingCreateUpdate subject_mapping = 1 [json_name = "subjectMapping", (.buf.validate.field) = { ... }</code>
     */
    public io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate.Builder getSubjectMappingBuilder() {
      bitField0_ |= 0x00000001;
      onChanged();
      return getSubjectMappingFieldBuilder().getBuilder();
    }
    /**
     * <code>.subjectmapping.SubjectMappingCreateUpdate subject_mapping = 1 [json_name = "subjectMapping", (.buf.validate.field) = { ... }</code>
     */
    public io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdateOrBuilder getSubjectMappingOrBuilder() {
      if (subjectMappingBuilder_ != null) {
        return subjectMappingBuilder_.getMessageOrBuilder();
      } else {
        return subjectMapping_ == null ?
            io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate.getDefaultInstance() : subjectMapping_;
      }
    }
    /**
     * <code>.subjectmapping.SubjectMappingCreateUpdate subject_mapping = 1 [json_name = "subjectMapping", (.buf.validate.field) = { ... }</code>
     */
    private com.google.protobuf.SingleFieldBuilderV3<
        io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate, io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate.Builder, io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdateOrBuilder> 
        getSubjectMappingFieldBuilder() {
      if (subjectMappingBuilder_ == null) {
        subjectMappingBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
            io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate, io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdate.Builder, io.opentdf.platform.subjectmapping.SubjectMappingCreateUpdateOrBuilder>(
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


    // @@protoc_insertion_point(builder_scope:subjectmapping.CreateSubjectMappingRequest)
  }

  // @@protoc_insertion_point(class_scope:subjectmapping.CreateSubjectMappingRequest)
  private static final io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest();
  }

  public static io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<CreateSubjectMappingRequest>
      PARSER = new com.google.protobuf.AbstractParser<CreateSubjectMappingRequest>() {
    @java.lang.Override
    public CreateSubjectMappingRequest parsePartialFrom(
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

  public static com.google.protobuf.Parser<CreateSubjectMappingRequest> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<CreateSubjectMappingRequest> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public io.opentdf.platform.subjectmapping.CreateSubjectMappingRequest getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

