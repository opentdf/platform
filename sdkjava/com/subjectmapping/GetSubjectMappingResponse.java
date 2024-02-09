// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: subjectmapping/subject_mapping.proto

// Protobuf Java Version: 3.25.2
package com.subjectmapping;

/**
 * Protobuf type {@code subjectmapping.GetSubjectMappingResponse}
 */
public final class GetSubjectMappingResponse extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:subjectmapping.GetSubjectMappingResponse)
    GetSubjectMappingResponseOrBuilder {
private static final long serialVersionUID = 0L;
  // Use GetSubjectMappingResponse.newBuilder() to construct.
  private GetSubjectMappingResponse(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private GetSubjectMappingResponse() {
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new GetSubjectMappingResponse();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return com.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_GetSubjectMappingResponse_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return com.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_GetSubjectMappingResponse_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            com.subjectmapping.GetSubjectMappingResponse.class, com.subjectmapping.GetSubjectMappingResponse.Builder.class);
  }

  private int bitField0_;
  public static final int SUBJECT_MAPPING_FIELD_NUMBER = 1;
  private com.subjectmapping.SubjectMapping subjectMapping_;
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
  public com.subjectmapping.SubjectMapping getSubjectMapping() {
    return subjectMapping_ == null ? com.subjectmapping.SubjectMapping.getDefaultInstance() : subjectMapping_;
  }
  /**
   * <code>.subjectmapping.SubjectMapping subject_mapping = 1 [json_name = "subjectMapping"];</code>
   */
  @java.lang.Override
  public com.subjectmapping.SubjectMappingOrBuilder getSubjectMappingOrBuilder() {
    return subjectMapping_ == null ? com.subjectmapping.SubjectMapping.getDefaultInstance() : subjectMapping_;
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
    if (!(obj instanceof com.subjectmapping.GetSubjectMappingResponse)) {
      return super.equals(obj);
    }
    com.subjectmapping.GetSubjectMappingResponse other = (com.subjectmapping.GetSubjectMappingResponse) obj;

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

  public static com.subjectmapping.GetSubjectMappingResponse parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.subjectmapping.GetSubjectMappingResponse parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.subjectmapping.GetSubjectMappingResponse parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.subjectmapping.GetSubjectMappingResponse parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.subjectmapping.GetSubjectMappingResponse parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.subjectmapping.GetSubjectMappingResponse parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.subjectmapping.GetSubjectMappingResponse parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.subjectmapping.GetSubjectMappingResponse parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static com.subjectmapping.GetSubjectMappingResponse parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static com.subjectmapping.GetSubjectMappingResponse parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static com.subjectmapping.GetSubjectMappingResponse parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.subjectmapping.GetSubjectMappingResponse parseFrom(
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
  public static Builder newBuilder(com.subjectmapping.GetSubjectMappingResponse prototype) {
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
   * Protobuf type {@code subjectmapping.GetSubjectMappingResponse}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:subjectmapping.GetSubjectMappingResponse)
      com.subjectmapping.GetSubjectMappingResponseOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return com.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_GetSubjectMappingResponse_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return com.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_GetSubjectMappingResponse_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              com.subjectmapping.GetSubjectMappingResponse.class, com.subjectmapping.GetSubjectMappingResponse.Builder.class);
    }

    // Construct using com.subjectmapping.GetSubjectMappingResponse.newBuilder()
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
      return com.subjectmapping.SubjectMappingProto.internal_static_subjectmapping_GetSubjectMappingResponse_descriptor;
    }

    @java.lang.Override
    public com.subjectmapping.GetSubjectMappingResponse getDefaultInstanceForType() {
      return com.subjectmapping.GetSubjectMappingResponse.getDefaultInstance();
    }

    @java.lang.Override
    public com.subjectmapping.GetSubjectMappingResponse build() {
      com.subjectmapping.GetSubjectMappingResponse result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public com.subjectmapping.GetSubjectMappingResponse buildPartial() {
      com.subjectmapping.GetSubjectMappingResponse result = new com.subjectmapping.GetSubjectMappingResponse(this);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartial0(com.subjectmapping.GetSubjectMappingResponse result) {
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
      if (other instanceof com.subjectmapping.GetSubjectMappingResponse) {
        return mergeFrom((com.subjectmapping.GetSubjectMappingResponse)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(com.subjectmapping.GetSubjectMappingResponse other) {
      if (other == com.subjectmapping.GetSubjectMappingResponse.getDefaultInstance()) return this;
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

    private com.subjectmapping.SubjectMapping subjectMapping_;
    private com.google.protobuf.SingleFieldBuilderV3<
        com.subjectmapping.SubjectMapping, com.subjectmapping.SubjectMapping.Builder, com.subjectmapping.SubjectMappingOrBuilder> subjectMappingBuilder_;
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
    public com.subjectmapping.SubjectMapping getSubjectMapping() {
      if (subjectMappingBuilder_ == null) {
        return subjectMapping_ == null ? com.subjectmapping.SubjectMapping.getDefaultInstance() : subjectMapping_;
      } else {
        return subjectMappingBuilder_.getMessage();
      }
    }
    /**
     * <code>.subjectmapping.SubjectMapping subject_mapping = 1 [json_name = "subjectMapping"];</code>
     */
    public Builder setSubjectMapping(com.subjectmapping.SubjectMapping value) {
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
        com.subjectmapping.SubjectMapping.Builder builderForValue) {
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
    public Builder mergeSubjectMapping(com.subjectmapping.SubjectMapping value) {
      if (subjectMappingBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0) &&
          subjectMapping_ != null &&
          subjectMapping_ != com.subjectmapping.SubjectMapping.getDefaultInstance()) {
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
    public com.subjectmapping.SubjectMapping.Builder getSubjectMappingBuilder() {
      bitField0_ |= 0x00000001;
      onChanged();
      return getSubjectMappingFieldBuilder().getBuilder();
    }
    /**
     * <code>.subjectmapping.SubjectMapping subject_mapping = 1 [json_name = "subjectMapping"];</code>
     */
    public com.subjectmapping.SubjectMappingOrBuilder getSubjectMappingOrBuilder() {
      if (subjectMappingBuilder_ != null) {
        return subjectMappingBuilder_.getMessageOrBuilder();
      } else {
        return subjectMapping_ == null ?
            com.subjectmapping.SubjectMapping.getDefaultInstance() : subjectMapping_;
      }
    }
    /**
     * <code>.subjectmapping.SubjectMapping subject_mapping = 1 [json_name = "subjectMapping"];</code>
     */
    private com.google.protobuf.SingleFieldBuilderV3<
        com.subjectmapping.SubjectMapping, com.subjectmapping.SubjectMapping.Builder, com.subjectmapping.SubjectMappingOrBuilder> 
        getSubjectMappingFieldBuilder() {
      if (subjectMappingBuilder_ == null) {
        subjectMappingBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
            com.subjectmapping.SubjectMapping, com.subjectmapping.SubjectMapping.Builder, com.subjectmapping.SubjectMappingOrBuilder>(
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


    // @@protoc_insertion_point(builder_scope:subjectmapping.GetSubjectMappingResponse)
  }

  // @@protoc_insertion_point(class_scope:subjectmapping.GetSubjectMappingResponse)
  private static final com.subjectmapping.GetSubjectMappingResponse DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new com.subjectmapping.GetSubjectMappingResponse();
  }

  public static com.subjectmapping.GetSubjectMappingResponse getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<GetSubjectMappingResponse>
      PARSER = new com.google.protobuf.AbstractParser<GetSubjectMappingResponse>() {
    @java.lang.Override
    public GetSubjectMappingResponse parsePartialFrom(
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

  public static com.google.protobuf.Parser<GetSubjectMappingResponse> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<GetSubjectMappingResponse> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public com.subjectmapping.GetSubjectMappingResponse getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

