// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: attributes/attributes.proto

// Protobuf Java Version: 3.25.3
package com.attributes;

/**
 * Protobuf type {@code attributes.CreateAttributeResponse}
 */
public final class CreateAttributeResponse extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:attributes.CreateAttributeResponse)
    CreateAttributeResponseOrBuilder {
private static final long serialVersionUID = 0L;
  // Use CreateAttributeResponse.newBuilder() to construct.
  private CreateAttributeResponse(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private CreateAttributeResponse() {
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new CreateAttributeResponse();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return com.attributes.AttributesProto.internal_static_attributes_CreateAttributeResponse_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return com.attributes.AttributesProto.internal_static_attributes_CreateAttributeResponse_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            com.attributes.CreateAttributeResponse.class, com.attributes.CreateAttributeResponse.Builder.class);
  }

  private int bitField0_;
  public static final int ATTRIBUTE_FIELD_NUMBER = 1;
  private com.attributes.Attribute attribute_;
  /**
   * <code>.attributes.Attribute attribute = 1 [json_name = "attribute"];</code>
   * @return Whether the attribute field is set.
   */
  @java.lang.Override
  public boolean hasAttribute() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <code>.attributes.Attribute attribute = 1 [json_name = "attribute"];</code>
   * @return The attribute.
   */
  @java.lang.Override
  public com.attributes.Attribute getAttribute() {
    return attribute_ == null ? com.attributes.Attribute.getDefaultInstance() : attribute_;
  }
  /**
   * <code>.attributes.Attribute attribute = 1 [json_name = "attribute"];</code>
   */
  @java.lang.Override
  public com.attributes.AttributeOrBuilder getAttributeOrBuilder() {
    return attribute_ == null ? com.attributes.Attribute.getDefaultInstance() : attribute_;
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
      output.writeMessage(1, getAttribute());
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
        .computeMessageSize(1, getAttribute());
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
    if (!(obj instanceof com.attributes.CreateAttributeResponse)) {
      return super.equals(obj);
    }
    com.attributes.CreateAttributeResponse other = (com.attributes.CreateAttributeResponse) obj;

    if (hasAttribute() != other.hasAttribute()) return false;
    if (hasAttribute()) {
      if (!getAttribute()
          .equals(other.getAttribute())) return false;
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
    if (hasAttribute()) {
      hash = (37 * hash) + ATTRIBUTE_FIELD_NUMBER;
      hash = (53 * hash) + getAttribute().hashCode();
    }
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static com.attributes.CreateAttributeResponse parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.attributes.CreateAttributeResponse parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.attributes.CreateAttributeResponse parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.attributes.CreateAttributeResponse parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.attributes.CreateAttributeResponse parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.attributes.CreateAttributeResponse parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.attributes.CreateAttributeResponse parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.attributes.CreateAttributeResponse parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static com.attributes.CreateAttributeResponse parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static com.attributes.CreateAttributeResponse parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static com.attributes.CreateAttributeResponse parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.attributes.CreateAttributeResponse parseFrom(
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
  public static Builder newBuilder(com.attributes.CreateAttributeResponse prototype) {
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
   * Protobuf type {@code attributes.CreateAttributeResponse}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:attributes.CreateAttributeResponse)
      com.attributes.CreateAttributeResponseOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return com.attributes.AttributesProto.internal_static_attributes_CreateAttributeResponse_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return com.attributes.AttributesProto.internal_static_attributes_CreateAttributeResponse_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              com.attributes.CreateAttributeResponse.class, com.attributes.CreateAttributeResponse.Builder.class);
    }

    // Construct using com.attributes.CreateAttributeResponse.newBuilder()
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
        getAttributeFieldBuilder();
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      bitField0_ = 0;
      attribute_ = null;
      if (attributeBuilder_ != null) {
        attributeBuilder_.dispose();
        attributeBuilder_ = null;
      }
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return com.attributes.AttributesProto.internal_static_attributes_CreateAttributeResponse_descriptor;
    }

    @java.lang.Override
    public com.attributes.CreateAttributeResponse getDefaultInstanceForType() {
      return com.attributes.CreateAttributeResponse.getDefaultInstance();
    }

    @java.lang.Override
    public com.attributes.CreateAttributeResponse build() {
      com.attributes.CreateAttributeResponse result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public com.attributes.CreateAttributeResponse buildPartial() {
      com.attributes.CreateAttributeResponse result = new com.attributes.CreateAttributeResponse(this);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartial0(com.attributes.CreateAttributeResponse result) {
      int from_bitField0_ = bitField0_;
      int to_bitField0_ = 0;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        result.attribute_ = attributeBuilder_ == null
            ? attribute_
            : attributeBuilder_.build();
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
      if (other instanceof com.attributes.CreateAttributeResponse) {
        return mergeFrom((com.attributes.CreateAttributeResponse)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(com.attributes.CreateAttributeResponse other) {
      if (other == com.attributes.CreateAttributeResponse.getDefaultInstance()) return this;
      if (other.hasAttribute()) {
        mergeAttribute(other.getAttribute());
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
                  getAttributeFieldBuilder().getBuilder(),
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

    private com.attributes.Attribute attribute_;
    private com.google.protobuf.SingleFieldBuilderV3<
        com.attributes.Attribute, com.attributes.Attribute.Builder, com.attributes.AttributeOrBuilder> attributeBuilder_;
    /**
     * <code>.attributes.Attribute attribute = 1 [json_name = "attribute"];</code>
     * @return Whether the attribute field is set.
     */
    public boolean hasAttribute() {
      return ((bitField0_ & 0x00000001) != 0);
    }
    /**
     * <code>.attributes.Attribute attribute = 1 [json_name = "attribute"];</code>
     * @return The attribute.
     */
    public com.attributes.Attribute getAttribute() {
      if (attributeBuilder_ == null) {
        return attribute_ == null ? com.attributes.Attribute.getDefaultInstance() : attribute_;
      } else {
        return attributeBuilder_.getMessage();
      }
    }
    /**
     * <code>.attributes.Attribute attribute = 1 [json_name = "attribute"];</code>
     */
    public Builder setAttribute(com.attributes.Attribute value) {
      if (attributeBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        attribute_ = value;
      } else {
        attributeBuilder_.setMessage(value);
      }
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>.attributes.Attribute attribute = 1 [json_name = "attribute"];</code>
     */
    public Builder setAttribute(
        com.attributes.Attribute.Builder builderForValue) {
      if (attributeBuilder_ == null) {
        attribute_ = builderForValue.build();
      } else {
        attributeBuilder_.setMessage(builderForValue.build());
      }
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>.attributes.Attribute attribute = 1 [json_name = "attribute"];</code>
     */
    public Builder mergeAttribute(com.attributes.Attribute value) {
      if (attributeBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0) &&
          attribute_ != null &&
          attribute_ != com.attributes.Attribute.getDefaultInstance()) {
          getAttributeBuilder().mergeFrom(value);
        } else {
          attribute_ = value;
        }
      } else {
        attributeBuilder_.mergeFrom(value);
      }
      if (attribute_ != null) {
        bitField0_ |= 0x00000001;
        onChanged();
      }
      return this;
    }
    /**
     * <code>.attributes.Attribute attribute = 1 [json_name = "attribute"];</code>
     */
    public Builder clearAttribute() {
      bitField0_ = (bitField0_ & ~0x00000001);
      attribute_ = null;
      if (attributeBuilder_ != null) {
        attributeBuilder_.dispose();
        attributeBuilder_ = null;
      }
      onChanged();
      return this;
    }
    /**
     * <code>.attributes.Attribute attribute = 1 [json_name = "attribute"];</code>
     */
    public com.attributes.Attribute.Builder getAttributeBuilder() {
      bitField0_ |= 0x00000001;
      onChanged();
      return getAttributeFieldBuilder().getBuilder();
    }
    /**
     * <code>.attributes.Attribute attribute = 1 [json_name = "attribute"];</code>
     */
    public com.attributes.AttributeOrBuilder getAttributeOrBuilder() {
      if (attributeBuilder_ != null) {
        return attributeBuilder_.getMessageOrBuilder();
      } else {
        return attribute_ == null ?
            com.attributes.Attribute.getDefaultInstance() : attribute_;
      }
    }
    /**
     * <code>.attributes.Attribute attribute = 1 [json_name = "attribute"];</code>
     */
    private com.google.protobuf.SingleFieldBuilderV3<
        com.attributes.Attribute, com.attributes.Attribute.Builder, com.attributes.AttributeOrBuilder> 
        getAttributeFieldBuilder() {
      if (attributeBuilder_ == null) {
        attributeBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
            com.attributes.Attribute, com.attributes.Attribute.Builder, com.attributes.AttributeOrBuilder>(
                getAttribute(),
                getParentForChildren(),
                isClean());
        attribute_ = null;
      }
      return attributeBuilder_;
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


    // @@protoc_insertion_point(builder_scope:attributes.CreateAttributeResponse)
  }

  // @@protoc_insertion_point(class_scope:attributes.CreateAttributeResponse)
  private static final com.attributes.CreateAttributeResponse DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new com.attributes.CreateAttributeResponse();
  }

  public static com.attributes.CreateAttributeResponse getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<CreateAttributeResponse>
      PARSER = new com.google.protobuf.AbstractParser<CreateAttributeResponse>() {
    @java.lang.Override
    public CreateAttributeResponse parsePartialFrom(
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

  public static com.google.protobuf.Parser<CreateAttributeResponse> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<CreateAttributeResponse> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public com.attributes.CreateAttributeResponse getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

