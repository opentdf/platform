// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: attributes/attributes.proto

// Protobuf Java Version: 3.25.2
package com.attributes;

/**
 * Protobuf type {@code attributes.CreateAttributeValueRequest}
 */
public final class CreateAttributeValueRequest extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:attributes.CreateAttributeValueRequest)
    CreateAttributeValueRequestOrBuilder {
private static final long serialVersionUID = 0L;
  // Use CreateAttributeValueRequest.newBuilder() to construct.
  private CreateAttributeValueRequest(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private CreateAttributeValueRequest() {
    attributeId_ = "";
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new CreateAttributeValueRequest();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return com.attributes.AttributesProto.internal_static_attributes_CreateAttributeValueRequest_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return com.attributes.AttributesProto.internal_static_attributes_CreateAttributeValueRequest_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            com.attributes.CreateAttributeValueRequest.class, com.attributes.CreateAttributeValueRequest.Builder.class);
  }

  private int bitField0_;
  public static final int ATTRIBUTE_ID_FIELD_NUMBER = 1;
  @SuppressWarnings("serial")
  private volatile java.lang.Object attributeId_ = "";
  /**
   * <code>string attribute_id = 1 [json_name = "attributeId", (.buf.validate.field) = { ... }</code>
   * @return The attributeId.
   */
  @java.lang.Override
  public java.lang.String getAttributeId() {
    java.lang.Object ref = attributeId_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      attributeId_ = s;
      return s;
    }
  }
  /**
   * <code>string attribute_id = 1 [json_name = "attributeId", (.buf.validate.field) = { ... }</code>
   * @return The bytes for attributeId.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString
      getAttributeIdBytes() {
    java.lang.Object ref = attributeId_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      attributeId_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int VALUE_FIELD_NUMBER = 2;
  private com.attributes.ValueCreateUpdate value_;
  /**
   * <code>.attributes.ValueCreateUpdate value = 2 [json_name = "value", (.buf.validate.field) = { ... }</code>
   * @return Whether the value field is set.
   */
  @java.lang.Override
  public boolean hasValue() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <code>.attributes.ValueCreateUpdate value = 2 [json_name = "value", (.buf.validate.field) = { ... }</code>
   * @return The value.
   */
  @java.lang.Override
  public com.attributes.ValueCreateUpdate getValue() {
    return value_ == null ? com.attributes.ValueCreateUpdate.getDefaultInstance() : value_;
  }
  /**
   * <code>.attributes.ValueCreateUpdate value = 2 [json_name = "value", (.buf.validate.field) = { ... }</code>
   */
  @java.lang.Override
  public com.attributes.ValueCreateUpdateOrBuilder getValueOrBuilder() {
    return value_ == null ? com.attributes.ValueCreateUpdate.getDefaultInstance() : value_;
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
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(attributeId_)) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 1, attributeId_);
    }
    if (((bitField0_ & 0x00000001) != 0)) {
      output.writeMessage(2, getValue());
    }
    getUnknownFields().writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(attributeId_)) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(1, attributeId_);
    }
    if (((bitField0_ & 0x00000001) != 0)) {
      size += com.google.protobuf.CodedOutputStream
        .computeMessageSize(2, getValue());
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
    if (!(obj instanceof com.attributes.CreateAttributeValueRequest)) {
      return super.equals(obj);
    }
    com.attributes.CreateAttributeValueRequest other = (com.attributes.CreateAttributeValueRequest) obj;

    if (!getAttributeId()
        .equals(other.getAttributeId())) return false;
    if (hasValue() != other.hasValue()) return false;
    if (hasValue()) {
      if (!getValue()
          .equals(other.getValue())) return false;
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
    hash = (37 * hash) + ATTRIBUTE_ID_FIELD_NUMBER;
    hash = (53 * hash) + getAttributeId().hashCode();
    if (hasValue()) {
      hash = (37 * hash) + VALUE_FIELD_NUMBER;
      hash = (53 * hash) + getValue().hashCode();
    }
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static com.attributes.CreateAttributeValueRequest parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.attributes.CreateAttributeValueRequest parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.attributes.CreateAttributeValueRequest parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.attributes.CreateAttributeValueRequest parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.attributes.CreateAttributeValueRequest parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.attributes.CreateAttributeValueRequest parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.attributes.CreateAttributeValueRequest parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.attributes.CreateAttributeValueRequest parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static com.attributes.CreateAttributeValueRequest parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static com.attributes.CreateAttributeValueRequest parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static com.attributes.CreateAttributeValueRequest parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.attributes.CreateAttributeValueRequest parseFrom(
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
  public static Builder newBuilder(com.attributes.CreateAttributeValueRequest prototype) {
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
   * Protobuf type {@code attributes.CreateAttributeValueRequest}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:attributes.CreateAttributeValueRequest)
      com.attributes.CreateAttributeValueRequestOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return com.attributes.AttributesProto.internal_static_attributes_CreateAttributeValueRequest_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return com.attributes.AttributesProto.internal_static_attributes_CreateAttributeValueRequest_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              com.attributes.CreateAttributeValueRequest.class, com.attributes.CreateAttributeValueRequest.Builder.class);
    }

    // Construct using com.attributes.CreateAttributeValueRequest.newBuilder()
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
        getValueFieldBuilder();
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      bitField0_ = 0;
      attributeId_ = "";
      value_ = null;
      if (valueBuilder_ != null) {
        valueBuilder_.dispose();
        valueBuilder_ = null;
      }
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return com.attributes.AttributesProto.internal_static_attributes_CreateAttributeValueRequest_descriptor;
    }

    @java.lang.Override
    public com.attributes.CreateAttributeValueRequest getDefaultInstanceForType() {
      return com.attributes.CreateAttributeValueRequest.getDefaultInstance();
    }

    @java.lang.Override
    public com.attributes.CreateAttributeValueRequest build() {
      com.attributes.CreateAttributeValueRequest result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public com.attributes.CreateAttributeValueRequest buildPartial() {
      com.attributes.CreateAttributeValueRequest result = new com.attributes.CreateAttributeValueRequest(this);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartial0(com.attributes.CreateAttributeValueRequest result) {
      int from_bitField0_ = bitField0_;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        result.attributeId_ = attributeId_;
      }
      int to_bitField0_ = 0;
      if (((from_bitField0_ & 0x00000002) != 0)) {
        result.value_ = valueBuilder_ == null
            ? value_
            : valueBuilder_.build();
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
      if (other instanceof com.attributes.CreateAttributeValueRequest) {
        return mergeFrom((com.attributes.CreateAttributeValueRequest)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(com.attributes.CreateAttributeValueRequest other) {
      if (other == com.attributes.CreateAttributeValueRequest.getDefaultInstance()) return this;
      if (!other.getAttributeId().isEmpty()) {
        attributeId_ = other.attributeId_;
        bitField0_ |= 0x00000001;
        onChanged();
      }
      if (other.hasValue()) {
        mergeValue(other.getValue());
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
              attributeId_ = input.readStringRequireUtf8();
              bitField0_ |= 0x00000001;
              break;
            } // case 10
            case 18: {
              input.readMessage(
                  getValueFieldBuilder().getBuilder(),
                  extensionRegistry);
              bitField0_ |= 0x00000002;
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

    private java.lang.Object attributeId_ = "";
    /**
     * <code>string attribute_id = 1 [json_name = "attributeId", (.buf.validate.field) = { ... }</code>
     * @return The attributeId.
     */
    public java.lang.String getAttributeId() {
      java.lang.Object ref = attributeId_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        attributeId_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>string attribute_id = 1 [json_name = "attributeId", (.buf.validate.field) = { ... }</code>
     * @return The bytes for attributeId.
     */
    public com.google.protobuf.ByteString
        getAttributeIdBytes() {
      java.lang.Object ref = attributeId_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        attributeId_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>string attribute_id = 1 [json_name = "attributeId", (.buf.validate.field) = { ... }</code>
     * @param value The attributeId to set.
     * @return This builder for chaining.
     */
    public Builder setAttributeId(
        java.lang.String value) {
      if (value == null) { throw new NullPointerException(); }
      attributeId_ = value;
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>string attribute_id = 1 [json_name = "attributeId", (.buf.validate.field) = { ... }</code>
     * @return This builder for chaining.
     */
    public Builder clearAttributeId() {
      attributeId_ = getDefaultInstance().getAttributeId();
      bitField0_ = (bitField0_ & ~0x00000001);
      onChanged();
      return this;
    }
    /**
     * <code>string attribute_id = 1 [json_name = "attributeId", (.buf.validate.field) = { ... }</code>
     * @param value The bytes for attributeId to set.
     * @return This builder for chaining.
     */
    public Builder setAttributeIdBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) { throw new NullPointerException(); }
      checkByteStringIsUtf8(value);
      attributeId_ = value;
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }

    private com.attributes.ValueCreateUpdate value_;
    private com.google.protobuf.SingleFieldBuilderV3<
        com.attributes.ValueCreateUpdate, com.attributes.ValueCreateUpdate.Builder, com.attributes.ValueCreateUpdateOrBuilder> valueBuilder_;
    /**
     * <code>.attributes.ValueCreateUpdate value = 2 [json_name = "value", (.buf.validate.field) = { ... }</code>
     * @return Whether the value field is set.
     */
    public boolean hasValue() {
      return ((bitField0_ & 0x00000002) != 0);
    }
    /**
     * <code>.attributes.ValueCreateUpdate value = 2 [json_name = "value", (.buf.validate.field) = { ... }</code>
     * @return The value.
     */
    public com.attributes.ValueCreateUpdate getValue() {
      if (valueBuilder_ == null) {
        return value_ == null ? com.attributes.ValueCreateUpdate.getDefaultInstance() : value_;
      } else {
        return valueBuilder_.getMessage();
      }
    }
    /**
     * <code>.attributes.ValueCreateUpdate value = 2 [json_name = "value", (.buf.validate.field) = { ... }</code>
     */
    public Builder setValue(com.attributes.ValueCreateUpdate value) {
      if (valueBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        value_ = value;
      } else {
        valueBuilder_.setMessage(value);
      }
      bitField0_ |= 0x00000002;
      onChanged();
      return this;
    }
    /**
     * <code>.attributes.ValueCreateUpdate value = 2 [json_name = "value", (.buf.validate.field) = { ... }</code>
     */
    public Builder setValue(
        com.attributes.ValueCreateUpdate.Builder builderForValue) {
      if (valueBuilder_ == null) {
        value_ = builderForValue.build();
      } else {
        valueBuilder_.setMessage(builderForValue.build());
      }
      bitField0_ |= 0x00000002;
      onChanged();
      return this;
    }
    /**
     * <code>.attributes.ValueCreateUpdate value = 2 [json_name = "value", (.buf.validate.field) = { ... }</code>
     */
    public Builder mergeValue(com.attributes.ValueCreateUpdate value) {
      if (valueBuilder_ == null) {
        if (((bitField0_ & 0x00000002) != 0) &&
          value_ != null &&
          value_ != com.attributes.ValueCreateUpdate.getDefaultInstance()) {
          getValueBuilder().mergeFrom(value);
        } else {
          value_ = value;
        }
      } else {
        valueBuilder_.mergeFrom(value);
      }
      if (value_ != null) {
        bitField0_ |= 0x00000002;
        onChanged();
      }
      return this;
    }
    /**
     * <code>.attributes.ValueCreateUpdate value = 2 [json_name = "value", (.buf.validate.field) = { ... }</code>
     */
    public Builder clearValue() {
      bitField0_ = (bitField0_ & ~0x00000002);
      value_ = null;
      if (valueBuilder_ != null) {
        valueBuilder_.dispose();
        valueBuilder_ = null;
      }
      onChanged();
      return this;
    }
    /**
     * <code>.attributes.ValueCreateUpdate value = 2 [json_name = "value", (.buf.validate.field) = { ... }</code>
     */
    public com.attributes.ValueCreateUpdate.Builder getValueBuilder() {
      bitField0_ |= 0x00000002;
      onChanged();
      return getValueFieldBuilder().getBuilder();
    }
    /**
     * <code>.attributes.ValueCreateUpdate value = 2 [json_name = "value", (.buf.validate.field) = { ... }</code>
     */
    public com.attributes.ValueCreateUpdateOrBuilder getValueOrBuilder() {
      if (valueBuilder_ != null) {
        return valueBuilder_.getMessageOrBuilder();
      } else {
        return value_ == null ?
            com.attributes.ValueCreateUpdate.getDefaultInstance() : value_;
      }
    }
    /**
     * <code>.attributes.ValueCreateUpdate value = 2 [json_name = "value", (.buf.validate.field) = { ... }</code>
     */
    private com.google.protobuf.SingleFieldBuilderV3<
        com.attributes.ValueCreateUpdate, com.attributes.ValueCreateUpdate.Builder, com.attributes.ValueCreateUpdateOrBuilder> 
        getValueFieldBuilder() {
      if (valueBuilder_ == null) {
        valueBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
            com.attributes.ValueCreateUpdate, com.attributes.ValueCreateUpdate.Builder, com.attributes.ValueCreateUpdateOrBuilder>(
                getValue(),
                getParentForChildren(),
                isClean());
        value_ = null;
      }
      return valueBuilder_;
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


    // @@protoc_insertion_point(builder_scope:attributes.CreateAttributeValueRequest)
  }

  // @@protoc_insertion_point(class_scope:attributes.CreateAttributeValueRequest)
  private static final com.attributes.CreateAttributeValueRequest DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new com.attributes.CreateAttributeValueRequest();
  }

  public static com.attributes.CreateAttributeValueRequest getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<CreateAttributeValueRequest>
      PARSER = new com.google.protobuf.AbstractParser<CreateAttributeValueRequest>() {
    @java.lang.Override
    public CreateAttributeValueRequest parsePartialFrom(
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

  public static com.google.protobuf.Parser<CreateAttributeValueRequest> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<CreateAttributeValueRequest> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public com.attributes.CreateAttributeValueRequest getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

