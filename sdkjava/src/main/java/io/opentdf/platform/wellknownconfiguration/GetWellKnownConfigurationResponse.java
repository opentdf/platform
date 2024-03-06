// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: wellknownconfigurationtemp/wellknown_configuration.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.wellknownconfiguration;

/**
 * Protobuf type {@code wellknownconfiguration.GetWellKnownConfigurationResponse}
 */
public final class GetWellKnownConfigurationResponse extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:wellknownconfiguration.GetWellKnownConfigurationResponse)
    GetWellKnownConfigurationResponseOrBuilder {
private static final long serialVersionUID = 0L;
  // Use GetWellKnownConfigurationResponse.newBuilder() to construct.
  private GetWellKnownConfigurationResponse(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private GetWellKnownConfigurationResponse() {
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new GetWellKnownConfigurationResponse();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return io.opentdf.platform.wellknownconfiguration.WellknownConfigurationProto.internal_static_wellknownconfiguration_GetWellKnownConfigurationResponse_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return io.opentdf.platform.wellknownconfiguration.WellknownConfigurationProto.internal_static_wellknownconfiguration_GetWellKnownConfigurationResponse_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse.class, io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse.Builder.class);
  }

  private int bitField0_;
  public static final int CONFIGURATION_FIELD_NUMBER = 1;
  private com.google.protobuf.Struct configuration_;
  /**
   * <code>.google.protobuf.Struct configuration = 1 [json_name = "configuration"];</code>
   * @return Whether the configuration field is set.
   */
  @java.lang.Override
  public boolean hasConfiguration() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <code>.google.protobuf.Struct configuration = 1 [json_name = "configuration"];</code>
   * @return The configuration.
   */
  @java.lang.Override
  public com.google.protobuf.Struct getConfiguration() {
    return configuration_ == null ? com.google.protobuf.Struct.getDefaultInstance() : configuration_;
  }
  /**
   * <code>.google.protobuf.Struct configuration = 1 [json_name = "configuration"];</code>
   */
  @java.lang.Override
  public com.google.protobuf.StructOrBuilder getConfigurationOrBuilder() {
    return configuration_ == null ? com.google.protobuf.Struct.getDefaultInstance() : configuration_;
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
      output.writeMessage(1, getConfiguration());
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
        .computeMessageSize(1, getConfiguration());
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
    if (!(obj instanceof io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse)) {
      return super.equals(obj);
    }
    io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse other = (io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse) obj;

    if (hasConfiguration() != other.hasConfiguration()) return false;
    if (hasConfiguration()) {
      if (!getConfiguration()
          .equals(other.getConfiguration())) return false;
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
    if (hasConfiguration()) {
      hash = (37 * hash) + CONFIGURATION_FIELD_NUMBER;
      hash = (53 * hash) + getConfiguration().hashCode();
    }
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse parseFrom(
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
  public static Builder newBuilder(io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse prototype) {
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
   * Protobuf type {@code wellknownconfiguration.GetWellKnownConfigurationResponse}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:wellknownconfiguration.GetWellKnownConfigurationResponse)
      io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponseOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return io.opentdf.platform.wellknownconfiguration.WellknownConfigurationProto.internal_static_wellknownconfiguration_GetWellKnownConfigurationResponse_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return io.opentdf.platform.wellknownconfiguration.WellknownConfigurationProto.internal_static_wellknownconfiguration_GetWellKnownConfigurationResponse_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse.class, io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse.Builder.class);
    }

    // Construct using io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse.newBuilder()
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
        getConfigurationFieldBuilder();
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      bitField0_ = 0;
      configuration_ = null;
      if (configurationBuilder_ != null) {
        configurationBuilder_.dispose();
        configurationBuilder_ = null;
      }
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return io.opentdf.platform.wellknownconfiguration.WellknownConfigurationProto.internal_static_wellknownconfiguration_GetWellKnownConfigurationResponse_descriptor;
    }

    @java.lang.Override
    public io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse getDefaultInstanceForType() {
      return io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse.getDefaultInstance();
    }

    @java.lang.Override
    public io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse build() {
      io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse buildPartial() {
      io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse result = new io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse(this);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartial0(io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse result) {
      int from_bitField0_ = bitField0_;
      int to_bitField0_ = 0;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        result.configuration_ = configurationBuilder_ == null
            ? configuration_
            : configurationBuilder_.build();
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
      if (other instanceof io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse) {
        return mergeFrom((io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse other) {
      if (other == io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse.getDefaultInstance()) return this;
      if (other.hasConfiguration()) {
        mergeConfiguration(other.getConfiguration());
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
                  getConfigurationFieldBuilder().getBuilder(),
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

    private com.google.protobuf.Struct configuration_;
    private com.google.protobuf.SingleFieldBuilderV3<
        com.google.protobuf.Struct, com.google.protobuf.Struct.Builder, com.google.protobuf.StructOrBuilder> configurationBuilder_;
    /**
     * <code>.google.protobuf.Struct configuration = 1 [json_name = "configuration"];</code>
     * @return Whether the configuration field is set.
     */
    public boolean hasConfiguration() {
      return ((bitField0_ & 0x00000001) != 0);
    }
    /**
     * <code>.google.protobuf.Struct configuration = 1 [json_name = "configuration"];</code>
     * @return The configuration.
     */
    public com.google.protobuf.Struct getConfiguration() {
      if (configurationBuilder_ == null) {
        return configuration_ == null ? com.google.protobuf.Struct.getDefaultInstance() : configuration_;
      } else {
        return configurationBuilder_.getMessage();
      }
    }
    /**
     * <code>.google.protobuf.Struct configuration = 1 [json_name = "configuration"];</code>
     */
    public Builder setConfiguration(com.google.protobuf.Struct value) {
      if (configurationBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        configuration_ = value;
      } else {
        configurationBuilder_.setMessage(value);
      }
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>.google.protobuf.Struct configuration = 1 [json_name = "configuration"];</code>
     */
    public Builder setConfiguration(
        com.google.protobuf.Struct.Builder builderForValue) {
      if (configurationBuilder_ == null) {
        configuration_ = builderForValue.build();
      } else {
        configurationBuilder_.setMessage(builderForValue.build());
      }
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>.google.protobuf.Struct configuration = 1 [json_name = "configuration"];</code>
     */
    public Builder mergeConfiguration(com.google.protobuf.Struct value) {
      if (configurationBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0) &&
          configuration_ != null &&
          configuration_ != com.google.protobuf.Struct.getDefaultInstance()) {
          getConfigurationBuilder().mergeFrom(value);
        } else {
          configuration_ = value;
        }
      } else {
        configurationBuilder_.mergeFrom(value);
      }
      if (configuration_ != null) {
        bitField0_ |= 0x00000001;
        onChanged();
      }
      return this;
    }
    /**
     * <code>.google.protobuf.Struct configuration = 1 [json_name = "configuration"];</code>
     */
    public Builder clearConfiguration() {
      bitField0_ = (bitField0_ & ~0x00000001);
      configuration_ = null;
      if (configurationBuilder_ != null) {
        configurationBuilder_.dispose();
        configurationBuilder_ = null;
      }
      onChanged();
      return this;
    }
    /**
     * <code>.google.protobuf.Struct configuration = 1 [json_name = "configuration"];</code>
     */
    public com.google.protobuf.Struct.Builder getConfigurationBuilder() {
      bitField0_ |= 0x00000001;
      onChanged();
      return getConfigurationFieldBuilder().getBuilder();
    }
    /**
     * <code>.google.protobuf.Struct configuration = 1 [json_name = "configuration"];</code>
     */
    public com.google.protobuf.StructOrBuilder getConfigurationOrBuilder() {
      if (configurationBuilder_ != null) {
        return configurationBuilder_.getMessageOrBuilder();
      } else {
        return configuration_ == null ?
            com.google.protobuf.Struct.getDefaultInstance() : configuration_;
      }
    }
    /**
     * <code>.google.protobuf.Struct configuration = 1 [json_name = "configuration"];</code>
     */
    private com.google.protobuf.SingleFieldBuilderV3<
        com.google.protobuf.Struct, com.google.protobuf.Struct.Builder, com.google.protobuf.StructOrBuilder> 
        getConfigurationFieldBuilder() {
      if (configurationBuilder_ == null) {
        configurationBuilder_ = new com.google.protobuf.SingleFieldBuilderV3<
            com.google.protobuf.Struct, com.google.protobuf.Struct.Builder, com.google.protobuf.StructOrBuilder>(
                getConfiguration(),
                getParentForChildren(),
                isClean());
        configuration_ = null;
      }
      return configurationBuilder_;
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


    // @@protoc_insertion_point(builder_scope:wellknownconfiguration.GetWellKnownConfigurationResponse)
  }

  // @@protoc_insertion_point(class_scope:wellknownconfiguration.GetWellKnownConfigurationResponse)
  private static final io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse();
  }

  public static io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<GetWellKnownConfigurationResponse>
      PARSER = new com.google.protobuf.AbstractParser<GetWellKnownConfigurationResponse>() {
    @java.lang.Override
    public GetWellKnownConfigurationResponse parsePartialFrom(
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

  public static com.google.protobuf.Parser<GetWellKnownConfigurationResponse> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<GetWellKnownConfigurationResponse> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public io.opentdf.platform.wellknownconfiguration.GetWellKnownConfigurationResponse getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

