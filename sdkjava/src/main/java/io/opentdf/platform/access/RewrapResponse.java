// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: access/access.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.access;

/**
 * Protobuf type {@code access.RewrapResponse}
 */
public final class RewrapResponse extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:access.RewrapResponse)
    RewrapResponseOrBuilder {
private static final long serialVersionUID = 0L;
  // Use RewrapResponse.newBuilder() to construct.
  private RewrapResponse(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private RewrapResponse() {
    entityWrappedKey_ = com.google.protobuf.ByteString.EMPTY;
    sessionPublicKey_ = "";
    schemaVersion_ = "";
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new RewrapResponse();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return io.opentdf.platform.access.AccessProto.internal_static_access_RewrapResponse_descriptor;
  }

  @SuppressWarnings({"rawtypes"})
  @java.lang.Override
  protected com.google.protobuf.MapFieldReflectionAccessor internalGetMapFieldReflection(
      int number) {
    switch (number) {
      case 1:
        return internalGetMetadata();
      default:
        throw new RuntimeException(
            "Invalid map field number: " + number);
    }
  }
  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return io.opentdf.platform.access.AccessProto.internal_static_access_RewrapResponse_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            io.opentdf.platform.access.RewrapResponse.class, io.opentdf.platform.access.RewrapResponse.Builder.class);
  }

  public static final int METADATA_FIELD_NUMBER = 1;
  private static final class MetadataDefaultEntryHolder {
    static final com.google.protobuf.MapEntry<
        java.lang.String, com.google.protobuf.Value> defaultEntry =
            com.google.protobuf.MapEntry
            .<java.lang.String, com.google.protobuf.Value>newDefaultInstance(
                io.opentdf.platform.access.AccessProto.internal_static_access_RewrapResponse_MetadataEntry_descriptor, 
                com.google.protobuf.WireFormat.FieldType.STRING,
                "",
                com.google.protobuf.WireFormat.FieldType.MESSAGE,
                com.google.protobuf.Value.getDefaultInstance());
  }
  @SuppressWarnings("serial")
  private com.google.protobuf.MapField<
      java.lang.String, com.google.protobuf.Value> metadata_;
  private com.google.protobuf.MapField<java.lang.String, com.google.protobuf.Value>
  internalGetMetadata() {
    if (metadata_ == null) {
      return com.google.protobuf.MapField.emptyMapField(
          MetadataDefaultEntryHolder.defaultEntry);
    }
    return metadata_;
  }
  public int getMetadataCount() {
    return internalGetMetadata().getMap().size();
  }
  /**
   * <code>map&lt;string, .google.protobuf.Value&gt; metadata = 1 [json_name = "metadata"];</code>
   */
  @java.lang.Override
  public boolean containsMetadata(
      java.lang.String key) {
    if (key == null) { throw new NullPointerException("map key"); }
    return internalGetMetadata().getMap().containsKey(key);
  }
  /**
   * Use {@link #getMetadataMap()} instead.
   */
  @java.lang.Override
  @java.lang.Deprecated
  public java.util.Map<java.lang.String, com.google.protobuf.Value> getMetadata() {
    return getMetadataMap();
  }
  /**
   * <code>map&lt;string, .google.protobuf.Value&gt; metadata = 1 [json_name = "metadata"];</code>
   */
  @java.lang.Override
  public java.util.Map<java.lang.String, com.google.protobuf.Value> getMetadataMap() {
    return internalGetMetadata().getMap();
  }
  /**
   * <code>map&lt;string, .google.protobuf.Value&gt; metadata = 1 [json_name = "metadata"];</code>
   */
  @java.lang.Override
  public /* nullable */
com.google.protobuf.Value getMetadataOrDefault(
      java.lang.String key,
      /* nullable */
com.google.protobuf.Value defaultValue) {
    if (key == null) { throw new NullPointerException("map key"); }
    java.util.Map<java.lang.String, com.google.protobuf.Value> map =
        internalGetMetadata().getMap();
    return map.containsKey(key) ? map.get(key) : defaultValue;
  }
  /**
   * <code>map&lt;string, .google.protobuf.Value&gt; metadata = 1 [json_name = "metadata"];</code>
   */
  @java.lang.Override
  public com.google.protobuf.Value getMetadataOrThrow(
      java.lang.String key) {
    if (key == null) { throw new NullPointerException("map key"); }
    java.util.Map<java.lang.String, com.google.protobuf.Value> map =
        internalGetMetadata().getMap();
    if (!map.containsKey(key)) {
      throw new java.lang.IllegalArgumentException();
    }
    return map.get(key);
  }

  public static final int ENTITY_WRAPPED_KEY_FIELD_NUMBER = 2;
  private com.google.protobuf.ByteString entityWrappedKey_ = com.google.protobuf.ByteString.EMPTY;
  /**
   * <code>bytes entity_wrapped_key = 2 [json_name = "entityWrappedKey"];</code>
   * @return The entityWrappedKey.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString getEntityWrappedKey() {
    return entityWrappedKey_;
  }

  public static final int SESSION_PUBLIC_KEY_FIELD_NUMBER = 3;
  @SuppressWarnings("serial")
  private volatile java.lang.Object sessionPublicKey_ = "";
  /**
   * <code>string session_public_key = 3 [json_name = "sessionPublicKey"];</code>
   * @return The sessionPublicKey.
   */
  @java.lang.Override
  public java.lang.String getSessionPublicKey() {
    java.lang.Object ref = sessionPublicKey_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      sessionPublicKey_ = s;
      return s;
    }
  }
  /**
   * <code>string session_public_key = 3 [json_name = "sessionPublicKey"];</code>
   * @return The bytes for sessionPublicKey.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString
      getSessionPublicKeyBytes() {
    java.lang.Object ref = sessionPublicKey_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      sessionPublicKey_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int SCHEMA_VERSION_FIELD_NUMBER = 4;
  @SuppressWarnings("serial")
  private volatile java.lang.Object schemaVersion_ = "";
  /**
   * <code>string schema_version = 4 [json_name = "schemaVersion"];</code>
   * @return The schemaVersion.
   */
  @java.lang.Override
  public java.lang.String getSchemaVersion() {
    java.lang.Object ref = schemaVersion_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      schemaVersion_ = s;
      return s;
    }
  }
  /**
   * <code>string schema_version = 4 [json_name = "schemaVersion"];</code>
   * @return The bytes for schemaVersion.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString
      getSchemaVersionBytes() {
    java.lang.Object ref = schemaVersion_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      schemaVersion_ = b;
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
    com.google.protobuf.GeneratedMessageV3
      .serializeStringMapTo(
        output,
        internalGetMetadata(),
        MetadataDefaultEntryHolder.defaultEntry,
        1);
    if (!entityWrappedKey_.isEmpty()) {
      output.writeBytes(2, entityWrappedKey_);
    }
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(sessionPublicKey_)) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 3, sessionPublicKey_);
    }
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(schemaVersion_)) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 4, schemaVersion_);
    }
    getUnknownFields().writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    for (java.util.Map.Entry<java.lang.String, com.google.protobuf.Value> entry
         : internalGetMetadata().getMap().entrySet()) {
      com.google.protobuf.MapEntry<java.lang.String, com.google.protobuf.Value>
      metadata__ = MetadataDefaultEntryHolder.defaultEntry.newBuilderForType()
          .setKey(entry.getKey())
          .setValue(entry.getValue())
          .build();
      size += com.google.protobuf.CodedOutputStream
          .computeMessageSize(1, metadata__);
    }
    if (!entityWrappedKey_.isEmpty()) {
      size += com.google.protobuf.CodedOutputStream
        .computeBytesSize(2, entityWrappedKey_);
    }
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(sessionPublicKey_)) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(3, sessionPublicKey_);
    }
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(schemaVersion_)) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(4, schemaVersion_);
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
    if (!(obj instanceof io.opentdf.platform.access.RewrapResponse)) {
      return super.equals(obj);
    }
    io.opentdf.platform.access.RewrapResponse other = (io.opentdf.platform.access.RewrapResponse) obj;

    if (!internalGetMetadata().equals(
        other.internalGetMetadata())) return false;
    if (!getEntityWrappedKey()
        .equals(other.getEntityWrappedKey())) return false;
    if (!getSessionPublicKey()
        .equals(other.getSessionPublicKey())) return false;
    if (!getSchemaVersion()
        .equals(other.getSchemaVersion())) return false;
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
    if (!internalGetMetadata().getMap().isEmpty()) {
      hash = (37 * hash) + METADATA_FIELD_NUMBER;
      hash = (53 * hash) + internalGetMetadata().hashCode();
    }
    hash = (37 * hash) + ENTITY_WRAPPED_KEY_FIELD_NUMBER;
    hash = (53 * hash) + getEntityWrappedKey().hashCode();
    hash = (37 * hash) + SESSION_PUBLIC_KEY_FIELD_NUMBER;
    hash = (53 * hash) + getSessionPublicKey().hashCode();
    hash = (37 * hash) + SCHEMA_VERSION_FIELD_NUMBER;
    hash = (53 * hash) + getSchemaVersion().hashCode();
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static io.opentdf.platform.access.RewrapResponse parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.access.RewrapResponse parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.access.RewrapResponse parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.access.RewrapResponse parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.access.RewrapResponse parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.access.RewrapResponse parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.access.RewrapResponse parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.access.RewrapResponse parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static io.opentdf.platform.access.RewrapResponse parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static io.opentdf.platform.access.RewrapResponse parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static io.opentdf.platform.access.RewrapResponse parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.access.RewrapResponse parseFrom(
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
  public static Builder newBuilder(io.opentdf.platform.access.RewrapResponse prototype) {
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
   * Protobuf type {@code access.RewrapResponse}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:access.RewrapResponse)
      io.opentdf.platform.access.RewrapResponseOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return io.opentdf.platform.access.AccessProto.internal_static_access_RewrapResponse_descriptor;
    }

    @SuppressWarnings({"rawtypes"})
    protected com.google.protobuf.MapFieldReflectionAccessor internalGetMapFieldReflection(
        int number) {
      switch (number) {
        case 1:
          return internalGetMetadata();
        default:
          throw new RuntimeException(
              "Invalid map field number: " + number);
      }
    }
    @SuppressWarnings({"rawtypes"})
    protected com.google.protobuf.MapFieldReflectionAccessor internalGetMutableMapFieldReflection(
        int number) {
      switch (number) {
        case 1:
          return internalGetMutableMetadata();
        default:
          throw new RuntimeException(
              "Invalid map field number: " + number);
      }
    }
    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return io.opentdf.platform.access.AccessProto.internal_static_access_RewrapResponse_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              io.opentdf.platform.access.RewrapResponse.class, io.opentdf.platform.access.RewrapResponse.Builder.class);
    }

    // Construct using io.opentdf.platform.access.RewrapResponse.newBuilder()
    private Builder() {

    }

    private Builder(
        com.google.protobuf.GeneratedMessageV3.BuilderParent parent) {
      super(parent);

    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      bitField0_ = 0;
      internalGetMutableMetadata().clear();
      entityWrappedKey_ = com.google.protobuf.ByteString.EMPTY;
      sessionPublicKey_ = "";
      schemaVersion_ = "";
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return io.opentdf.platform.access.AccessProto.internal_static_access_RewrapResponse_descriptor;
    }

    @java.lang.Override
    public io.opentdf.platform.access.RewrapResponse getDefaultInstanceForType() {
      return io.opentdf.platform.access.RewrapResponse.getDefaultInstance();
    }

    @java.lang.Override
    public io.opentdf.platform.access.RewrapResponse build() {
      io.opentdf.platform.access.RewrapResponse result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public io.opentdf.platform.access.RewrapResponse buildPartial() {
      io.opentdf.platform.access.RewrapResponse result = new io.opentdf.platform.access.RewrapResponse(this);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartial0(io.opentdf.platform.access.RewrapResponse result) {
      int from_bitField0_ = bitField0_;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        result.metadata_ = internalGetMetadata().build(MetadataDefaultEntryHolder.defaultEntry);
      }
      if (((from_bitField0_ & 0x00000002) != 0)) {
        result.entityWrappedKey_ = entityWrappedKey_;
      }
      if (((from_bitField0_ & 0x00000004) != 0)) {
        result.sessionPublicKey_ = sessionPublicKey_;
      }
      if (((from_bitField0_ & 0x00000008) != 0)) {
        result.schemaVersion_ = schemaVersion_;
      }
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
      if (other instanceof io.opentdf.platform.access.RewrapResponse) {
        return mergeFrom((io.opentdf.platform.access.RewrapResponse)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(io.opentdf.platform.access.RewrapResponse other) {
      if (other == io.opentdf.platform.access.RewrapResponse.getDefaultInstance()) return this;
      internalGetMutableMetadata().mergeFrom(
          other.internalGetMetadata());
      bitField0_ |= 0x00000001;
      if (other.getEntityWrappedKey() != com.google.protobuf.ByteString.EMPTY) {
        setEntityWrappedKey(other.getEntityWrappedKey());
      }
      if (!other.getSessionPublicKey().isEmpty()) {
        sessionPublicKey_ = other.sessionPublicKey_;
        bitField0_ |= 0x00000004;
        onChanged();
      }
      if (!other.getSchemaVersion().isEmpty()) {
        schemaVersion_ = other.schemaVersion_;
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
              com.google.protobuf.MapEntry<java.lang.String, com.google.protobuf.Value>
              metadata__ = input.readMessage(
                  MetadataDefaultEntryHolder.defaultEntry.getParserForType(), extensionRegistry);
              internalGetMutableMetadata().ensureBuilderMap().put(
                  metadata__.getKey(), metadata__.getValue());
              bitField0_ |= 0x00000001;
              break;
            } // case 10
            case 18: {
              entityWrappedKey_ = input.readBytes();
              bitField0_ |= 0x00000002;
              break;
            } // case 18
            case 26: {
              sessionPublicKey_ = input.readStringRequireUtf8();
              bitField0_ |= 0x00000004;
              break;
            } // case 26
            case 34: {
              schemaVersion_ = input.readStringRequireUtf8();
              bitField0_ |= 0x00000008;
              break;
            } // case 34
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

    private static final class MetadataConverter implements com.google.protobuf.MapFieldBuilder.Converter<java.lang.String, com.google.protobuf.ValueOrBuilder, com.google.protobuf.Value> {
      @java.lang.Override
      public com.google.protobuf.Value build(com.google.protobuf.ValueOrBuilder val) {
        if (val instanceof com.google.protobuf.Value) { return (com.google.protobuf.Value) val; }
        return ((com.google.protobuf.Value.Builder) val).build();
      }

      @java.lang.Override
      public com.google.protobuf.MapEntry<java.lang.String, com.google.protobuf.Value> defaultEntry() {
        return MetadataDefaultEntryHolder.defaultEntry;
      }
    };
    private static final MetadataConverter metadataConverter = new MetadataConverter();

    private com.google.protobuf.MapFieldBuilder<
        java.lang.String, com.google.protobuf.ValueOrBuilder, com.google.protobuf.Value, com.google.protobuf.Value.Builder> metadata_;
    private com.google.protobuf.MapFieldBuilder<java.lang.String, com.google.protobuf.ValueOrBuilder, com.google.protobuf.Value, com.google.protobuf.Value.Builder>
        internalGetMetadata() {
      if (metadata_ == null) {
        return new com.google.protobuf.MapFieldBuilder<>(metadataConverter);
      }
      return metadata_;
    }
    private com.google.protobuf.MapFieldBuilder<java.lang.String, com.google.protobuf.ValueOrBuilder, com.google.protobuf.Value, com.google.protobuf.Value.Builder>
        internalGetMutableMetadata() {
      if (metadata_ == null) {
        metadata_ = new com.google.protobuf.MapFieldBuilder<>(metadataConverter);
      }
      bitField0_ |= 0x00000001;
      onChanged();
      return metadata_;
    }
    public int getMetadataCount() {
      return internalGetMetadata().ensureBuilderMap().size();
    }
    /**
     * <code>map&lt;string, .google.protobuf.Value&gt; metadata = 1 [json_name = "metadata"];</code>
     */
    @java.lang.Override
    public boolean containsMetadata(
        java.lang.String key) {
      if (key == null) { throw new NullPointerException("map key"); }
      return internalGetMetadata().ensureBuilderMap().containsKey(key);
    }
    /**
     * Use {@link #getMetadataMap()} instead.
     */
    @java.lang.Override
    @java.lang.Deprecated
    public java.util.Map<java.lang.String, com.google.protobuf.Value> getMetadata() {
      return getMetadataMap();
    }
    /**
     * <code>map&lt;string, .google.protobuf.Value&gt; metadata = 1 [json_name = "metadata"];</code>
     */
    @java.lang.Override
    public java.util.Map<java.lang.String, com.google.protobuf.Value> getMetadataMap() {
      return internalGetMetadata().getImmutableMap();
    }
    /**
     * <code>map&lt;string, .google.protobuf.Value&gt; metadata = 1 [json_name = "metadata"];</code>
     */
    @java.lang.Override
    public /* nullable */
com.google.protobuf.Value getMetadataOrDefault(
        java.lang.String key,
        /* nullable */
com.google.protobuf.Value defaultValue) {
      if (key == null) { throw new NullPointerException("map key"); }
      java.util.Map<java.lang.String, com.google.protobuf.ValueOrBuilder> map = internalGetMutableMetadata().ensureBuilderMap();
      return map.containsKey(key) ? metadataConverter.build(map.get(key)) : defaultValue;
    }
    /**
     * <code>map&lt;string, .google.protobuf.Value&gt; metadata = 1 [json_name = "metadata"];</code>
     */
    @java.lang.Override
    public com.google.protobuf.Value getMetadataOrThrow(
        java.lang.String key) {
      if (key == null) { throw new NullPointerException("map key"); }
      java.util.Map<java.lang.String, com.google.protobuf.ValueOrBuilder> map = internalGetMutableMetadata().ensureBuilderMap();
      if (!map.containsKey(key)) {
        throw new java.lang.IllegalArgumentException();
      }
      return metadataConverter.build(map.get(key));
    }
    public Builder clearMetadata() {
      bitField0_ = (bitField0_ & ~0x00000001);
      internalGetMutableMetadata().clear();
      return this;
    }
    /**
     * <code>map&lt;string, .google.protobuf.Value&gt; metadata = 1 [json_name = "metadata"];</code>
     */
    public Builder removeMetadata(
        java.lang.String key) {
      if (key == null) { throw new NullPointerException("map key"); }
      internalGetMutableMetadata().ensureBuilderMap()
          .remove(key);
      return this;
    }
    /**
     * Use alternate mutation accessors instead.
     */
    @java.lang.Deprecated
    public java.util.Map<java.lang.String, com.google.protobuf.Value>
        getMutableMetadata() {
      bitField0_ |= 0x00000001;
      return internalGetMutableMetadata().ensureMessageMap();
    }
    /**
     * <code>map&lt;string, .google.protobuf.Value&gt; metadata = 1 [json_name = "metadata"];</code>
     */
    public Builder putMetadata(
        java.lang.String key,
        com.google.protobuf.Value value) {
      if (key == null) { throw new NullPointerException("map key"); }
      if (value == null) { throw new NullPointerException("map value"); }
      internalGetMutableMetadata().ensureBuilderMap()
          .put(key, value);
      bitField0_ |= 0x00000001;
      return this;
    }
    /**
     * <code>map&lt;string, .google.protobuf.Value&gt; metadata = 1 [json_name = "metadata"];</code>
     */
    public Builder putAllMetadata(
        java.util.Map<java.lang.String, com.google.protobuf.Value> values) {
      for (java.util.Map.Entry<java.lang.String, com.google.protobuf.Value> e : values.entrySet()) {
        if (e.getKey() == null || e.getValue() == null) {
          throw new NullPointerException();
        }
      }
      internalGetMutableMetadata().ensureBuilderMap()
          .putAll(values);
      bitField0_ |= 0x00000001;
      return this;
    }
    /**
     * <code>map&lt;string, .google.protobuf.Value&gt; metadata = 1 [json_name = "metadata"];</code>
     */
    public com.google.protobuf.Value.Builder putMetadataBuilderIfAbsent(
        java.lang.String key) {
      java.util.Map<java.lang.String, com.google.protobuf.ValueOrBuilder> builderMap = internalGetMutableMetadata().ensureBuilderMap();
      com.google.protobuf.ValueOrBuilder entry = builderMap.get(key);
      if (entry == null) {
        entry = com.google.protobuf.Value.newBuilder();
        builderMap.put(key, entry);
      }
      if (entry instanceof com.google.protobuf.Value) {
        entry = ((com.google.protobuf.Value) entry).toBuilder();
        builderMap.put(key, entry);
      }
      return (com.google.protobuf.Value.Builder) entry;
    }

    private com.google.protobuf.ByteString entityWrappedKey_ = com.google.protobuf.ByteString.EMPTY;
    /**
     * <code>bytes entity_wrapped_key = 2 [json_name = "entityWrappedKey"];</code>
     * @return The entityWrappedKey.
     */
    @java.lang.Override
    public com.google.protobuf.ByteString getEntityWrappedKey() {
      return entityWrappedKey_;
    }
    /**
     * <code>bytes entity_wrapped_key = 2 [json_name = "entityWrappedKey"];</code>
     * @param value The entityWrappedKey to set.
     * @return This builder for chaining.
     */
    public Builder setEntityWrappedKey(com.google.protobuf.ByteString value) {
      if (value == null) { throw new NullPointerException(); }
      entityWrappedKey_ = value;
      bitField0_ |= 0x00000002;
      onChanged();
      return this;
    }
    /**
     * <code>bytes entity_wrapped_key = 2 [json_name = "entityWrappedKey"];</code>
     * @return This builder for chaining.
     */
    public Builder clearEntityWrappedKey() {
      bitField0_ = (bitField0_ & ~0x00000002);
      entityWrappedKey_ = getDefaultInstance().getEntityWrappedKey();
      onChanged();
      return this;
    }

    private java.lang.Object sessionPublicKey_ = "";
    /**
     * <code>string session_public_key = 3 [json_name = "sessionPublicKey"];</code>
     * @return The sessionPublicKey.
     */
    public java.lang.String getSessionPublicKey() {
      java.lang.Object ref = sessionPublicKey_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        sessionPublicKey_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>string session_public_key = 3 [json_name = "sessionPublicKey"];</code>
     * @return The bytes for sessionPublicKey.
     */
    public com.google.protobuf.ByteString
        getSessionPublicKeyBytes() {
      java.lang.Object ref = sessionPublicKey_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        sessionPublicKey_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>string session_public_key = 3 [json_name = "sessionPublicKey"];</code>
     * @param value The sessionPublicKey to set.
     * @return This builder for chaining.
     */
    public Builder setSessionPublicKey(
        java.lang.String value) {
      if (value == null) { throw new NullPointerException(); }
      sessionPublicKey_ = value;
      bitField0_ |= 0x00000004;
      onChanged();
      return this;
    }
    /**
     * <code>string session_public_key = 3 [json_name = "sessionPublicKey"];</code>
     * @return This builder for chaining.
     */
    public Builder clearSessionPublicKey() {
      sessionPublicKey_ = getDefaultInstance().getSessionPublicKey();
      bitField0_ = (bitField0_ & ~0x00000004);
      onChanged();
      return this;
    }
    /**
     * <code>string session_public_key = 3 [json_name = "sessionPublicKey"];</code>
     * @param value The bytes for sessionPublicKey to set.
     * @return This builder for chaining.
     */
    public Builder setSessionPublicKeyBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) { throw new NullPointerException(); }
      checkByteStringIsUtf8(value);
      sessionPublicKey_ = value;
      bitField0_ |= 0x00000004;
      onChanged();
      return this;
    }

    private java.lang.Object schemaVersion_ = "";
    /**
     * <code>string schema_version = 4 [json_name = "schemaVersion"];</code>
     * @return The schemaVersion.
     */
    public java.lang.String getSchemaVersion() {
      java.lang.Object ref = schemaVersion_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        schemaVersion_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>string schema_version = 4 [json_name = "schemaVersion"];</code>
     * @return The bytes for schemaVersion.
     */
    public com.google.protobuf.ByteString
        getSchemaVersionBytes() {
      java.lang.Object ref = schemaVersion_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        schemaVersion_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>string schema_version = 4 [json_name = "schemaVersion"];</code>
     * @param value The schemaVersion to set.
     * @return This builder for chaining.
     */
    public Builder setSchemaVersion(
        java.lang.String value) {
      if (value == null) { throw new NullPointerException(); }
      schemaVersion_ = value;
      bitField0_ |= 0x00000008;
      onChanged();
      return this;
    }
    /**
     * <code>string schema_version = 4 [json_name = "schemaVersion"];</code>
     * @return This builder for chaining.
     */
    public Builder clearSchemaVersion() {
      schemaVersion_ = getDefaultInstance().getSchemaVersion();
      bitField0_ = (bitField0_ & ~0x00000008);
      onChanged();
      return this;
    }
    /**
     * <code>string schema_version = 4 [json_name = "schemaVersion"];</code>
     * @param value The bytes for schemaVersion to set.
     * @return This builder for chaining.
     */
    public Builder setSchemaVersionBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) { throw new NullPointerException(); }
      checkByteStringIsUtf8(value);
      schemaVersion_ = value;
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


    // @@protoc_insertion_point(builder_scope:access.RewrapResponse)
  }

  // @@protoc_insertion_point(class_scope:access.RewrapResponse)
  private static final io.opentdf.platform.access.RewrapResponse DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new io.opentdf.platform.access.RewrapResponse();
  }

  public static io.opentdf.platform.access.RewrapResponse getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<RewrapResponse>
      PARSER = new com.google.protobuf.AbstractParser<RewrapResponse>() {
    @java.lang.Override
    public RewrapResponse parsePartialFrom(
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

  public static com.google.protobuf.Parser<RewrapResponse> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<RewrapResponse> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public io.opentdf.platform.access.RewrapResponse getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

