// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/attributes/attributes.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.attributes;

/**
 * Protobuf type {@code policy.attributes.UpdateAttributeValueRequest}
 */
public final class UpdateAttributeValueRequest extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:policy.attributes.UpdateAttributeValueRequest)
    UpdateAttributeValueRequestOrBuilder {
private static final long serialVersionUID = 0L;
  // Use UpdateAttributeValueRequest.newBuilder() to construct.
  private UpdateAttributeValueRequest(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private UpdateAttributeValueRequest() {
    id_ = "";
    members_ =
        com.google.protobuf.LazyStringArrayList.emptyList();
    metadataUpdateBehavior_ = 0;
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new UpdateAttributeValueRequest();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return io.opentdf.platform.policy.attributes.AttributesProto.internal_static_policy_attributes_UpdateAttributeValueRequest_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return io.opentdf.platform.policy.attributes.AttributesProto.internal_static_policy_attributes_UpdateAttributeValueRequest_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest.class, io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest.Builder.class);
  }

  private int bitField0_;
  public static final int ID_FIELD_NUMBER = 1;
  @SuppressWarnings("serial")
  private volatile java.lang.Object id_ = "";
  /**
   * <code>string id = 1 [json_name = "id", (.buf.validate.field) = { ... }</code>
   * @return The id.
   */
  @java.lang.Override
  public java.lang.String getId() {
    java.lang.Object ref = id_;
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      id_ = s;
      return s;
    }
  }
  /**
   * <code>string id = 1 [json_name = "id", (.buf.validate.field) = { ... }</code>
   * @return The bytes for id.
   */
  @java.lang.Override
  public com.google.protobuf.ByteString
      getIdBytes() {
    java.lang.Object ref = id_;
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      id_ = b;
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int MEMBERS_FIELD_NUMBER = 4;
  @SuppressWarnings("serial")
  private com.google.protobuf.LazyStringArrayList members_ =
      com.google.protobuf.LazyStringArrayList.emptyList();
  /**
   * <pre>
   * Optional
   * </pre>
   *
   * <code>repeated string members = 4 [json_name = "members"];</code>
   * @return A list containing the members.
   */
  public com.google.protobuf.ProtocolStringList
      getMembersList() {
    return members_;
  }
  /**
   * <pre>
   * Optional
   * </pre>
   *
   * <code>repeated string members = 4 [json_name = "members"];</code>
   * @return The count of members.
   */
  public int getMembersCount() {
    return members_.size();
  }
  /**
   * <pre>
   * Optional
   * </pre>
   *
   * <code>repeated string members = 4 [json_name = "members"];</code>
   * @param index The index of the element to return.
   * @return The members at the given index.
   */
  public java.lang.String getMembers(int index) {
    return members_.get(index);
  }
  /**
   * <pre>
   * Optional
   * </pre>
   *
   * <code>repeated string members = 4 [json_name = "members"];</code>
   * @param index The index of the value to return.
   * @return The bytes of the members at the given index.
   */
  public com.google.protobuf.ByteString
      getMembersBytes(int index) {
    return members_.getByteString(index);
  }

  public static final int METADATA_FIELD_NUMBER = 100;
  private io.opentdf.platform.common.MetadataMutable metadata_;
  /**
   * <pre>
   * Common metadata
   * </pre>
   *
   * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
   * @return Whether the metadata field is set.
   */
  @java.lang.Override
  public boolean hasMetadata() {
    return ((bitField0_ & 0x00000001) != 0);
  }
  /**
   * <pre>
   * Common metadata
   * </pre>
   *
   * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
   * @return The metadata.
   */
  @java.lang.Override
  public io.opentdf.platform.common.MetadataMutable getMetadata() {
    return metadata_ == null ? io.opentdf.platform.common.MetadataMutable.getDefaultInstance() : metadata_;
  }
  /**
   * <pre>
   * Common metadata
   * </pre>
   *
   * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
   */
  @java.lang.Override
  public io.opentdf.platform.common.MetadataMutableOrBuilder getMetadataOrBuilder() {
    return metadata_ == null ? io.opentdf.platform.common.MetadataMutable.getDefaultInstance() : metadata_;
  }

  public static final int METADATA_UPDATE_BEHAVIOR_FIELD_NUMBER = 101;
  private int metadataUpdateBehavior_ = 0;
  /**
   * <code>.common.MetadataUpdateEnum metadata_update_behavior = 101 [json_name = "metadataUpdateBehavior"];</code>
   * @return The enum numeric value on the wire for metadataUpdateBehavior.
   */
  @java.lang.Override public int getMetadataUpdateBehaviorValue() {
    return metadataUpdateBehavior_;
  }
  /**
   * <code>.common.MetadataUpdateEnum metadata_update_behavior = 101 [json_name = "metadataUpdateBehavior"];</code>
   * @return The metadataUpdateBehavior.
   */
  @java.lang.Override public io.opentdf.platform.common.MetadataUpdateEnum getMetadataUpdateBehavior() {
    io.opentdf.platform.common.MetadataUpdateEnum result = io.opentdf.platform.common.MetadataUpdateEnum.forNumber(metadataUpdateBehavior_);
    return result == null ? io.opentdf.platform.common.MetadataUpdateEnum.UNRECOGNIZED : result;
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
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(id_)) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 1, id_);
    }
    for (int i = 0; i < members_.size(); i++) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 4, members_.getRaw(i));
    }
    if (((bitField0_ & 0x00000001) != 0)) {
      output.writeMessage(100, getMetadata());
    }
    if (metadataUpdateBehavior_ != io.opentdf.platform.common.MetadataUpdateEnum.METADATA_UPDATE_ENUM_UNSPECIFIED.getNumber()) {
      output.writeEnum(101, metadataUpdateBehavior_);
    }
    getUnknownFields().writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    if (!com.google.protobuf.GeneratedMessageV3.isStringEmpty(id_)) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(1, id_);
    }
    {
      int dataSize = 0;
      for (int i = 0; i < members_.size(); i++) {
        dataSize += computeStringSizeNoTag(members_.getRaw(i));
      }
      size += dataSize;
      size += 1 * getMembersList().size();
    }
    if (((bitField0_ & 0x00000001) != 0)) {
      size += com.google.protobuf.CodedOutputStream
        .computeMessageSize(100, getMetadata());
    }
    if (metadataUpdateBehavior_ != io.opentdf.platform.common.MetadataUpdateEnum.METADATA_UPDATE_ENUM_UNSPECIFIED.getNumber()) {
      size += com.google.protobuf.CodedOutputStream
        .computeEnumSize(101, metadataUpdateBehavior_);
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
    if (!(obj instanceof io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest)) {
      return super.equals(obj);
    }
    io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest other = (io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest) obj;

    if (!getId()
        .equals(other.getId())) return false;
    if (!getMembersList()
        .equals(other.getMembersList())) return false;
    if (hasMetadata() != other.hasMetadata()) return false;
    if (hasMetadata()) {
      if (!getMetadata()
          .equals(other.getMetadata())) return false;
    }
    if (metadataUpdateBehavior_ != other.metadataUpdateBehavior_) return false;
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
    hash = (37 * hash) + ID_FIELD_NUMBER;
    hash = (53 * hash) + getId().hashCode();
    if (getMembersCount() > 0) {
      hash = (37 * hash) + MEMBERS_FIELD_NUMBER;
      hash = (53 * hash) + getMembersList().hashCode();
    }
    if (hasMetadata()) {
      hash = (37 * hash) + METADATA_FIELD_NUMBER;
      hash = (53 * hash) + getMetadata().hashCode();
    }
    hash = (37 * hash) + METADATA_UPDATE_BEHAVIOR_FIELD_NUMBER;
    hash = (53 * hash) + metadataUpdateBehavior_;
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest parseFrom(
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
  public static Builder newBuilder(io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest prototype) {
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
   * Protobuf type {@code policy.attributes.UpdateAttributeValueRequest}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:policy.attributes.UpdateAttributeValueRequest)
      io.opentdf.platform.policy.attributes.UpdateAttributeValueRequestOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return io.opentdf.platform.policy.attributes.AttributesProto.internal_static_policy_attributes_UpdateAttributeValueRequest_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return io.opentdf.platform.policy.attributes.AttributesProto.internal_static_policy_attributes_UpdateAttributeValueRequest_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest.class, io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest.Builder.class);
    }

    // Construct using io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest.newBuilder()
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
      }
    }
    @java.lang.Override
    public Builder clear() {
      super.clear();
      bitField0_ = 0;
      id_ = "";
      members_ =
          com.google.protobuf.LazyStringArrayList.emptyList();
      metadata_ = null;
      if (metadataBuilder_ != null) {
        metadataBuilder_.dispose();
        metadataBuilder_ = null;
      }
      metadataUpdateBehavior_ = 0;
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return io.opentdf.platform.policy.attributes.AttributesProto.internal_static_policy_attributes_UpdateAttributeValueRequest_descriptor;
    }

    @java.lang.Override
    public io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest getDefaultInstanceForType() {
      return io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest.getDefaultInstance();
    }

    @java.lang.Override
    public io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest build() {
      io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest buildPartial() {
      io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest result = new io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest(this);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartial0(io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest result) {
      int from_bitField0_ = bitField0_;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        result.id_ = id_;
      }
      if (((from_bitField0_ & 0x00000002) != 0)) {
        members_.makeImmutable();
        result.members_ = members_;
      }
      int to_bitField0_ = 0;
      if (((from_bitField0_ & 0x00000004) != 0)) {
        result.metadata_ = metadataBuilder_ == null
            ? metadata_
            : metadataBuilder_.build();
        to_bitField0_ |= 0x00000001;
      }
      if (((from_bitField0_ & 0x00000008) != 0)) {
        result.metadataUpdateBehavior_ = metadataUpdateBehavior_;
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
      if (other instanceof io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest) {
        return mergeFrom((io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest other) {
      if (other == io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest.getDefaultInstance()) return this;
      if (!other.getId().isEmpty()) {
        id_ = other.id_;
        bitField0_ |= 0x00000001;
        onChanged();
      }
      if (!other.members_.isEmpty()) {
        if (members_.isEmpty()) {
          members_ = other.members_;
          bitField0_ |= 0x00000002;
        } else {
          ensureMembersIsMutable();
          members_.addAll(other.members_);
        }
        onChanged();
      }
      if (other.hasMetadata()) {
        mergeMetadata(other.getMetadata());
      }
      if (other.metadataUpdateBehavior_ != 0) {
        setMetadataUpdateBehaviorValue(other.getMetadataUpdateBehaviorValue());
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
              id_ = input.readStringRequireUtf8();
              bitField0_ |= 0x00000001;
              break;
            } // case 10
            case 34: {
              java.lang.String s = input.readStringRequireUtf8();
              ensureMembersIsMutable();
              members_.add(s);
              break;
            } // case 34
            case 802: {
              input.readMessage(
                  getMetadataFieldBuilder().getBuilder(),
                  extensionRegistry);
              bitField0_ |= 0x00000004;
              break;
            } // case 802
            case 808: {
              metadataUpdateBehavior_ = input.readEnum();
              bitField0_ |= 0x00000008;
              break;
            } // case 808
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

    private java.lang.Object id_ = "";
    /**
     * <code>string id = 1 [json_name = "id", (.buf.validate.field) = { ... }</code>
     * @return The id.
     */
    public java.lang.String getId() {
      java.lang.Object ref = id_;
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        id_ = s;
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <code>string id = 1 [json_name = "id", (.buf.validate.field) = { ... }</code>
     * @return The bytes for id.
     */
    public com.google.protobuf.ByteString
        getIdBytes() {
      java.lang.Object ref = id_;
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        id_ = b;
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <code>string id = 1 [json_name = "id", (.buf.validate.field) = { ... }</code>
     * @param value The id to set.
     * @return This builder for chaining.
     */
    public Builder setId(
        java.lang.String value) {
      if (value == null) { throw new NullPointerException(); }
      id_ = value;
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }
    /**
     * <code>string id = 1 [json_name = "id", (.buf.validate.field) = { ... }</code>
     * @return This builder for chaining.
     */
    public Builder clearId() {
      id_ = getDefaultInstance().getId();
      bitField0_ = (bitField0_ & ~0x00000001);
      onChanged();
      return this;
    }
    /**
     * <code>string id = 1 [json_name = "id", (.buf.validate.field) = { ... }</code>
     * @param value The bytes for id to set.
     * @return This builder for chaining.
     */
    public Builder setIdBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) { throw new NullPointerException(); }
      checkByteStringIsUtf8(value);
      id_ = value;
      bitField0_ |= 0x00000001;
      onChanged();
      return this;
    }

    private com.google.protobuf.LazyStringArrayList members_ =
        com.google.protobuf.LazyStringArrayList.emptyList();
    private void ensureMembersIsMutable() {
      if (!members_.isModifiable()) {
        members_ = new com.google.protobuf.LazyStringArrayList(members_);
      }
      bitField0_ |= 0x00000002;
    }
    /**
     * <pre>
     * Optional
     * </pre>
     *
     * <code>repeated string members = 4 [json_name = "members"];</code>
     * @return A list containing the members.
     */
    public com.google.protobuf.ProtocolStringList
        getMembersList() {
      members_.makeImmutable();
      return members_;
    }
    /**
     * <pre>
     * Optional
     * </pre>
     *
     * <code>repeated string members = 4 [json_name = "members"];</code>
     * @return The count of members.
     */
    public int getMembersCount() {
      return members_.size();
    }
    /**
     * <pre>
     * Optional
     * </pre>
     *
     * <code>repeated string members = 4 [json_name = "members"];</code>
     * @param index The index of the element to return.
     * @return The members at the given index.
     */
    public java.lang.String getMembers(int index) {
      return members_.get(index);
    }
    /**
     * <pre>
     * Optional
     * </pre>
     *
     * <code>repeated string members = 4 [json_name = "members"];</code>
     * @param index The index of the value to return.
     * @return The bytes of the members at the given index.
     */
    public com.google.protobuf.ByteString
        getMembersBytes(int index) {
      return members_.getByteString(index);
    }
    /**
     * <pre>
     * Optional
     * </pre>
     *
     * <code>repeated string members = 4 [json_name = "members"];</code>
     * @param index The index to set the value at.
     * @param value The members to set.
     * @return This builder for chaining.
     */
    public Builder setMembers(
        int index, java.lang.String value) {
      if (value == null) { throw new NullPointerException(); }
      ensureMembersIsMutable();
      members_.set(index, value);
      bitField0_ |= 0x00000002;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Optional
     * </pre>
     *
     * <code>repeated string members = 4 [json_name = "members"];</code>
     * @param value The members to add.
     * @return This builder for chaining.
     */
    public Builder addMembers(
        java.lang.String value) {
      if (value == null) { throw new NullPointerException(); }
      ensureMembersIsMutable();
      members_.add(value);
      bitField0_ |= 0x00000002;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Optional
     * </pre>
     *
     * <code>repeated string members = 4 [json_name = "members"];</code>
     * @param values The members to add.
     * @return This builder for chaining.
     */
    public Builder addAllMembers(
        java.lang.Iterable<java.lang.String> values) {
      ensureMembersIsMutable();
      com.google.protobuf.AbstractMessageLite.Builder.addAll(
          values, members_);
      bitField0_ |= 0x00000002;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Optional
     * </pre>
     *
     * <code>repeated string members = 4 [json_name = "members"];</code>
     * @return This builder for chaining.
     */
    public Builder clearMembers() {
      members_ =
        com.google.protobuf.LazyStringArrayList.emptyList();
      bitField0_ = (bitField0_ & ~0x00000002);;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Optional
     * </pre>
     *
     * <code>repeated string members = 4 [json_name = "members"];</code>
     * @param value The bytes of the members to add.
     * @return This builder for chaining.
     */
    public Builder addMembersBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) { throw new NullPointerException(); }
      checkByteStringIsUtf8(value);
      ensureMembersIsMutable();
      members_.add(value);
      bitField0_ |= 0x00000002;
      onChanged();
      return this;
    }

    private io.opentdf.platform.common.MetadataMutable metadata_;
    private com.google.protobuf.SingleFieldBuilderV3<
        io.opentdf.platform.common.MetadataMutable, io.opentdf.platform.common.MetadataMutable.Builder, io.opentdf.platform.common.MetadataMutableOrBuilder> metadataBuilder_;
    /**
     * <pre>
     * Common metadata
     * </pre>
     *
     * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
     * @return Whether the metadata field is set.
     */
    public boolean hasMetadata() {
      return ((bitField0_ & 0x00000004) != 0);
    }
    /**
     * <pre>
     * Common metadata
     * </pre>
     *
     * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
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
     * <pre>
     * Common metadata
     * </pre>
     *
     * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
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
      bitField0_ |= 0x00000004;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Common metadata
     * </pre>
     *
     * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
     */
    public Builder setMetadata(
        io.opentdf.platform.common.MetadataMutable.Builder builderForValue) {
      if (metadataBuilder_ == null) {
        metadata_ = builderForValue.build();
      } else {
        metadataBuilder_.setMessage(builderForValue.build());
      }
      bitField0_ |= 0x00000004;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Common metadata
     * </pre>
     *
     * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
     */
    public Builder mergeMetadata(io.opentdf.platform.common.MetadataMutable value) {
      if (metadataBuilder_ == null) {
        if (((bitField0_ & 0x00000004) != 0) &&
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
        bitField0_ |= 0x00000004;
        onChanged();
      }
      return this;
    }
    /**
     * <pre>
     * Common metadata
     * </pre>
     *
     * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
     */
    public Builder clearMetadata() {
      bitField0_ = (bitField0_ & ~0x00000004);
      metadata_ = null;
      if (metadataBuilder_ != null) {
        metadataBuilder_.dispose();
        metadataBuilder_ = null;
      }
      onChanged();
      return this;
    }
    /**
     * <pre>
     * Common metadata
     * </pre>
     *
     * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
     */
    public io.opentdf.platform.common.MetadataMutable.Builder getMetadataBuilder() {
      bitField0_ |= 0x00000004;
      onChanged();
      return getMetadataFieldBuilder().getBuilder();
    }
    /**
     * <pre>
     * Common metadata
     * </pre>
     *
     * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
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
     * <pre>
     * Common metadata
     * </pre>
     *
     * <code>.common.MetadataMutable metadata = 100 [json_name = "metadata"];</code>
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

    private int metadataUpdateBehavior_ = 0;
    /**
     * <code>.common.MetadataUpdateEnum metadata_update_behavior = 101 [json_name = "metadataUpdateBehavior"];</code>
     * @return The enum numeric value on the wire for metadataUpdateBehavior.
     */
    @java.lang.Override public int getMetadataUpdateBehaviorValue() {
      return metadataUpdateBehavior_;
    }
    /**
     * <code>.common.MetadataUpdateEnum metadata_update_behavior = 101 [json_name = "metadataUpdateBehavior"];</code>
     * @param value The enum numeric value on the wire for metadataUpdateBehavior to set.
     * @return This builder for chaining.
     */
    public Builder setMetadataUpdateBehaviorValue(int value) {
      metadataUpdateBehavior_ = value;
      bitField0_ |= 0x00000008;
      onChanged();
      return this;
    }
    /**
     * <code>.common.MetadataUpdateEnum metadata_update_behavior = 101 [json_name = "metadataUpdateBehavior"];</code>
     * @return The metadataUpdateBehavior.
     */
    @java.lang.Override
    public io.opentdf.platform.common.MetadataUpdateEnum getMetadataUpdateBehavior() {
      io.opentdf.platform.common.MetadataUpdateEnum result = io.opentdf.platform.common.MetadataUpdateEnum.forNumber(metadataUpdateBehavior_);
      return result == null ? io.opentdf.platform.common.MetadataUpdateEnum.UNRECOGNIZED : result;
    }
    /**
     * <code>.common.MetadataUpdateEnum metadata_update_behavior = 101 [json_name = "metadataUpdateBehavior"];</code>
     * @param value The metadataUpdateBehavior to set.
     * @return This builder for chaining.
     */
    public Builder setMetadataUpdateBehavior(io.opentdf.platform.common.MetadataUpdateEnum value) {
      if (value == null) {
        throw new NullPointerException();
      }
      bitField0_ |= 0x00000008;
      metadataUpdateBehavior_ = value.getNumber();
      onChanged();
      return this;
    }
    /**
     * <code>.common.MetadataUpdateEnum metadata_update_behavior = 101 [json_name = "metadataUpdateBehavior"];</code>
     * @return This builder for chaining.
     */
    public Builder clearMetadataUpdateBehavior() {
      bitField0_ = (bitField0_ & ~0x00000008);
      metadataUpdateBehavior_ = 0;
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


    // @@protoc_insertion_point(builder_scope:policy.attributes.UpdateAttributeValueRequest)
  }

  // @@protoc_insertion_point(class_scope:policy.attributes.UpdateAttributeValueRequest)
  private static final io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest();
  }

  public static io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<UpdateAttributeValueRequest>
      PARSER = new com.google.protobuf.AbstractParser<UpdateAttributeValueRequest>() {
    @java.lang.Override
    public UpdateAttributeValueRequest parsePartialFrom(
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

  public static com.google.protobuf.Parser<UpdateAttributeValueRequest> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<UpdateAttributeValueRequest> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public io.opentdf.platform.policy.attributes.UpdateAttributeValueRequest getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

