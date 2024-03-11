// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: authorization/authorization.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.authorization;

/**
 * <pre>
 * A set of related PE and NPE
 * </pre>
 *
 * Protobuf type {@code authorization.EntityChain}
 */
public final class EntityChain extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:authorization.EntityChain)
    EntityChainOrBuilder {
private static final long serialVersionUID = 0L;
  // Use EntityChain.newBuilder() to construct.
  private EntityChain(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private EntityChain() {
    id_ = "";
    entities_ = java.util.Collections.emptyList();
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new EntityChain();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return io.opentdf.platform.authorization.AuthorizationProto.internal_static_authorization_EntityChain_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return io.opentdf.platform.authorization.AuthorizationProto.internal_static_authorization_EntityChain_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            io.opentdf.platform.authorization.EntityChain.class, io.opentdf.platform.authorization.EntityChain.Builder.class);
  }

  public static final int ID_FIELD_NUMBER = 1;
  @SuppressWarnings("serial")
  private volatile java.lang.Object id_ = "";
  /**
   * <pre>
   * ephemeral id for tracking between request and response
   * </pre>
   *
   * <code>string id = 1 [json_name = "id"];</code>
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
   * <pre>
   * ephemeral id for tracking between request and response
   * </pre>
   *
   * <code>string id = 1 [json_name = "id"];</code>
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

  public static final int ENTITIES_FIELD_NUMBER = 2;
  @SuppressWarnings("serial")
  private java.util.List<io.opentdf.platform.authorization.Entity> entities_;
  /**
   * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
   */
  @java.lang.Override
  public java.util.List<io.opentdf.platform.authorization.Entity> getEntitiesList() {
    return entities_;
  }
  /**
   * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
   */
  @java.lang.Override
  public java.util.List<? extends io.opentdf.platform.authorization.EntityOrBuilder> 
      getEntitiesOrBuilderList() {
    return entities_;
  }
  /**
   * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
   */
  @java.lang.Override
  public int getEntitiesCount() {
    return entities_.size();
  }
  /**
   * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
   */
  @java.lang.Override
  public io.opentdf.platform.authorization.Entity getEntities(int index) {
    return entities_.get(index);
  }
  /**
   * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
   */
  @java.lang.Override
  public io.opentdf.platform.authorization.EntityOrBuilder getEntitiesOrBuilder(
      int index) {
    return entities_.get(index);
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
    for (int i = 0; i < entities_.size(); i++) {
      output.writeMessage(2, entities_.get(i));
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
    for (int i = 0; i < entities_.size(); i++) {
      size += com.google.protobuf.CodedOutputStream
        .computeMessageSize(2, entities_.get(i));
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
    if (!(obj instanceof io.opentdf.platform.authorization.EntityChain)) {
      return super.equals(obj);
    }
    io.opentdf.platform.authorization.EntityChain other = (io.opentdf.platform.authorization.EntityChain) obj;

    if (!getId()
        .equals(other.getId())) return false;
    if (!getEntitiesList()
        .equals(other.getEntitiesList())) return false;
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
    if (getEntitiesCount() > 0) {
      hash = (37 * hash) + ENTITIES_FIELD_NUMBER;
      hash = (53 * hash) + getEntitiesList().hashCode();
    }
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static io.opentdf.platform.authorization.EntityChain parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.authorization.EntityChain parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.authorization.EntityChain parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.authorization.EntityChain parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.authorization.EntityChain parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.authorization.EntityChain parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.authorization.EntityChain parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.authorization.EntityChain parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static io.opentdf.platform.authorization.EntityChain parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static io.opentdf.platform.authorization.EntityChain parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static io.opentdf.platform.authorization.EntityChain parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.authorization.EntityChain parseFrom(
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
  public static Builder newBuilder(io.opentdf.platform.authorization.EntityChain prototype) {
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
   * <pre>
   * A set of related PE and NPE
   * </pre>
   *
   * Protobuf type {@code authorization.EntityChain}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:authorization.EntityChain)
      io.opentdf.platform.authorization.EntityChainOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return io.opentdf.platform.authorization.AuthorizationProto.internal_static_authorization_EntityChain_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return io.opentdf.platform.authorization.AuthorizationProto.internal_static_authorization_EntityChain_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              io.opentdf.platform.authorization.EntityChain.class, io.opentdf.platform.authorization.EntityChain.Builder.class);
    }

    // Construct using io.opentdf.platform.authorization.EntityChain.newBuilder()
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
      id_ = "";
      if (entitiesBuilder_ == null) {
        entities_ = java.util.Collections.emptyList();
      } else {
        entities_ = null;
        entitiesBuilder_.clear();
      }
      bitField0_ = (bitField0_ & ~0x00000002);
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return io.opentdf.platform.authorization.AuthorizationProto.internal_static_authorization_EntityChain_descriptor;
    }

    @java.lang.Override
    public io.opentdf.platform.authorization.EntityChain getDefaultInstanceForType() {
      return io.opentdf.platform.authorization.EntityChain.getDefaultInstance();
    }

    @java.lang.Override
    public io.opentdf.platform.authorization.EntityChain build() {
      io.opentdf.platform.authorization.EntityChain result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public io.opentdf.platform.authorization.EntityChain buildPartial() {
      io.opentdf.platform.authorization.EntityChain result = new io.opentdf.platform.authorization.EntityChain(this);
      buildPartialRepeatedFields(result);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartialRepeatedFields(io.opentdf.platform.authorization.EntityChain result) {
      if (entitiesBuilder_ == null) {
        if (((bitField0_ & 0x00000002) != 0)) {
          entities_ = java.util.Collections.unmodifiableList(entities_);
          bitField0_ = (bitField0_ & ~0x00000002);
        }
        result.entities_ = entities_;
      } else {
        result.entities_ = entitiesBuilder_.build();
      }
    }

    private void buildPartial0(io.opentdf.platform.authorization.EntityChain result) {
      int from_bitField0_ = bitField0_;
      if (((from_bitField0_ & 0x00000001) != 0)) {
        result.id_ = id_;
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
      if (other instanceof io.opentdf.platform.authorization.EntityChain) {
        return mergeFrom((io.opentdf.platform.authorization.EntityChain)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(io.opentdf.platform.authorization.EntityChain other) {
      if (other == io.opentdf.platform.authorization.EntityChain.getDefaultInstance()) return this;
      if (!other.getId().isEmpty()) {
        id_ = other.id_;
        bitField0_ |= 0x00000001;
        onChanged();
      }
      if (entitiesBuilder_ == null) {
        if (!other.entities_.isEmpty()) {
          if (entities_.isEmpty()) {
            entities_ = other.entities_;
            bitField0_ = (bitField0_ & ~0x00000002);
          } else {
            ensureEntitiesIsMutable();
            entities_.addAll(other.entities_);
          }
          onChanged();
        }
      } else {
        if (!other.entities_.isEmpty()) {
          if (entitiesBuilder_.isEmpty()) {
            entitiesBuilder_.dispose();
            entitiesBuilder_ = null;
            entities_ = other.entities_;
            bitField0_ = (bitField0_ & ~0x00000002);
            entitiesBuilder_ = 
              com.google.protobuf.GeneratedMessageV3.alwaysUseFieldBuilders ?
                 getEntitiesFieldBuilder() : null;
          } else {
            entitiesBuilder_.addAllMessages(other.entities_);
          }
        }
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
            case 18: {
              io.opentdf.platform.authorization.Entity m =
                  input.readMessage(
                      io.opentdf.platform.authorization.Entity.parser(),
                      extensionRegistry);
              if (entitiesBuilder_ == null) {
                ensureEntitiesIsMutable();
                entities_.add(m);
              } else {
                entitiesBuilder_.addMessage(m);
              }
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

    private java.lang.Object id_ = "";
    /**
     * <pre>
     * ephemeral id for tracking between request and response
     * </pre>
     *
     * <code>string id = 1 [json_name = "id"];</code>
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
     * <pre>
     * ephemeral id for tracking between request and response
     * </pre>
     *
     * <code>string id = 1 [json_name = "id"];</code>
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
     * <pre>
     * ephemeral id for tracking between request and response
     * </pre>
     *
     * <code>string id = 1 [json_name = "id"];</code>
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
     * <pre>
     * ephemeral id for tracking between request and response
     * </pre>
     *
     * <code>string id = 1 [json_name = "id"];</code>
     * @return This builder for chaining.
     */
    public Builder clearId() {
      id_ = getDefaultInstance().getId();
      bitField0_ = (bitField0_ & ~0x00000001);
      onChanged();
      return this;
    }
    /**
     * <pre>
     * ephemeral id for tracking between request and response
     * </pre>
     *
     * <code>string id = 1 [json_name = "id"];</code>
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

    private java.util.List<io.opentdf.platform.authorization.Entity> entities_ =
      java.util.Collections.emptyList();
    private void ensureEntitiesIsMutable() {
      if (!((bitField0_ & 0x00000002) != 0)) {
        entities_ = new java.util.ArrayList<io.opentdf.platform.authorization.Entity>(entities_);
        bitField0_ |= 0x00000002;
       }
    }

    private com.google.protobuf.RepeatedFieldBuilderV3<
        io.opentdf.platform.authorization.Entity, io.opentdf.platform.authorization.Entity.Builder, io.opentdf.platform.authorization.EntityOrBuilder> entitiesBuilder_;

    /**
     * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
     */
    public java.util.List<io.opentdf.platform.authorization.Entity> getEntitiesList() {
      if (entitiesBuilder_ == null) {
        return java.util.Collections.unmodifiableList(entities_);
      } else {
        return entitiesBuilder_.getMessageList();
      }
    }
    /**
     * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
     */
    public int getEntitiesCount() {
      if (entitiesBuilder_ == null) {
        return entities_.size();
      } else {
        return entitiesBuilder_.getCount();
      }
    }
    /**
     * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
     */
    public io.opentdf.platform.authorization.Entity getEntities(int index) {
      if (entitiesBuilder_ == null) {
        return entities_.get(index);
      } else {
        return entitiesBuilder_.getMessage(index);
      }
    }
    /**
     * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
     */
    public Builder setEntities(
        int index, io.opentdf.platform.authorization.Entity value) {
      if (entitiesBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureEntitiesIsMutable();
        entities_.set(index, value);
        onChanged();
      } else {
        entitiesBuilder_.setMessage(index, value);
      }
      return this;
    }
    /**
     * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
     */
    public Builder setEntities(
        int index, io.opentdf.platform.authorization.Entity.Builder builderForValue) {
      if (entitiesBuilder_ == null) {
        ensureEntitiesIsMutable();
        entities_.set(index, builderForValue.build());
        onChanged();
      } else {
        entitiesBuilder_.setMessage(index, builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
     */
    public Builder addEntities(io.opentdf.platform.authorization.Entity value) {
      if (entitiesBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureEntitiesIsMutable();
        entities_.add(value);
        onChanged();
      } else {
        entitiesBuilder_.addMessage(value);
      }
      return this;
    }
    /**
     * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
     */
    public Builder addEntities(
        int index, io.opentdf.platform.authorization.Entity value) {
      if (entitiesBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureEntitiesIsMutable();
        entities_.add(index, value);
        onChanged();
      } else {
        entitiesBuilder_.addMessage(index, value);
      }
      return this;
    }
    /**
     * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
     */
    public Builder addEntities(
        io.opentdf.platform.authorization.Entity.Builder builderForValue) {
      if (entitiesBuilder_ == null) {
        ensureEntitiesIsMutable();
        entities_.add(builderForValue.build());
        onChanged();
      } else {
        entitiesBuilder_.addMessage(builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
     */
    public Builder addEntities(
        int index, io.opentdf.platform.authorization.Entity.Builder builderForValue) {
      if (entitiesBuilder_ == null) {
        ensureEntitiesIsMutable();
        entities_.add(index, builderForValue.build());
        onChanged();
      } else {
        entitiesBuilder_.addMessage(index, builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
     */
    public Builder addAllEntities(
        java.lang.Iterable<? extends io.opentdf.platform.authorization.Entity> values) {
      if (entitiesBuilder_ == null) {
        ensureEntitiesIsMutable();
        com.google.protobuf.AbstractMessageLite.Builder.addAll(
            values, entities_);
        onChanged();
      } else {
        entitiesBuilder_.addAllMessages(values);
      }
      return this;
    }
    /**
     * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
     */
    public Builder clearEntities() {
      if (entitiesBuilder_ == null) {
        entities_ = java.util.Collections.emptyList();
        bitField0_ = (bitField0_ & ~0x00000002);
        onChanged();
      } else {
        entitiesBuilder_.clear();
      }
      return this;
    }
    /**
     * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
     */
    public Builder removeEntities(int index) {
      if (entitiesBuilder_ == null) {
        ensureEntitiesIsMutable();
        entities_.remove(index);
        onChanged();
      } else {
        entitiesBuilder_.remove(index);
      }
      return this;
    }
    /**
     * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
     */
    public io.opentdf.platform.authorization.Entity.Builder getEntitiesBuilder(
        int index) {
      return getEntitiesFieldBuilder().getBuilder(index);
    }
    /**
     * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
     */
    public io.opentdf.platform.authorization.EntityOrBuilder getEntitiesOrBuilder(
        int index) {
      if (entitiesBuilder_ == null) {
        return entities_.get(index);  } else {
        return entitiesBuilder_.getMessageOrBuilder(index);
      }
    }
    /**
     * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
     */
    public java.util.List<? extends io.opentdf.platform.authorization.EntityOrBuilder> 
         getEntitiesOrBuilderList() {
      if (entitiesBuilder_ != null) {
        return entitiesBuilder_.getMessageOrBuilderList();
      } else {
        return java.util.Collections.unmodifiableList(entities_);
      }
    }
    /**
     * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
     */
    public io.opentdf.platform.authorization.Entity.Builder addEntitiesBuilder() {
      return getEntitiesFieldBuilder().addBuilder(
          io.opentdf.platform.authorization.Entity.getDefaultInstance());
    }
    /**
     * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
     */
    public io.opentdf.platform.authorization.Entity.Builder addEntitiesBuilder(
        int index) {
      return getEntitiesFieldBuilder().addBuilder(
          index, io.opentdf.platform.authorization.Entity.getDefaultInstance());
    }
    /**
     * <code>repeated .authorization.Entity entities = 2 [json_name = "entities"];</code>
     */
    public java.util.List<io.opentdf.platform.authorization.Entity.Builder> 
         getEntitiesBuilderList() {
      return getEntitiesFieldBuilder().getBuilderList();
    }
    private com.google.protobuf.RepeatedFieldBuilderV3<
        io.opentdf.platform.authorization.Entity, io.opentdf.platform.authorization.Entity.Builder, io.opentdf.platform.authorization.EntityOrBuilder> 
        getEntitiesFieldBuilder() {
      if (entitiesBuilder_ == null) {
        entitiesBuilder_ = new com.google.protobuf.RepeatedFieldBuilderV3<
            io.opentdf.platform.authorization.Entity, io.opentdf.platform.authorization.Entity.Builder, io.opentdf.platform.authorization.EntityOrBuilder>(
                entities_,
                ((bitField0_ & 0x00000002) != 0),
                getParentForChildren(),
                isClean());
        entities_ = null;
      }
      return entitiesBuilder_;
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


    // @@protoc_insertion_point(builder_scope:authorization.EntityChain)
  }

  // @@protoc_insertion_point(class_scope:authorization.EntityChain)
  private static final io.opentdf.platform.authorization.EntityChain DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new io.opentdf.platform.authorization.EntityChain();
  }

  public static io.opentdf.platform.authorization.EntityChain getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<EntityChain>
      PARSER = new com.google.protobuf.AbstractParser<EntityChain>() {
    @java.lang.Override
    public EntityChain parsePartialFrom(
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

  public static com.google.protobuf.Parser<EntityChain> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<EntityChain> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public io.opentdf.platform.authorization.EntityChain getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

