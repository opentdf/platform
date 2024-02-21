// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: authorization/idpaddon/idp_add_on.proto

// Protobuf Java Version: 3.25.3
package com.authorization.idpaddon;

/**
 * Protobuf type {@code authorization.idpaddon.IdpAddOnResponse}
 */
public final class IdpAddOnResponse extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:authorization.idpaddon.IdpAddOnResponse)
    IdpAddOnResponseOrBuilder {
private static final long serialVersionUID = 0L;
  // Use IdpAddOnResponse.newBuilder() to construct.
  private IdpAddOnResponse(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private IdpAddOnResponse() {
    entityRepresentations_ = java.util.Collections.emptyList();
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new IdpAddOnResponse();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return com.authorization.idpaddon.IdpAddOnProto.internal_static_authorization_idpaddon_IdpAddOnResponse_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return com.authorization.idpaddon.IdpAddOnProto.internal_static_authorization_idpaddon_IdpAddOnResponse_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            com.authorization.idpaddon.IdpAddOnResponse.class, com.authorization.idpaddon.IdpAddOnResponse.Builder.class);
  }

  public static final int ENTITY_REPRESENTATIONS_FIELD_NUMBER = 1;
  @SuppressWarnings("serial")
  private java.util.List<com.authorization.idpaddon.IdpEntityRepresentation> entityRepresentations_;
  /**
   * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
   */
  @java.lang.Override
  public java.util.List<com.authorization.idpaddon.IdpEntityRepresentation> getEntityRepresentationsList() {
    return entityRepresentations_;
  }
  /**
   * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
   */
  @java.lang.Override
  public java.util.List<? extends com.authorization.idpaddon.IdpEntityRepresentationOrBuilder> 
      getEntityRepresentationsOrBuilderList() {
    return entityRepresentations_;
  }
  /**
   * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
   */
  @java.lang.Override
  public int getEntityRepresentationsCount() {
    return entityRepresentations_.size();
  }
  /**
   * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
   */
  @java.lang.Override
  public com.authorization.idpaddon.IdpEntityRepresentation getEntityRepresentations(int index) {
    return entityRepresentations_.get(index);
  }
  /**
   * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
   */
  @java.lang.Override
  public com.authorization.idpaddon.IdpEntityRepresentationOrBuilder getEntityRepresentationsOrBuilder(
      int index) {
    return entityRepresentations_.get(index);
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
    for (int i = 0; i < entityRepresentations_.size(); i++) {
      output.writeMessage(1, entityRepresentations_.get(i));
    }
    getUnknownFields().writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    for (int i = 0; i < entityRepresentations_.size(); i++) {
      size += com.google.protobuf.CodedOutputStream
        .computeMessageSize(1, entityRepresentations_.get(i));
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
    if (!(obj instanceof com.authorization.idpaddon.IdpAddOnResponse)) {
      return super.equals(obj);
    }
    com.authorization.idpaddon.IdpAddOnResponse other = (com.authorization.idpaddon.IdpAddOnResponse) obj;

    if (!getEntityRepresentationsList()
        .equals(other.getEntityRepresentationsList())) return false;
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
    if (getEntityRepresentationsCount() > 0) {
      hash = (37 * hash) + ENTITY_REPRESENTATIONS_FIELD_NUMBER;
      hash = (53 * hash) + getEntityRepresentationsList().hashCode();
    }
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static com.authorization.idpaddon.IdpAddOnResponse parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.authorization.idpaddon.IdpAddOnResponse parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.authorization.idpaddon.IdpAddOnResponse parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.authorization.idpaddon.IdpAddOnResponse parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.authorization.idpaddon.IdpAddOnResponse parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.authorization.idpaddon.IdpAddOnResponse parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.authorization.idpaddon.IdpAddOnResponse parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.authorization.idpaddon.IdpAddOnResponse parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static com.authorization.idpaddon.IdpAddOnResponse parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static com.authorization.idpaddon.IdpAddOnResponse parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static com.authorization.idpaddon.IdpAddOnResponse parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.authorization.idpaddon.IdpAddOnResponse parseFrom(
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
  public static Builder newBuilder(com.authorization.idpaddon.IdpAddOnResponse prototype) {
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
   * Protobuf type {@code authorization.idpaddon.IdpAddOnResponse}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:authorization.idpaddon.IdpAddOnResponse)
      com.authorization.idpaddon.IdpAddOnResponseOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return com.authorization.idpaddon.IdpAddOnProto.internal_static_authorization_idpaddon_IdpAddOnResponse_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return com.authorization.idpaddon.IdpAddOnProto.internal_static_authorization_idpaddon_IdpAddOnResponse_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              com.authorization.idpaddon.IdpAddOnResponse.class, com.authorization.idpaddon.IdpAddOnResponse.Builder.class);
    }

    // Construct using com.authorization.idpaddon.IdpAddOnResponse.newBuilder()
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
      if (entityRepresentationsBuilder_ == null) {
        entityRepresentations_ = java.util.Collections.emptyList();
      } else {
        entityRepresentations_ = null;
        entityRepresentationsBuilder_.clear();
      }
      bitField0_ = (bitField0_ & ~0x00000001);
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return com.authorization.idpaddon.IdpAddOnProto.internal_static_authorization_idpaddon_IdpAddOnResponse_descriptor;
    }

    @java.lang.Override
    public com.authorization.idpaddon.IdpAddOnResponse getDefaultInstanceForType() {
      return com.authorization.idpaddon.IdpAddOnResponse.getDefaultInstance();
    }

    @java.lang.Override
    public com.authorization.idpaddon.IdpAddOnResponse build() {
      com.authorization.idpaddon.IdpAddOnResponse result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public com.authorization.idpaddon.IdpAddOnResponse buildPartial() {
      com.authorization.idpaddon.IdpAddOnResponse result = new com.authorization.idpaddon.IdpAddOnResponse(this);
      buildPartialRepeatedFields(result);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartialRepeatedFields(com.authorization.idpaddon.IdpAddOnResponse result) {
      if (entityRepresentationsBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0)) {
          entityRepresentations_ = java.util.Collections.unmodifiableList(entityRepresentations_);
          bitField0_ = (bitField0_ & ~0x00000001);
        }
        result.entityRepresentations_ = entityRepresentations_;
      } else {
        result.entityRepresentations_ = entityRepresentationsBuilder_.build();
      }
    }

    private void buildPartial0(com.authorization.idpaddon.IdpAddOnResponse result) {
      int from_bitField0_ = bitField0_;
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
      if (other instanceof com.authorization.idpaddon.IdpAddOnResponse) {
        return mergeFrom((com.authorization.idpaddon.IdpAddOnResponse)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(com.authorization.idpaddon.IdpAddOnResponse other) {
      if (other == com.authorization.idpaddon.IdpAddOnResponse.getDefaultInstance()) return this;
      if (entityRepresentationsBuilder_ == null) {
        if (!other.entityRepresentations_.isEmpty()) {
          if (entityRepresentations_.isEmpty()) {
            entityRepresentations_ = other.entityRepresentations_;
            bitField0_ = (bitField0_ & ~0x00000001);
          } else {
            ensureEntityRepresentationsIsMutable();
            entityRepresentations_.addAll(other.entityRepresentations_);
          }
          onChanged();
        }
      } else {
        if (!other.entityRepresentations_.isEmpty()) {
          if (entityRepresentationsBuilder_.isEmpty()) {
            entityRepresentationsBuilder_.dispose();
            entityRepresentationsBuilder_ = null;
            entityRepresentations_ = other.entityRepresentations_;
            bitField0_ = (bitField0_ & ~0x00000001);
            entityRepresentationsBuilder_ = 
              com.google.protobuf.GeneratedMessageV3.alwaysUseFieldBuilders ?
                 getEntityRepresentationsFieldBuilder() : null;
          } else {
            entityRepresentationsBuilder_.addAllMessages(other.entityRepresentations_);
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
              com.authorization.idpaddon.IdpEntityRepresentation m =
                  input.readMessage(
                      com.authorization.idpaddon.IdpEntityRepresentation.parser(),
                      extensionRegistry);
              if (entityRepresentationsBuilder_ == null) {
                ensureEntityRepresentationsIsMutable();
                entityRepresentations_.add(m);
              } else {
                entityRepresentationsBuilder_.addMessage(m);
              }
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

    private java.util.List<com.authorization.idpaddon.IdpEntityRepresentation> entityRepresentations_ =
      java.util.Collections.emptyList();
    private void ensureEntityRepresentationsIsMutable() {
      if (!((bitField0_ & 0x00000001) != 0)) {
        entityRepresentations_ = new java.util.ArrayList<com.authorization.idpaddon.IdpEntityRepresentation>(entityRepresentations_);
        bitField0_ |= 0x00000001;
       }
    }

    private com.google.protobuf.RepeatedFieldBuilderV3<
        com.authorization.idpaddon.IdpEntityRepresentation, com.authorization.idpaddon.IdpEntityRepresentation.Builder, com.authorization.idpaddon.IdpEntityRepresentationOrBuilder> entityRepresentationsBuilder_;

    /**
     * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
     */
    public java.util.List<com.authorization.idpaddon.IdpEntityRepresentation> getEntityRepresentationsList() {
      if (entityRepresentationsBuilder_ == null) {
        return java.util.Collections.unmodifiableList(entityRepresentations_);
      } else {
        return entityRepresentationsBuilder_.getMessageList();
      }
    }
    /**
     * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
     */
    public int getEntityRepresentationsCount() {
      if (entityRepresentationsBuilder_ == null) {
        return entityRepresentations_.size();
      } else {
        return entityRepresentationsBuilder_.getCount();
      }
    }
    /**
     * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
     */
    public com.authorization.idpaddon.IdpEntityRepresentation getEntityRepresentations(int index) {
      if (entityRepresentationsBuilder_ == null) {
        return entityRepresentations_.get(index);
      } else {
        return entityRepresentationsBuilder_.getMessage(index);
      }
    }
    /**
     * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
     */
    public Builder setEntityRepresentations(
        int index, com.authorization.idpaddon.IdpEntityRepresentation value) {
      if (entityRepresentationsBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureEntityRepresentationsIsMutable();
        entityRepresentations_.set(index, value);
        onChanged();
      } else {
        entityRepresentationsBuilder_.setMessage(index, value);
      }
      return this;
    }
    /**
     * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
     */
    public Builder setEntityRepresentations(
        int index, com.authorization.idpaddon.IdpEntityRepresentation.Builder builderForValue) {
      if (entityRepresentationsBuilder_ == null) {
        ensureEntityRepresentationsIsMutable();
        entityRepresentations_.set(index, builderForValue.build());
        onChanged();
      } else {
        entityRepresentationsBuilder_.setMessage(index, builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
     */
    public Builder addEntityRepresentations(com.authorization.idpaddon.IdpEntityRepresentation value) {
      if (entityRepresentationsBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureEntityRepresentationsIsMutable();
        entityRepresentations_.add(value);
        onChanged();
      } else {
        entityRepresentationsBuilder_.addMessage(value);
      }
      return this;
    }
    /**
     * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
     */
    public Builder addEntityRepresentations(
        int index, com.authorization.idpaddon.IdpEntityRepresentation value) {
      if (entityRepresentationsBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureEntityRepresentationsIsMutable();
        entityRepresentations_.add(index, value);
        onChanged();
      } else {
        entityRepresentationsBuilder_.addMessage(index, value);
      }
      return this;
    }
    /**
     * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
     */
    public Builder addEntityRepresentations(
        com.authorization.idpaddon.IdpEntityRepresentation.Builder builderForValue) {
      if (entityRepresentationsBuilder_ == null) {
        ensureEntityRepresentationsIsMutable();
        entityRepresentations_.add(builderForValue.build());
        onChanged();
      } else {
        entityRepresentationsBuilder_.addMessage(builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
     */
    public Builder addEntityRepresentations(
        int index, com.authorization.idpaddon.IdpEntityRepresentation.Builder builderForValue) {
      if (entityRepresentationsBuilder_ == null) {
        ensureEntityRepresentationsIsMutable();
        entityRepresentations_.add(index, builderForValue.build());
        onChanged();
      } else {
        entityRepresentationsBuilder_.addMessage(index, builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
     */
    public Builder addAllEntityRepresentations(
        java.lang.Iterable<? extends com.authorization.idpaddon.IdpEntityRepresentation> values) {
      if (entityRepresentationsBuilder_ == null) {
        ensureEntityRepresentationsIsMutable();
        com.google.protobuf.AbstractMessageLite.Builder.addAll(
            values, entityRepresentations_);
        onChanged();
      } else {
        entityRepresentationsBuilder_.addAllMessages(values);
      }
      return this;
    }
    /**
     * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
     */
    public Builder clearEntityRepresentations() {
      if (entityRepresentationsBuilder_ == null) {
        entityRepresentations_ = java.util.Collections.emptyList();
        bitField0_ = (bitField0_ & ~0x00000001);
        onChanged();
      } else {
        entityRepresentationsBuilder_.clear();
      }
      return this;
    }
    /**
     * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
     */
    public Builder removeEntityRepresentations(int index) {
      if (entityRepresentationsBuilder_ == null) {
        ensureEntityRepresentationsIsMutable();
        entityRepresentations_.remove(index);
        onChanged();
      } else {
        entityRepresentationsBuilder_.remove(index);
      }
      return this;
    }
    /**
     * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
     */
    public com.authorization.idpaddon.IdpEntityRepresentation.Builder getEntityRepresentationsBuilder(
        int index) {
      return getEntityRepresentationsFieldBuilder().getBuilder(index);
    }
    /**
     * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
     */
    public com.authorization.idpaddon.IdpEntityRepresentationOrBuilder getEntityRepresentationsOrBuilder(
        int index) {
      if (entityRepresentationsBuilder_ == null) {
        return entityRepresentations_.get(index);  } else {
        return entityRepresentationsBuilder_.getMessageOrBuilder(index);
      }
    }
    /**
     * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
     */
    public java.util.List<? extends com.authorization.idpaddon.IdpEntityRepresentationOrBuilder> 
         getEntityRepresentationsOrBuilderList() {
      if (entityRepresentationsBuilder_ != null) {
        return entityRepresentationsBuilder_.getMessageOrBuilderList();
      } else {
        return java.util.Collections.unmodifiableList(entityRepresentations_);
      }
    }
    /**
     * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
     */
    public com.authorization.idpaddon.IdpEntityRepresentation.Builder addEntityRepresentationsBuilder() {
      return getEntityRepresentationsFieldBuilder().addBuilder(
          com.authorization.idpaddon.IdpEntityRepresentation.getDefaultInstance());
    }
    /**
     * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
     */
    public com.authorization.idpaddon.IdpEntityRepresentation.Builder addEntityRepresentationsBuilder(
        int index) {
      return getEntityRepresentationsFieldBuilder().addBuilder(
          index, com.authorization.idpaddon.IdpEntityRepresentation.getDefaultInstance());
    }
    /**
     * <code>repeated .authorization.idpaddon.IdpEntityRepresentation entity_representations = 1 [json_name = "entityRepresentations"];</code>
     */
    public java.util.List<com.authorization.idpaddon.IdpEntityRepresentation.Builder> 
         getEntityRepresentationsBuilderList() {
      return getEntityRepresentationsFieldBuilder().getBuilderList();
    }
    private com.google.protobuf.RepeatedFieldBuilderV3<
        com.authorization.idpaddon.IdpEntityRepresentation, com.authorization.idpaddon.IdpEntityRepresentation.Builder, com.authorization.idpaddon.IdpEntityRepresentationOrBuilder> 
        getEntityRepresentationsFieldBuilder() {
      if (entityRepresentationsBuilder_ == null) {
        entityRepresentationsBuilder_ = new com.google.protobuf.RepeatedFieldBuilderV3<
            com.authorization.idpaddon.IdpEntityRepresentation, com.authorization.idpaddon.IdpEntityRepresentation.Builder, com.authorization.idpaddon.IdpEntityRepresentationOrBuilder>(
                entityRepresentations_,
                ((bitField0_ & 0x00000001) != 0),
                getParentForChildren(),
                isClean());
        entityRepresentations_ = null;
      }
      return entityRepresentationsBuilder_;
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


    // @@protoc_insertion_point(builder_scope:authorization.idpaddon.IdpAddOnResponse)
  }

  // @@protoc_insertion_point(class_scope:authorization.idpaddon.IdpAddOnResponse)
  private static final com.authorization.idpaddon.IdpAddOnResponse DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new com.authorization.idpaddon.IdpAddOnResponse();
  }

  public static com.authorization.idpaddon.IdpAddOnResponse getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<IdpAddOnResponse>
      PARSER = new com.google.protobuf.AbstractParser<IdpAddOnResponse>() {
    @java.lang.Override
    public IdpAddOnResponse parsePartialFrom(
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

  public static com.google.protobuf.Parser<IdpAddOnResponse> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<IdpAddOnResponse> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public com.authorization.idpaddon.IdpAddOnResponse getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

