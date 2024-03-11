// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: kasregistry/key_access_server_registry.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.kasregistry;

/**
 * Protobuf type {@code kasregistry.ListKeyAccessServersResponse}
 */
public final class ListKeyAccessServersResponse extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:kasregistry.ListKeyAccessServersResponse)
    ListKeyAccessServersResponseOrBuilder {
private static final long serialVersionUID = 0L;
  // Use ListKeyAccessServersResponse.newBuilder() to construct.
  private ListKeyAccessServersResponse(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private ListKeyAccessServersResponse() {
    keyAccessServers_ = java.util.Collections.emptyList();
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new ListKeyAccessServersResponse();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return io.opentdf.platform.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_ListKeyAccessServersResponse_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return io.opentdf.platform.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_ListKeyAccessServersResponse_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            io.opentdf.platform.kasregistry.ListKeyAccessServersResponse.class, io.opentdf.platform.kasregistry.ListKeyAccessServersResponse.Builder.class);
  }

  public static final int KEY_ACCESS_SERVERS_FIELD_NUMBER = 1;
  @SuppressWarnings("serial")
  private java.util.List<io.opentdf.platform.kasregistry.KeyAccessServer> keyAccessServers_;
  /**
   * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
   */
  @java.lang.Override
  public java.util.List<io.opentdf.platform.kasregistry.KeyAccessServer> getKeyAccessServersList() {
    return keyAccessServers_;
  }
  /**
   * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
   */
  @java.lang.Override
  public java.util.List<? extends io.opentdf.platform.kasregistry.KeyAccessServerOrBuilder> 
      getKeyAccessServersOrBuilderList() {
    return keyAccessServers_;
  }
  /**
   * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
   */
  @java.lang.Override
  public int getKeyAccessServersCount() {
    return keyAccessServers_.size();
  }
  /**
   * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
   */
  @java.lang.Override
  public io.opentdf.platform.kasregistry.KeyAccessServer getKeyAccessServers(int index) {
    return keyAccessServers_.get(index);
  }
  /**
   * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
   */
  @java.lang.Override
  public io.opentdf.platform.kasregistry.KeyAccessServerOrBuilder getKeyAccessServersOrBuilder(
      int index) {
    return keyAccessServers_.get(index);
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
    for (int i = 0; i < keyAccessServers_.size(); i++) {
      output.writeMessage(1, keyAccessServers_.get(i));
    }
    getUnknownFields().writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    for (int i = 0; i < keyAccessServers_.size(); i++) {
      size += com.google.protobuf.CodedOutputStream
        .computeMessageSize(1, keyAccessServers_.get(i));
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
    if (!(obj instanceof io.opentdf.platform.kasregistry.ListKeyAccessServersResponse)) {
      return super.equals(obj);
    }
    io.opentdf.platform.kasregistry.ListKeyAccessServersResponse other = (io.opentdf.platform.kasregistry.ListKeyAccessServersResponse) obj;

    if (!getKeyAccessServersList()
        .equals(other.getKeyAccessServersList())) return false;
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
    if (getKeyAccessServersCount() > 0) {
      hash = (37 * hash) + KEY_ACCESS_SERVERS_FIELD_NUMBER;
      hash = (53 * hash) + getKeyAccessServersList().hashCode();
    }
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static io.opentdf.platform.kasregistry.ListKeyAccessServersResponse parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.kasregistry.ListKeyAccessServersResponse parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.kasregistry.ListKeyAccessServersResponse parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.kasregistry.ListKeyAccessServersResponse parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.kasregistry.ListKeyAccessServersResponse parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.kasregistry.ListKeyAccessServersResponse parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.kasregistry.ListKeyAccessServersResponse parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.kasregistry.ListKeyAccessServersResponse parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static io.opentdf.platform.kasregistry.ListKeyAccessServersResponse parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static io.opentdf.platform.kasregistry.ListKeyAccessServersResponse parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static io.opentdf.platform.kasregistry.ListKeyAccessServersResponse parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.kasregistry.ListKeyAccessServersResponse parseFrom(
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
  public static Builder newBuilder(io.opentdf.platform.kasregistry.ListKeyAccessServersResponse prototype) {
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
   * Protobuf type {@code kasregistry.ListKeyAccessServersResponse}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:kasregistry.ListKeyAccessServersResponse)
      io.opentdf.platform.kasregistry.ListKeyAccessServersResponseOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return io.opentdf.platform.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_ListKeyAccessServersResponse_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return io.opentdf.platform.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_ListKeyAccessServersResponse_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              io.opentdf.platform.kasregistry.ListKeyAccessServersResponse.class, io.opentdf.platform.kasregistry.ListKeyAccessServersResponse.Builder.class);
    }

    // Construct using io.opentdf.platform.kasregistry.ListKeyAccessServersResponse.newBuilder()
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
      if (keyAccessServersBuilder_ == null) {
        keyAccessServers_ = java.util.Collections.emptyList();
      } else {
        keyAccessServers_ = null;
        keyAccessServersBuilder_.clear();
      }
      bitField0_ = (bitField0_ & ~0x00000001);
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return io.opentdf.platform.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_ListKeyAccessServersResponse_descriptor;
    }

    @java.lang.Override
    public io.opentdf.platform.kasregistry.ListKeyAccessServersResponse getDefaultInstanceForType() {
      return io.opentdf.platform.kasregistry.ListKeyAccessServersResponse.getDefaultInstance();
    }

    @java.lang.Override
    public io.opentdf.platform.kasregistry.ListKeyAccessServersResponse build() {
      io.opentdf.platform.kasregistry.ListKeyAccessServersResponse result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public io.opentdf.platform.kasregistry.ListKeyAccessServersResponse buildPartial() {
      io.opentdf.platform.kasregistry.ListKeyAccessServersResponse result = new io.opentdf.platform.kasregistry.ListKeyAccessServersResponse(this);
      buildPartialRepeatedFields(result);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartialRepeatedFields(io.opentdf.platform.kasregistry.ListKeyAccessServersResponse result) {
      if (keyAccessServersBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0)) {
          keyAccessServers_ = java.util.Collections.unmodifiableList(keyAccessServers_);
          bitField0_ = (bitField0_ & ~0x00000001);
        }
        result.keyAccessServers_ = keyAccessServers_;
      } else {
        result.keyAccessServers_ = keyAccessServersBuilder_.build();
      }
    }

    private void buildPartial0(io.opentdf.platform.kasregistry.ListKeyAccessServersResponse result) {
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
      if (other instanceof io.opentdf.platform.kasregistry.ListKeyAccessServersResponse) {
        return mergeFrom((io.opentdf.platform.kasregistry.ListKeyAccessServersResponse)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(io.opentdf.platform.kasregistry.ListKeyAccessServersResponse other) {
      if (other == io.opentdf.platform.kasregistry.ListKeyAccessServersResponse.getDefaultInstance()) return this;
      if (keyAccessServersBuilder_ == null) {
        if (!other.keyAccessServers_.isEmpty()) {
          if (keyAccessServers_.isEmpty()) {
            keyAccessServers_ = other.keyAccessServers_;
            bitField0_ = (bitField0_ & ~0x00000001);
          } else {
            ensureKeyAccessServersIsMutable();
            keyAccessServers_.addAll(other.keyAccessServers_);
          }
          onChanged();
        }
      } else {
        if (!other.keyAccessServers_.isEmpty()) {
          if (keyAccessServersBuilder_.isEmpty()) {
            keyAccessServersBuilder_.dispose();
            keyAccessServersBuilder_ = null;
            keyAccessServers_ = other.keyAccessServers_;
            bitField0_ = (bitField0_ & ~0x00000001);
            keyAccessServersBuilder_ = 
              com.google.protobuf.GeneratedMessageV3.alwaysUseFieldBuilders ?
                 getKeyAccessServersFieldBuilder() : null;
          } else {
            keyAccessServersBuilder_.addAllMessages(other.keyAccessServers_);
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
              io.opentdf.platform.kasregistry.KeyAccessServer m =
                  input.readMessage(
                      io.opentdf.platform.kasregistry.KeyAccessServer.parser(),
                      extensionRegistry);
              if (keyAccessServersBuilder_ == null) {
                ensureKeyAccessServersIsMutable();
                keyAccessServers_.add(m);
              } else {
                keyAccessServersBuilder_.addMessage(m);
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

    private java.util.List<io.opentdf.platform.kasregistry.KeyAccessServer> keyAccessServers_ =
      java.util.Collections.emptyList();
    private void ensureKeyAccessServersIsMutable() {
      if (!((bitField0_ & 0x00000001) != 0)) {
        keyAccessServers_ = new java.util.ArrayList<io.opentdf.platform.kasregistry.KeyAccessServer>(keyAccessServers_);
        bitField0_ |= 0x00000001;
       }
    }

    private com.google.protobuf.RepeatedFieldBuilderV3<
        io.opentdf.platform.kasregistry.KeyAccessServer, io.opentdf.platform.kasregistry.KeyAccessServer.Builder, io.opentdf.platform.kasregistry.KeyAccessServerOrBuilder> keyAccessServersBuilder_;

    /**
     * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
     */
    public java.util.List<io.opentdf.platform.kasregistry.KeyAccessServer> getKeyAccessServersList() {
      if (keyAccessServersBuilder_ == null) {
        return java.util.Collections.unmodifiableList(keyAccessServers_);
      } else {
        return keyAccessServersBuilder_.getMessageList();
      }
    }
    /**
     * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
     */
    public int getKeyAccessServersCount() {
      if (keyAccessServersBuilder_ == null) {
        return keyAccessServers_.size();
      } else {
        return keyAccessServersBuilder_.getCount();
      }
    }
    /**
     * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
     */
    public io.opentdf.platform.kasregistry.KeyAccessServer getKeyAccessServers(int index) {
      if (keyAccessServersBuilder_ == null) {
        return keyAccessServers_.get(index);
      } else {
        return keyAccessServersBuilder_.getMessage(index);
      }
    }
    /**
     * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
     */
    public Builder setKeyAccessServers(
        int index, io.opentdf.platform.kasregistry.KeyAccessServer value) {
      if (keyAccessServersBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureKeyAccessServersIsMutable();
        keyAccessServers_.set(index, value);
        onChanged();
      } else {
        keyAccessServersBuilder_.setMessage(index, value);
      }
      return this;
    }
    /**
     * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
     */
    public Builder setKeyAccessServers(
        int index, io.opentdf.platform.kasregistry.KeyAccessServer.Builder builderForValue) {
      if (keyAccessServersBuilder_ == null) {
        ensureKeyAccessServersIsMutable();
        keyAccessServers_.set(index, builderForValue.build());
        onChanged();
      } else {
        keyAccessServersBuilder_.setMessage(index, builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
     */
    public Builder addKeyAccessServers(io.opentdf.platform.kasregistry.KeyAccessServer value) {
      if (keyAccessServersBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureKeyAccessServersIsMutable();
        keyAccessServers_.add(value);
        onChanged();
      } else {
        keyAccessServersBuilder_.addMessage(value);
      }
      return this;
    }
    /**
     * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
     */
    public Builder addKeyAccessServers(
        int index, io.opentdf.platform.kasregistry.KeyAccessServer value) {
      if (keyAccessServersBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureKeyAccessServersIsMutable();
        keyAccessServers_.add(index, value);
        onChanged();
      } else {
        keyAccessServersBuilder_.addMessage(index, value);
      }
      return this;
    }
    /**
     * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
     */
    public Builder addKeyAccessServers(
        io.opentdf.platform.kasregistry.KeyAccessServer.Builder builderForValue) {
      if (keyAccessServersBuilder_ == null) {
        ensureKeyAccessServersIsMutable();
        keyAccessServers_.add(builderForValue.build());
        onChanged();
      } else {
        keyAccessServersBuilder_.addMessage(builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
     */
    public Builder addKeyAccessServers(
        int index, io.opentdf.platform.kasregistry.KeyAccessServer.Builder builderForValue) {
      if (keyAccessServersBuilder_ == null) {
        ensureKeyAccessServersIsMutable();
        keyAccessServers_.add(index, builderForValue.build());
        onChanged();
      } else {
        keyAccessServersBuilder_.addMessage(index, builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
     */
    public Builder addAllKeyAccessServers(
        java.lang.Iterable<? extends io.opentdf.platform.kasregistry.KeyAccessServer> values) {
      if (keyAccessServersBuilder_ == null) {
        ensureKeyAccessServersIsMutable();
        com.google.protobuf.AbstractMessageLite.Builder.addAll(
            values, keyAccessServers_);
        onChanged();
      } else {
        keyAccessServersBuilder_.addAllMessages(values);
      }
      return this;
    }
    /**
     * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
     */
    public Builder clearKeyAccessServers() {
      if (keyAccessServersBuilder_ == null) {
        keyAccessServers_ = java.util.Collections.emptyList();
        bitField0_ = (bitField0_ & ~0x00000001);
        onChanged();
      } else {
        keyAccessServersBuilder_.clear();
      }
      return this;
    }
    /**
     * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
     */
    public Builder removeKeyAccessServers(int index) {
      if (keyAccessServersBuilder_ == null) {
        ensureKeyAccessServersIsMutable();
        keyAccessServers_.remove(index);
        onChanged();
      } else {
        keyAccessServersBuilder_.remove(index);
      }
      return this;
    }
    /**
     * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
     */
    public io.opentdf.platform.kasregistry.KeyAccessServer.Builder getKeyAccessServersBuilder(
        int index) {
      return getKeyAccessServersFieldBuilder().getBuilder(index);
    }
    /**
     * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
     */
    public io.opentdf.platform.kasregistry.KeyAccessServerOrBuilder getKeyAccessServersOrBuilder(
        int index) {
      if (keyAccessServersBuilder_ == null) {
        return keyAccessServers_.get(index);  } else {
        return keyAccessServersBuilder_.getMessageOrBuilder(index);
      }
    }
    /**
     * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
     */
    public java.util.List<? extends io.opentdf.platform.kasregistry.KeyAccessServerOrBuilder> 
         getKeyAccessServersOrBuilderList() {
      if (keyAccessServersBuilder_ != null) {
        return keyAccessServersBuilder_.getMessageOrBuilderList();
      } else {
        return java.util.Collections.unmodifiableList(keyAccessServers_);
      }
    }
    /**
     * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
     */
    public io.opentdf.platform.kasregistry.KeyAccessServer.Builder addKeyAccessServersBuilder() {
      return getKeyAccessServersFieldBuilder().addBuilder(
          io.opentdf.platform.kasregistry.KeyAccessServer.getDefaultInstance());
    }
    /**
     * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
     */
    public io.opentdf.platform.kasregistry.KeyAccessServer.Builder addKeyAccessServersBuilder(
        int index) {
      return getKeyAccessServersFieldBuilder().addBuilder(
          index, io.opentdf.platform.kasregistry.KeyAccessServer.getDefaultInstance());
    }
    /**
     * <code>repeated .kasregistry.KeyAccessServer key_access_servers = 1 [json_name = "keyAccessServers"];</code>
     */
    public java.util.List<io.opentdf.platform.kasregistry.KeyAccessServer.Builder> 
         getKeyAccessServersBuilderList() {
      return getKeyAccessServersFieldBuilder().getBuilderList();
    }
    private com.google.protobuf.RepeatedFieldBuilderV3<
        io.opentdf.platform.kasregistry.KeyAccessServer, io.opentdf.platform.kasregistry.KeyAccessServer.Builder, io.opentdf.platform.kasregistry.KeyAccessServerOrBuilder> 
        getKeyAccessServersFieldBuilder() {
      if (keyAccessServersBuilder_ == null) {
        keyAccessServersBuilder_ = new com.google.protobuf.RepeatedFieldBuilderV3<
            io.opentdf.platform.kasregistry.KeyAccessServer, io.opentdf.platform.kasregistry.KeyAccessServer.Builder, io.opentdf.platform.kasregistry.KeyAccessServerOrBuilder>(
                keyAccessServers_,
                ((bitField0_ & 0x00000001) != 0),
                getParentForChildren(),
                isClean());
        keyAccessServers_ = null;
      }
      return keyAccessServersBuilder_;
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


    // @@protoc_insertion_point(builder_scope:kasregistry.ListKeyAccessServersResponse)
  }

  // @@protoc_insertion_point(class_scope:kasregistry.ListKeyAccessServersResponse)
  private static final io.opentdf.platform.kasregistry.ListKeyAccessServersResponse DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new io.opentdf.platform.kasregistry.ListKeyAccessServersResponse();
  }

  public static io.opentdf.platform.kasregistry.ListKeyAccessServersResponse getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<ListKeyAccessServersResponse>
      PARSER = new com.google.protobuf.AbstractParser<ListKeyAccessServersResponse>() {
    @java.lang.Override
    public ListKeyAccessServersResponse parsePartialFrom(
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

  public static com.google.protobuf.Parser<ListKeyAccessServersResponse> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<ListKeyAccessServersResponse> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public io.opentdf.platform.kasregistry.ListKeyAccessServersResponse getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

