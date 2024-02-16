// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: kasregistry/key_access_server_registry.proto

// Protobuf Java Version: 3.25.3
package com.kasregistry;

/**
 * Protobuf type {@code kasregistry.PublicKey}
 */
public final class PublicKey extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:kasregistry.PublicKey)
    PublicKeyOrBuilder {
private static final long serialVersionUID = 0L;
  // Use PublicKey.newBuilder() to construct.
  private PublicKey(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private PublicKey() {
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new PublicKey();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return com.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_PublicKey_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return com.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_PublicKey_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            com.kasregistry.PublicKey.class, com.kasregistry.PublicKey.Builder.class);
  }

  private int publicKeyCase_ = 0;
  @SuppressWarnings("serial")
  private java.lang.Object publicKey_;
  public enum PublicKeyCase
      implements com.google.protobuf.Internal.EnumLite,
          com.google.protobuf.AbstractMessage.InternalOneOfEnum {
    REMOTE(1),
    LOCAL(2),
    PUBLICKEY_NOT_SET(0);
    private final int value;
    private PublicKeyCase(int value) {
      this.value = value;
    }
    /**
     * @param value The number of the enum to look for.
     * @return The enum associated with the given number.
     * @deprecated Use {@link #forNumber(int)} instead.
     */
    @java.lang.Deprecated
    public static PublicKeyCase valueOf(int value) {
      return forNumber(value);
    }

    public static PublicKeyCase forNumber(int value) {
      switch (value) {
        case 1: return REMOTE;
        case 2: return LOCAL;
        case 0: return PUBLICKEY_NOT_SET;
        default: return null;
      }
    }
    public int getNumber() {
      return this.value;
    }
  };

  public PublicKeyCase
  getPublicKeyCase() {
    return PublicKeyCase.forNumber(
        publicKeyCase_);
  }

  public static final int REMOTE_FIELD_NUMBER = 1;
  /**
   * <pre>
   * kas public key url - optional since can also be retrieved via public key
   * </pre>
   *
   * <code>string remote = 1 [json_name = "remote", (.buf.validate.field) = { ... }</code>
   * @return Whether the remote field is set.
   */
  public boolean hasRemote() {
    return publicKeyCase_ == 1;
  }
  /**
   * <pre>
   * kas public key url - optional since can also be retrieved via public key
   * </pre>
   *
   * <code>string remote = 1 [json_name = "remote", (.buf.validate.field) = { ... }</code>
   * @return The remote.
   */
  public java.lang.String getRemote() {
    java.lang.Object ref = "";
    if (publicKeyCase_ == 1) {
      ref = publicKey_;
    }
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      if (publicKeyCase_ == 1) {
        publicKey_ = s;
      }
      return s;
    }
  }
  /**
   * <pre>
   * kas public key url - optional since can also be retrieved via public key
   * </pre>
   *
   * <code>string remote = 1 [json_name = "remote", (.buf.validate.field) = { ... }</code>
   * @return The bytes for remote.
   */
  public com.google.protobuf.ByteString
      getRemoteBytes() {
    java.lang.Object ref = "";
    if (publicKeyCase_ == 1) {
      ref = publicKey_;
    }
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      if (publicKeyCase_ == 1) {
        publicKey_ = b;
      }
      return b;
    } else {
      return (com.google.protobuf.ByteString) ref;
    }
  }

  public static final int LOCAL_FIELD_NUMBER = 2;
  /**
   * <pre>
   * public key - optional since can also be retrieved via url
   * </pre>
   *
   * <code>string local = 2 [json_name = "local"];</code>
   * @return Whether the local field is set.
   */
  public boolean hasLocal() {
    return publicKeyCase_ == 2;
  }
  /**
   * <pre>
   * public key - optional since can also be retrieved via url
   * </pre>
   *
   * <code>string local = 2 [json_name = "local"];</code>
   * @return The local.
   */
  public java.lang.String getLocal() {
    java.lang.Object ref = "";
    if (publicKeyCase_ == 2) {
      ref = publicKey_;
    }
    if (ref instanceof java.lang.String) {
      return (java.lang.String) ref;
    } else {
      com.google.protobuf.ByteString bs = 
          (com.google.protobuf.ByteString) ref;
      java.lang.String s = bs.toStringUtf8();
      if (publicKeyCase_ == 2) {
        publicKey_ = s;
      }
      return s;
    }
  }
  /**
   * <pre>
   * public key - optional since can also be retrieved via url
   * </pre>
   *
   * <code>string local = 2 [json_name = "local"];</code>
   * @return The bytes for local.
   */
  public com.google.protobuf.ByteString
      getLocalBytes() {
    java.lang.Object ref = "";
    if (publicKeyCase_ == 2) {
      ref = publicKey_;
    }
    if (ref instanceof java.lang.String) {
      com.google.protobuf.ByteString b = 
          com.google.protobuf.ByteString.copyFromUtf8(
              (java.lang.String) ref);
      if (publicKeyCase_ == 2) {
        publicKey_ = b;
      }
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
    if (publicKeyCase_ == 1) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 1, publicKey_);
    }
    if (publicKeyCase_ == 2) {
      com.google.protobuf.GeneratedMessageV3.writeString(output, 2, publicKey_);
    }
    getUnknownFields().writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    if (publicKeyCase_ == 1) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(1, publicKey_);
    }
    if (publicKeyCase_ == 2) {
      size += com.google.protobuf.GeneratedMessageV3.computeStringSize(2, publicKey_);
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
    if (!(obj instanceof com.kasregistry.PublicKey)) {
      return super.equals(obj);
    }
    com.kasregistry.PublicKey other = (com.kasregistry.PublicKey) obj;

    if (!getPublicKeyCase().equals(other.getPublicKeyCase())) return false;
    switch (publicKeyCase_) {
      case 1:
        if (!getRemote()
            .equals(other.getRemote())) return false;
        break;
      case 2:
        if (!getLocal()
            .equals(other.getLocal())) return false;
        break;
      case 0:
      default:
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
    switch (publicKeyCase_) {
      case 1:
        hash = (37 * hash) + REMOTE_FIELD_NUMBER;
        hash = (53 * hash) + getRemote().hashCode();
        break;
      case 2:
        hash = (37 * hash) + LOCAL_FIELD_NUMBER;
        hash = (53 * hash) + getLocal().hashCode();
        break;
      case 0:
      default:
    }
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static com.kasregistry.PublicKey parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.kasregistry.PublicKey parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.kasregistry.PublicKey parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.kasregistry.PublicKey parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.kasregistry.PublicKey parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static com.kasregistry.PublicKey parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static com.kasregistry.PublicKey parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.kasregistry.PublicKey parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static com.kasregistry.PublicKey parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static com.kasregistry.PublicKey parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static com.kasregistry.PublicKey parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static com.kasregistry.PublicKey parseFrom(
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
  public static Builder newBuilder(com.kasregistry.PublicKey prototype) {
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
   * Protobuf type {@code kasregistry.PublicKey}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:kasregistry.PublicKey)
      com.kasregistry.PublicKeyOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return com.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_PublicKey_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return com.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_PublicKey_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              com.kasregistry.PublicKey.class, com.kasregistry.PublicKey.Builder.class);
    }

    // Construct using com.kasregistry.PublicKey.newBuilder()
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
      publicKeyCase_ = 0;
      publicKey_ = null;
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return com.kasregistry.KeyAccessServerRegistryProto.internal_static_kasregistry_PublicKey_descriptor;
    }

    @java.lang.Override
    public com.kasregistry.PublicKey getDefaultInstanceForType() {
      return com.kasregistry.PublicKey.getDefaultInstance();
    }

    @java.lang.Override
    public com.kasregistry.PublicKey build() {
      com.kasregistry.PublicKey result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public com.kasregistry.PublicKey buildPartial() {
      com.kasregistry.PublicKey result = new com.kasregistry.PublicKey(this);
      if (bitField0_ != 0) { buildPartial0(result); }
      buildPartialOneofs(result);
      onBuilt();
      return result;
    }

    private void buildPartial0(com.kasregistry.PublicKey result) {
      int from_bitField0_ = bitField0_;
    }

    private void buildPartialOneofs(com.kasregistry.PublicKey result) {
      result.publicKeyCase_ = publicKeyCase_;
      result.publicKey_ = this.publicKey_;
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
      if (other instanceof com.kasregistry.PublicKey) {
        return mergeFrom((com.kasregistry.PublicKey)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(com.kasregistry.PublicKey other) {
      if (other == com.kasregistry.PublicKey.getDefaultInstance()) return this;
      switch (other.getPublicKeyCase()) {
        case REMOTE: {
          publicKeyCase_ = 1;
          publicKey_ = other.publicKey_;
          onChanged();
          break;
        }
        case LOCAL: {
          publicKeyCase_ = 2;
          publicKey_ = other.publicKey_;
          onChanged();
          break;
        }
        case PUBLICKEY_NOT_SET: {
          break;
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
              java.lang.String s = input.readStringRequireUtf8();
              publicKeyCase_ = 1;
              publicKey_ = s;
              break;
            } // case 10
            case 18: {
              java.lang.String s = input.readStringRequireUtf8();
              publicKeyCase_ = 2;
              publicKey_ = s;
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
    private int publicKeyCase_ = 0;
    private java.lang.Object publicKey_;
    public PublicKeyCase
        getPublicKeyCase() {
      return PublicKeyCase.forNumber(
          publicKeyCase_);
    }

    public Builder clearPublicKey() {
      publicKeyCase_ = 0;
      publicKey_ = null;
      onChanged();
      return this;
    }

    private int bitField0_;

    /**
     * <pre>
     * kas public key url - optional since can also be retrieved via public key
     * </pre>
     *
     * <code>string remote = 1 [json_name = "remote", (.buf.validate.field) = { ... }</code>
     * @return Whether the remote field is set.
     */
    @java.lang.Override
    public boolean hasRemote() {
      return publicKeyCase_ == 1;
    }
    /**
     * <pre>
     * kas public key url - optional since can also be retrieved via public key
     * </pre>
     *
     * <code>string remote = 1 [json_name = "remote", (.buf.validate.field) = { ... }</code>
     * @return The remote.
     */
    @java.lang.Override
    public java.lang.String getRemote() {
      java.lang.Object ref = "";
      if (publicKeyCase_ == 1) {
        ref = publicKey_;
      }
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        if (publicKeyCase_ == 1) {
          publicKey_ = s;
        }
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <pre>
     * kas public key url - optional since can also be retrieved via public key
     * </pre>
     *
     * <code>string remote = 1 [json_name = "remote", (.buf.validate.field) = { ... }</code>
     * @return The bytes for remote.
     */
    @java.lang.Override
    public com.google.protobuf.ByteString
        getRemoteBytes() {
      java.lang.Object ref = "";
      if (publicKeyCase_ == 1) {
        ref = publicKey_;
      }
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        if (publicKeyCase_ == 1) {
          publicKey_ = b;
        }
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <pre>
     * kas public key url - optional since can also be retrieved via public key
     * </pre>
     *
     * <code>string remote = 1 [json_name = "remote", (.buf.validate.field) = { ... }</code>
     * @param value The remote to set.
     * @return This builder for chaining.
     */
    public Builder setRemote(
        java.lang.String value) {
      if (value == null) { throw new NullPointerException(); }
      publicKeyCase_ = 1;
      publicKey_ = value;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * kas public key url - optional since can also be retrieved via public key
     * </pre>
     *
     * <code>string remote = 1 [json_name = "remote", (.buf.validate.field) = { ... }</code>
     * @return This builder for chaining.
     */
    public Builder clearRemote() {
      if (publicKeyCase_ == 1) {
        publicKeyCase_ = 0;
        publicKey_ = null;
        onChanged();
      }
      return this;
    }
    /**
     * <pre>
     * kas public key url - optional since can also be retrieved via public key
     * </pre>
     *
     * <code>string remote = 1 [json_name = "remote", (.buf.validate.field) = { ... }</code>
     * @param value The bytes for remote to set.
     * @return This builder for chaining.
     */
    public Builder setRemoteBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) { throw new NullPointerException(); }
      checkByteStringIsUtf8(value);
      publicKeyCase_ = 1;
      publicKey_ = value;
      onChanged();
      return this;
    }

    /**
     * <pre>
     * public key - optional since can also be retrieved via url
     * </pre>
     *
     * <code>string local = 2 [json_name = "local"];</code>
     * @return Whether the local field is set.
     */
    @java.lang.Override
    public boolean hasLocal() {
      return publicKeyCase_ == 2;
    }
    /**
     * <pre>
     * public key - optional since can also be retrieved via url
     * </pre>
     *
     * <code>string local = 2 [json_name = "local"];</code>
     * @return The local.
     */
    @java.lang.Override
    public java.lang.String getLocal() {
      java.lang.Object ref = "";
      if (publicKeyCase_ == 2) {
        ref = publicKey_;
      }
      if (!(ref instanceof java.lang.String)) {
        com.google.protobuf.ByteString bs =
            (com.google.protobuf.ByteString) ref;
        java.lang.String s = bs.toStringUtf8();
        if (publicKeyCase_ == 2) {
          publicKey_ = s;
        }
        return s;
      } else {
        return (java.lang.String) ref;
      }
    }
    /**
     * <pre>
     * public key - optional since can also be retrieved via url
     * </pre>
     *
     * <code>string local = 2 [json_name = "local"];</code>
     * @return The bytes for local.
     */
    @java.lang.Override
    public com.google.protobuf.ByteString
        getLocalBytes() {
      java.lang.Object ref = "";
      if (publicKeyCase_ == 2) {
        ref = publicKey_;
      }
      if (ref instanceof String) {
        com.google.protobuf.ByteString b = 
            com.google.protobuf.ByteString.copyFromUtf8(
                (java.lang.String) ref);
        if (publicKeyCase_ == 2) {
          publicKey_ = b;
        }
        return b;
      } else {
        return (com.google.protobuf.ByteString) ref;
      }
    }
    /**
     * <pre>
     * public key - optional since can also be retrieved via url
     * </pre>
     *
     * <code>string local = 2 [json_name = "local"];</code>
     * @param value The local to set.
     * @return This builder for chaining.
     */
    public Builder setLocal(
        java.lang.String value) {
      if (value == null) { throw new NullPointerException(); }
      publicKeyCase_ = 2;
      publicKey_ = value;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * public key - optional since can also be retrieved via url
     * </pre>
     *
     * <code>string local = 2 [json_name = "local"];</code>
     * @return This builder for chaining.
     */
    public Builder clearLocal() {
      if (publicKeyCase_ == 2) {
        publicKeyCase_ = 0;
        publicKey_ = null;
        onChanged();
      }
      return this;
    }
    /**
     * <pre>
     * public key - optional since can also be retrieved via url
     * </pre>
     *
     * <code>string local = 2 [json_name = "local"];</code>
     * @param value The bytes for local to set.
     * @return This builder for chaining.
     */
    public Builder setLocalBytes(
        com.google.protobuf.ByteString value) {
      if (value == null) { throw new NullPointerException(); }
      checkByteStringIsUtf8(value);
      publicKeyCase_ = 2;
      publicKey_ = value;
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


    // @@protoc_insertion_point(builder_scope:kasregistry.PublicKey)
  }

  // @@protoc_insertion_point(class_scope:kasregistry.PublicKey)
  private static final com.kasregistry.PublicKey DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new com.kasregistry.PublicKey();
  }

  public static com.kasregistry.PublicKey getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<PublicKey>
      PARSER = new com.google.protobuf.AbstractParser<PublicKey>() {
    @java.lang.Override
    public PublicKey parsePartialFrom(
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

  public static com.google.protobuf.Parser<PublicKey> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<PublicKey> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public com.kasregistry.PublicKey getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

