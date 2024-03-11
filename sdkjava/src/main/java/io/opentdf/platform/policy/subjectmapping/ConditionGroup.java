// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/subjectmapping/subject_mapping.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.policy.subjectmapping;

/**
 * <pre>
 * A collection of Conditions evaluated by the boolean_operator provided
 * </pre>
 *
 * Protobuf type {@code policy.subjectmapping.ConditionGroup}
 */
public final class ConditionGroup extends
    com.google.protobuf.GeneratedMessageV3 implements
    // @@protoc_insertion_point(message_implements:policy.subjectmapping.ConditionGroup)
    ConditionGroupOrBuilder {
private static final long serialVersionUID = 0L;
  // Use ConditionGroup.newBuilder() to construct.
  private ConditionGroup(com.google.protobuf.GeneratedMessageV3.Builder<?> builder) {
    super(builder);
  }
  private ConditionGroup() {
    conditions_ = java.util.Collections.emptyList();
    booleanOperator_ = 0;
  }

  @java.lang.Override
  @SuppressWarnings({"unused"})
  protected java.lang.Object newInstance(
      UnusedPrivateParameter unused) {
    return new ConditionGroup();
  }

  public static final com.google.protobuf.Descriptors.Descriptor
      getDescriptor() {
    return io.opentdf.platform.policy.subjectmapping.SubjectMappingProto.internal_static_policy_subjectmapping_ConditionGroup_descriptor;
  }

  @java.lang.Override
  protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
      internalGetFieldAccessorTable() {
    return io.opentdf.platform.policy.subjectmapping.SubjectMappingProto.internal_static_policy_subjectmapping_ConditionGroup_fieldAccessorTable
        .ensureFieldAccessorsInitialized(
            io.opentdf.platform.policy.subjectmapping.ConditionGroup.class, io.opentdf.platform.policy.subjectmapping.ConditionGroup.Builder.class);
  }

  public static final int CONDITIONS_FIELD_NUMBER = 1;
  @SuppressWarnings("serial")
  private java.util.List<io.opentdf.platform.policy.subjectmapping.Condition> conditions_;
  /**
   * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
   */
  @java.lang.Override
  public java.util.List<io.opentdf.platform.policy.subjectmapping.Condition> getConditionsList() {
    return conditions_;
  }
  /**
   * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
   */
  @java.lang.Override
  public java.util.List<? extends io.opentdf.platform.policy.subjectmapping.ConditionOrBuilder> 
      getConditionsOrBuilderList() {
    return conditions_;
  }
  /**
   * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
   */
  @java.lang.Override
  public int getConditionsCount() {
    return conditions_.size();
  }
  /**
   * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
   */
  @java.lang.Override
  public io.opentdf.platform.policy.subjectmapping.Condition getConditions(int index) {
    return conditions_.get(index);
  }
  /**
   * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
   */
  @java.lang.Override
  public io.opentdf.platform.policy.subjectmapping.ConditionOrBuilder getConditionsOrBuilder(
      int index) {
    return conditions_.get(index);
  }

  public static final int BOOLEAN_OPERATOR_FIELD_NUMBER = 2;
  private int booleanOperator_ = 0;
  /**
   * <pre>
   * the boolean evaluation type across the conditions
   * </pre>
   *
   * <code>.policy.subjectmapping.ConditionBooleanTypeEnum boolean_operator = 2 [json_name = "booleanOperator", (.buf.validate.field) = { ... }</code>
   * @return The enum numeric value on the wire for booleanOperator.
   */
  @java.lang.Override public int getBooleanOperatorValue() {
    return booleanOperator_;
  }
  /**
   * <pre>
   * the boolean evaluation type across the conditions
   * </pre>
   *
   * <code>.policy.subjectmapping.ConditionBooleanTypeEnum boolean_operator = 2 [json_name = "booleanOperator", (.buf.validate.field) = { ... }</code>
   * @return The booleanOperator.
   */
  @java.lang.Override public io.opentdf.platform.policy.subjectmapping.ConditionBooleanTypeEnum getBooleanOperator() {
    io.opentdf.platform.policy.subjectmapping.ConditionBooleanTypeEnum result = io.opentdf.platform.policy.subjectmapping.ConditionBooleanTypeEnum.forNumber(booleanOperator_);
    return result == null ? io.opentdf.platform.policy.subjectmapping.ConditionBooleanTypeEnum.UNRECOGNIZED : result;
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
    for (int i = 0; i < conditions_.size(); i++) {
      output.writeMessage(1, conditions_.get(i));
    }
    if (booleanOperator_ != io.opentdf.platform.policy.subjectmapping.ConditionBooleanTypeEnum.CONDITION_BOOLEAN_TYPE_ENUM_UNSPECIFIED.getNumber()) {
      output.writeEnum(2, booleanOperator_);
    }
    getUnknownFields().writeTo(output);
  }

  @java.lang.Override
  public int getSerializedSize() {
    int size = memoizedSize;
    if (size != -1) return size;

    size = 0;
    for (int i = 0; i < conditions_.size(); i++) {
      size += com.google.protobuf.CodedOutputStream
        .computeMessageSize(1, conditions_.get(i));
    }
    if (booleanOperator_ != io.opentdf.platform.policy.subjectmapping.ConditionBooleanTypeEnum.CONDITION_BOOLEAN_TYPE_ENUM_UNSPECIFIED.getNumber()) {
      size += com.google.protobuf.CodedOutputStream
        .computeEnumSize(2, booleanOperator_);
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
    if (!(obj instanceof io.opentdf.platform.policy.subjectmapping.ConditionGroup)) {
      return super.equals(obj);
    }
    io.opentdf.platform.policy.subjectmapping.ConditionGroup other = (io.opentdf.platform.policy.subjectmapping.ConditionGroup) obj;

    if (!getConditionsList()
        .equals(other.getConditionsList())) return false;
    if (booleanOperator_ != other.booleanOperator_) return false;
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
    if (getConditionsCount() > 0) {
      hash = (37 * hash) + CONDITIONS_FIELD_NUMBER;
      hash = (53 * hash) + getConditionsList().hashCode();
    }
    hash = (37 * hash) + BOOLEAN_OPERATOR_FIELD_NUMBER;
    hash = (53 * hash) + booleanOperator_;
    hash = (29 * hash) + getUnknownFields().hashCode();
    memoizedHashCode = hash;
    return hash;
  }

  public static io.opentdf.platform.policy.subjectmapping.ConditionGroup parseFrom(
      java.nio.ByteBuffer data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.subjectmapping.ConditionGroup parseFrom(
      java.nio.ByteBuffer data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.subjectmapping.ConditionGroup parseFrom(
      com.google.protobuf.ByteString data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.subjectmapping.ConditionGroup parseFrom(
      com.google.protobuf.ByteString data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.subjectmapping.ConditionGroup parseFrom(byte[] data)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data);
  }
  public static io.opentdf.platform.policy.subjectmapping.ConditionGroup parseFrom(
      byte[] data,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws com.google.protobuf.InvalidProtocolBufferException {
    return PARSER.parseFrom(data, extensionRegistry);
  }
  public static io.opentdf.platform.policy.subjectmapping.ConditionGroup parseFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.policy.subjectmapping.ConditionGroup parseFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input, extensionRegistry);
  }

  public static io.opentdf.platform.policy.subjectmapping.ConditionGroup parseDelimitedFrom(java.io.InputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input);
  }

  public static io.opentdf.platform.policy.subjectmapping.ConditionGroup parseDelimitedFrom(
      java.io.InputStream input,
      com.google.protobuf.ExtensionRegistryLite extensionRegistry)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseDelimitedWithIOException(PARSER, input, extensionRegistry);
  }
  public static io.opentdf.platform.policy.subjectmapping.ConditionGroup parseFrom(
      com.google.protobuf.CodedInputStream input)
      throws java.io.IOException {
    return com.google.protobuf.GeneratedMessageV3
        .parseWithIOException(PARSER, input);
  }
  public static io.opentdf.platform.policy.subjectmapping.ConditionGroup parseFrom(
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
  public static Builder newBuilder(io.opentdf.platform.policy.subjectmapping.ConditionGroup prototype) {
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
   * A collection of Conditions evaluated by the boolean_operator provided
   * </pre>
   *
   * Protobuf type {@code policy.subjectmapping.ConditionGroup}
   */
  public static final class Builder extends
      com.google.protobuf.GeneratedMessageV3.Builder<Builder> implements
      // @@protoc_insertion_point(builder_implements:policy.subjectmapping.ConditionGroup)
      io.opentdf.platform.policy.subjectmapping.ConditionGroupOrBuilder {
    public static final com.google.protobuf.Descriptors.Descriptor
        getDescriptor() {
      return io.opentdf.platform.policy.subjectmapping.SubjectMappingProto.internal_static_policy_subjectmapping_ConditionGroup_descriptor;
    }

    @java.lang.Override
    protected com.google.protobuf.GeneratedMessageV3.FieldAccessorTable
        internalGetFieldAccessorTable() {
      return io.opentdf.platform.policy.subjectmapping.SubjectMappingProto.internal_static_policy_subjectmapping_ConditionGroup_fieldAccessorTable
          .ensureFieldAccessorsInitialized(
              io.opentdf.platform.policy.subjectmapping.ConditionGroup.class, io.opentdf.platform.policy.subjectmapping.ConditionGroup.Builder.class);
    }

    // Construct using io.opentdf.platform.policy.subjectmapping.ConditionGroup.newBuilder()
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
      if (conditionsBuilder_ == null) {
        conditions_ = java.util.Collections.emptyList();
      } else {
        conditions_ = null;
        conditionsBuilder_.clear();
      }
      bitField0_ = (bitField0_ & ~0x00000001);
      booleanOperator_ = 0;
      return this;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.Descriptor
        getDescriptorForType() {
      return io.opentdf.platform.policy.subjectmapping.SubjectMappingProto.internal_static_policy_subjectmapping_ConditionGroup_descriptor;
    }

    @java.lang.Override
    public io.opentdf.platform.policy.subjectmapping.ConditionGroup getDefaultInstanceForType() {
      return io.opentdf.platform.policy.subjectmapping.ConditionGroup.getDefaultInstance();
    }

    @java.lang.Override
    public io.opentdf.platform.policy.subjectmapping.ConditionGroup build() {
      io.opentdf.platform.policy.subjectmapping.ConditionGroup result = buildPartial();
      if (!result.isInitialized()) {
        throw newUninitializedMessageException(result);
      }
      return result;
    }

    @java.lang.Override
    public io.opentdf.platform.policy.subjectmapping.ConditionGroup buildPartial() {
      io.opentdf.platform.policy.subjectmapping.ConditionGroup result = new io.opentdf.platform.policy.subjectmapping.ConditionGroup(this);
      buildPartialRepeatedFields(result);
      if (bitField0_ != 0) { buildPartial0(result); }
      onBuilt();
      return result;
    }

    private void buildPartialRepeatedFields(io.opentdf.platform.policy.subjectmapping.ConditionGroup result) {
      if (conditionsBuilder_ == null) {
        if (((bitField0_ & 0x00000001) != 0)) {
          conditions_ = java.util.Collections.unmodifiableList(conditions_);
          bitField0_ = (bitField0_ & ~0x00000001);
        }
        result.conditions_ = conditions_;
      } else {
        result.conditions_ = conditionsBuilder_.build();
      }
    }

    private void buildPartial0(io.opentdf.platform.policy.subjectmapping.ConditionGroup result) {
      int from_bitField0_ = bitField0_;
      if (((from_bitField0_ & 0x00000002) != 0)) {
        result.booleanOperator_ = booleanOperator_;
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
      if (other instanceof io.opentdf.platform.policy.subjectmapping.ConditionGroup) {
        return mergeFrom((io.opentdf.platform.policy.subjectmapping.ConditionGroup)other);
      } else {
        super.mergeFrom(other);
        return this;
      }
    }

    public Builder mergeFrom(io.opentdf.platform.policy.subjectmapping.ConditionGroup other) {
      if (other == io.opentdf.platform.policy.subjectmapping.ConditionGroup.getDefaultInstance()) return this;
      if (conditionsBuilder_ == null) {
        if (!other.conditions_.isEmpty()) {
          if (conditions_.isEmpty()) {
            conditions_ = other.conditions_;
            bitField0_ = (bitField0_ & ~0x00000001);
          } else {
            ensureConditionsIsMutable();
            conditions_.addAll(other.conditions_);
          }
          onChanged();
        }
      } else {
        if (!other.conditions_.isEmpty()) {
          if (conditionsBuilder_.isEmpty()) {
            conditionsBuilder_.dispose();
            conditionsBuilder_ = null;
            conditions_ = other.conditions_;
            bitField0_ = (bitField0_ & ~0x00000001);
            conditionsBuilder_ = 
              com.google.protobuf.GeneratedMessageV3.alwaysUseFieldBuilders ?
                 getConditionsFieldBuilder() : null;
          } else {
            conditionsBuilder_.addAllMessages(other.conditions_);
          }
        }
      }
      if (other.booleanOperator_ != 0) {
        setBooleanOperatorValue(other.getBooleanOperatorValue());
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
              io.opentdf.platform.policy.subjectmapping.Condition m =
                  input.readMessage(
                      io.opentdf.platform.policy.subjectmapping.Condition.parser(),
                      extensionRegistry);
              if (conditionsBuilder_ == null) {
                ensureConditionsIsMutable();
                conditions_.add(m);
              } else {
                conditionsBuilder_.addMessage(m);
              }
              break;
            } // case 10
            case 16: {
              booleanOperator_ = input.readEnum();
              bitField0_ |= 0x00000002;
              break;
            } // case 16
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

    private java.util.List<io.opentdf.platform.policy.subjectmapping.Condition> conditions_ =
      java.util.Collections.emptyList();
    private void ensureConditionsIsMutable() {
      if (!((bitField0_ & 0x00000001) != 0)) {
        conditions_ = new java.util.ArrayList<io.opentdf.platform.policy.subjectmapping.Condition>(conditions_);
        bitField0_ |= 0x00000001;
       }
    }

    private com.google.protobuf.RepeatedFieldBuilderV3<
        io.opentdf.platform.policy.subjectmapping.Condition, io.opentdf.platform.policy.subjectmapping.Condition.Builder, io.opentdf.platform.policy.subjectmapping.ConditionOrBuilder> conditionsBuilder_;

    /**
     * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
     */
    public java.util.List<io.opentdf.platform.policy.subjectmapping.Condition> getConditionsList() {
      if (conditionsBuilder_ == null) {
        return java.util.Collections.unmodifiableList(conditions_);
      } else {
        return conditionsBuilder_.getMessageList();
      }
    }
    /**
     * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
     */
    public int getConditionsCount() {
      if (conditionsBuilder_ == null) {
        return conditions_.size();
      } else {
        return conditionsBuilder_.getCount();
      }
    }
    /**
     * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
     */
    public io.opentdf.platform.policy.subjectmapping.Condition getConditions(int index) {
      if (conditionsBuilder_ == null) {
        return conditions_.get(index);
      } else {
        return conditionsBuilder_.getMessage(index);
      }
    }
    /**
     * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
     */
    public Builder setConditions(
        int index, io.opentdf.platform.policy.subjectmapping.Condition value) {
      if (conditionsBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureConditionsIsMutable();
        conditions_.set(index, value);
        onChanged();
      } else {
        conditionsBuilder_.setMessage(index, value);
      }
      return this;
    }
    /**
     * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
     */
    public Builder setConditions(
        int index, io.opentdf.platform.policy.subjectmapping.Condition.Builder builderForValue) {
      if (conditionsBuilder_ == null) {
        ensureConditionsIsMutable();
        conditions_.set(index, builderForValue.build());
        onChanged();
      } else {
        conditionsBuilder_.setMessage(index, builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
     */
    public Builder addConditions(io.opentdf.platform.policy.subjectmapping.Condition value) {
      if (conditionsBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureConditionsIsMutable();
        conditions_.add(value);
        onChanged();
      } else {
        conditionsBuilder_.addMessage(value);
      }
      return this;
    }
    /**
     * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
     */
    public Builder addConditions(
        int index, io.opentdf.platform.policy.subjectmapping.Condition value) {
      if (conditionsBuilder_ == null) {
        if (value == null) {
          throw new NullPointerException();
        }
        ensureConditionsIsMutable();
        conditions_.add(index, value);
        onChanged();
      } else {
        conditionsBuilder_.addMessage(index, value);
      }
      return this;
    }
    /**
     * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
     */
    public Builder addConditions(
        io.opentdf.platform.policy.subjectmapping.Condition.Builder builderForValue) {
      if (conditionsBuilder_ == null) {
        ensureConditionsIsMutable();
        conditions_.add(builderForValue.build());
        onChanged();
      } else {
        conditionsBuilder_.addMessage(builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
     */
    public Builder addConditions(
        int index, io.opentdf.platform.policy.subjectmapping.Condition.Builder builderForValue) {
      if (conditionsBuilder_ == null) {
        ensureConditionsIsMutable();
        conditions_.add(index, builderForValue.build());
        onChanged();
      } else {
        conditionsBuilder_.addMessage(index, builderForValue.build());
      }
      return this;
    }
    /**
     * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
     */
    public Builder addAllConditions(
        java.lang.Iterable<? extends io.opentdf.platform.policy.subjectmapping.Condition> values) {
      if (conditionsBuilder_ == null) {
        ensureConditionsIsMutable();
        com.google.protobuf.AbstractMessageLite.Builder.addAll(
            values, conditions_);
        onChanged();
      } else {
        conditionsBuilder_.addAllMessages(values);
      }
      return this;
    }
    /**
     * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
     */
    public Builder clearConditions() {
      if (conditionsBuilder_ == null) {
        conditions_ = java.util.Collections.emptyList();
        bitField0_ = (bitField0_ & ~0x00000001);
        onChanged();
      } else {
        conditionsBuilder_.clear();
      }
      return this;
    }
    /**
     * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
     */
    public Builder removeConditions(int index) {
      if (conditionsBuilder_ == null) {
        ensureConditionsIsMutable();
        conditions_.remove(index);
        onChanged();
      } else {
        conditionsBuilder_.remove(index);
      }
      return this;
    }
    /**
     * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
     */
    public io.opentdf.platform.policy.subjectmapping.Condition.Builder getConditionsBuilder(
        int index) {
      return getConditionsFieldBuilder().getBuilder(index);
    }
    /**
     * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
     */
    public io.opentdf.platform.policy.subjectmapping.ConditionOrBuilder getConditionsOrBuilder(
        int index) {
      if (conditionsBuilder_ == null) {
        return conditions_.get(index);  } else {
        return conditionsBuilder_.getMessageOrBuilder(index);
      }
    }
    /**
     * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
     */
    public java.util.List<? extends io.opentdf.platform.policy.subjectmapping.ConditionOrBuilder> 
         getConditionsOrBuilderList() {
      if (conditionsBuilder_ != null) {
        return conditionsBuilder_.getMessageOrBuilderList();
      } else {
        return java.util.Collections.unmodifiableList(conditions_);
      }
    }
    /**
     * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
     */
    public io.opentdf.platform.policy.subjectmapping.Condition.Builder addConditionsBuilder() {
      return getConditionsFieldBuilder().addBuilder(
          io.opentdf.platform.policy.subjectmapping.Condition.getDefaultInstance());
    }
    /**
     * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
     */
    public io.opentdf.platform.policy.subjectmapping.Condition.Builder addConditionsBuilder(
        int index) {
      return getConditionsFieldBuilder().addBuilder(
          index, io.opentdf.platform.policy.subjectmapping.Condition.getDefaultInstance());
    }
    /**
     * <code>repeated .policy.subjectmapping.Condition conditions = 1 [json_name = "conditions", (.buf.validate.field) = { ... }</code>
     */
    public java.util.List<io.opentdf.platform.policy.subjectmapping.Condition.Builder> 
         getConditionsBuilderList() {
      return getConditionsFieldBuilder().getBuilderList();
    }
    private com.google.protobuf.RepeatedFieldBuilderV3<
        io.opentdf.platform.policy.subjectmapping.Condition, io.opentdf.platform.policy.subjectmapping.Condition.Builder, io.opentdf.platform.policy.subjectmapping.ConditionOrBuilder> 
        getConditionsFieldBuilder() {
      if (conditionsBuilder_ == null) {
        conditionsBuilder_ = new com.google.protobuf.RepeatedFieldBuilderV3<
            io.opentdf.platform.policy.subjectmapping.Condition, io.opentdf.platform.policy.subjectmapping.Condition.Builder, io.opentdf.platform.policy.subjectmapping.ConditionOrBuilder>(
                conditions_,
                ((bitField0_ & 0x00000001) != 0),
                getParentForChildren(),
                isClean());
        conditions_ = null;
      }
      return conditionsBuilder_;
    }

    private int booleanOperator_ = 0;
    /**
     * <pre>
     * the boolean evaluation type across the conditions
     * </pre>
     *
     * <code>.policy.subjectmapping.ConditionBooleanTypeEnum boolean_operator = 2 [json_name = "booleanOperator", (.buf.validate.field) = { ... }</code>
     * @return The enum numeric value on the wire for booleanOperator.
     */
    @java.lang.Override public int getBooleanOperatorValue() {
      return booleanOperator_;
    }
    /**
     * <pre>
     * the boolean evaluation type across the conditions
     * </pre>
     *
     * <code>.policy.subjectmapping.ConditionBooleanTypeEnum boolean_operator = 2 [json_name = "booleanOperator", (.buf.validate.field) = { ... }</code>
     * @param value The enum numeric value on the wire for booleanOperator to set.
     * @return This builder for chaining.
     */
    public Builder setBooleanOperatorValue(int value) {
      booleanOperator_ = value;
      bitField0_ |= 0x00000002;
      onChanged();
      return this;
    }
    /**
     * <pre>
     * the boolean evaluation type across the conditions
     * </pre>
     *
     * <code>.policy.subjectmapping.ConditionBooleanTypeEnum boolean_operator = 2 [json_name = "booleanOperator", (.buf.validate.field) = { ... }</code>
     * @return The booleanOperator.
     */
    @java.lang.Override
    public io.opentdf.platform.policy.subjectmapping.ConditionBooleanTypeEnum getBooleanOperator() {
      io.opentdf.platform.policy.subjectmapping.ConditionBooleanTypeEnum result = io.opentdf.platform.policy.subjectmapping.ConditionBooleanTypeEnum.forNumber(booleanOperator_);
      return result == null ? io.opentdf.platform.policy.subjectmapping.ConditionBooleanTypeEnum.UNRECOGNIZED : result;
    }
    /**
     * <pre>
     * the boolean evaluation type across the conditions
     * </pre>
     *
     * <code>.policy.subjectmapping.ConditionBooleanTypeEnum boolean_operator = 2 [json_name = "booleanOperator", (.buf.validate.field) = { ... }</code>
     * @param value The booleanOperator to set.
     * @return This builder for chaining.
     */
    public Builder setBooleanOperator(io.opentdf.platform.policy.subjectmapping.ConditionBooleanTypeEnum value) {
      if (value == null) {
        throw new NullPointerException();
      }
      bitField0_ |= 0x00000002;
      booleanOperator_ = value.getNumber();
      onChanged();
      return this;
    }
    /**
     * <pre>
     * the boolean evaluation type across the conditions
     * </pre>
     *
     * <code>.policy.subjectmapping.ConditionBooleanTypeEnum boolean_operator = 2 [json_name = "booleanOperator", (.buf.validate.field) = { ... }</code>
     * @return This builder for chaining.
     */
    public Builder clearBooleanOperator() {
      bitField0_ = (bitField0_ & ~0x00000002);
      booleanOperator_ = 0;
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


    // @@protoc_insertion_point(builder_scope:policy.subjectmapping.ConditionGroup)
  }

  // @@protoc_insertion_point(class_scope:policy.subjectmapping.ConditionGroup)
  private static final io.opentdf.platform.policy.subjectmapping.ConditionGroup DEFAULT_INSTANCE;
  static {
    DEFAULT_INSTANCE = new io.opentdf.platform.policy.subjectmapping.ConditionGroup();
  }

  public static io.opentdf.platform.policy.subjectmapping.ConditionGroup getDefaultInstance() {
    return DEFAULT_INSTANCE;
  }

  private static final com.google.protobuf.Parser<ConditionGroup>
      PARSER = new com.google.protobuf.AbstractParser<ConditionGroup>() {
    @java.lang.Override
    public ConditionGroup parsePartialFrom(
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

  public static com.google.protobuf.Parser<ConditionGroup> parser() {
    return PARSER;
  }

  @java.lang.Override
  public com.google.protobuf.Parser<ConditionGroup> getParserForType() {
    return PARSER;
  }

  @java.lang.Override
  public io.opentdf.platform.policy.subjectmapping.ConditionGroup getDefaultInstanceForType() {
    return DEFAULT_INSTANCE;
  }

}

