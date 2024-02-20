// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: common/common.proto

// Protobuf Java Version: 3.25.3
package com.common;

/**
 * <pre>
 * buflint ENUM_VALUE_PREFIX: to make sure that C++ scoping rules aren't violated when users add new enum values to an enum in a given package
 * </pre>
 *
 * Protobuf enum {@code common.ActiveStateEnum}
 */
public enum ActiveStateEnum
    implements com.google.protobuf.ProtocolMessageEnum {
  /**
   * <code>ACTIVE_STATE_ENUM_UNSPECIFIED = 0;</code>
   */
  ACTIVE_STATE_ENUM_UNSPECIFIED(0),
  /**
   * <code>ACTIVE_STATE_ENUM_ACTIVE = 1;</code>
   */
  ACTIVE_STATE_ENUM_ACTIVE(1),
  /**
   * <code>ACTIVE_STATE_ENUM_INACTIVE = 2;</code>
   */
  ACTIVE_STATE_ENUM_INACTIVE(2),
  /**
   * <code>ACTIVE_STATE_ENUM_ANY = 3;</code>
   */
  ACTIVE_STATE_ENUM_ANY(3),
  UNRECOGNIZED(-1),
  ;

  /**
   * <code>ACTIVE_STATE_ENUM_UNSPECIFIED = 0;</code>
   */
  public static final int ACTIVE_STATE_ENUM_UNSPECIFIED_VALUE = 0;
  /**
   * <code>ACTIVE_STATE_ENUM_ACTIVE = 1;</code>
   */
  public static final int ACTIVE_STATE_ENUM_ACTIVE_VALUE = 1;
  /**
   * <code>ACTIVE_STATE_ENUM_INACTIVE = 2;</code>
   */
  public static final int ACTIVE_STATE_ENUM_INACTIVE_VALUE = 2;
  /**
   * <code>ACTIVE_STATE_ENUM_ANY = 3;</code>
   */
  public static final int ACTIVE_STATE_ENUM_ANY_VALUE = 3;


  public final int getNumber() {
    if (this == UNRECOGNIZED) {
      throw new java.lang.IllegalArgumentException(
          "Can't get the number of an unknown enum value.");
    }
    return value;
  }

  /**
   * @param value The numeric wire value of the corresponding enum entry.
   * @return The enum associated with the given numeric wire value.
   * @deprecated Use {@link #forNumber(int)} instead.
   */
  @java.lang.Deprecated
  public static ActiveStateEnum valueOf(int value) {
    return forNumber(value);
  }

  /**
   * @param value The numeric wire value of the corresponding enum entry.
   * @return The enum associated with the given numeric wire value.
   */
  public static ActiveStateEnum forNumber(int value) {
    switch (value) {
      case 0: return ACTIVE_STATE_ENUM_UNSPECIFIED;
      case 1: return ACTIVE_STATE_ENUM_ACTIVE;
      case 2: return ACTIVE_STATE_ENUM_INACTIVE;
      case 3: return ACTIVE_STATE_ENUM_ANY;
      default: return null;
    }
  }

  public static com.google.protobuf.Internal.EnumLiteMap<ActiveStateEnum>
      internalGetValueMap() {
    return internalValueMap;
  }
  private static final com.google.protobuf.Internal.EnumLiteMap<
      ActiveStateEnum> internalValueMap =
        new com.google.protobuf.Internal.EnumLiteMap<ActiveStateEnum>() {
          public ActiveStateEnum findValueByNumber(int number) {
            return ActiveStateEnum.forNumber(number);
          }
        };

  public final com.google.protobuf.Descriptors.EnumValueDescriptor
      getValueDescriptor() {
    if (this == UNRECOGNIZED) {
      throw new java.lang.IllegalStateException(
          "Can't get the descriptor of an unrecognized enum value.");
    }
    return getDescriptor().getValues().get(ordinal());
  }
  public final com.google.protobuf.Descriptors.EnumDescriptor
      getDescriptorForType() {
    return getDescriptor();
  }
  public static final com.google.protobuf.Descriptors.EnumDescriptor
      getDescriptor() {
    return com.common.CommonProto.getDescriptor().getEnumTypes().get(0);
  }

  private static final ActiveStateEnum[] VALUES = values();

  public static ActiveStateEnum valueOf(
      com.google.protobuf.Descriptors.EnumValueDescriptor desc) {
    if (desc.getType() != getDescriptor()) {
      throw new java.lang.IllegalArgumentException(
        "EnumValueDescriptor is not for this type.");
    }
    if (desc.getIndex() == -1) {
      return UNRECOGNIZED;
    }
    return VALUES[desc.getIndex()];
  }

  private final int value;

  private ActiveStateEnum(int value) {
    this.value = value;
  }

  // @@protoc_insertion_point(enum_scope:common.ActiveStateEnum)
}

