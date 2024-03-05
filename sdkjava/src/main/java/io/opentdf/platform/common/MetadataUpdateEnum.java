// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: common/common.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.common;

/**
 * Protobuf enum {@code common.MetadataUpdateEnum}
 */
public enum MetadataUpdateEnum
    implements com.google.protobuf.ProtocolMessageEnum {
  /**
   * <pre>
   * unspecified update type
   * </pre>
   *
   * <code>METADATA_UPDATE_ENUM_UNSPECIFIED = 0;</code>
   */
  METADATA_UPDATE_ENUM_UNSPECIFIED(0),
  /**
   * <pre>
   * only update the fields that are set
   * </pre>
   *
   * <code>METADATA_UPDATE_ENUM_EXTEND = 1;</code>
   */
  METADATA_UPDATE_ENUM_EXTEND(1),
  /**
   * <pre>
   * replace the entire metadata with the new metadata
   * </pre>
   *
   * <code>METADATA_UPDATE_ENUM_REPLACE = 2;</code>
   */
  METADATA_UPDATE_ENUM_REPLACE(2),
  UNRECOGNIZED(-1),
  ;

  /**
   * <pre>
   * unspecified update type
   * </pre>
   *
   * <code>METADATA_UPDATE_ENUM_UNSPECIFIED = 0;</code>
   */
  public static final int METADATA_UPDATE_ENUM_UNSPECIFIED_VALUE = 0;
  /**
   * <pre>
   * only update the fields that are set
   * </pre>
   *
   * <code>METADATA_UPDATE_ENUM_EXTEND = 1;</code>
   */
  public static final int METADATA_UPDATE_ENUM_EXTEND_VALUE = 1;
  /**
   * <pre>
   * replace the entire metadata with the new metadata
   * </pre>
   *
   * <code>METADATA_UPDATE_ENUM_REPLACE = 2;</code>
   */
  public static final int METADATA_UPDATE_ENUM_REPLACE_VALUE = 2;


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
  public static MetadataUpdateEnum valueOf(int value) {
    return forNumber(value);
  }

  /**
   * @param value The numeric wire value of the corresponding enum entry.
   * @return The enum associated with the given numeric wire value.
   */
  public static MetadataUpdateEnum forNumber(int value) {
    switch (value) {
      case 0: return METADATA_UPDATE_ENUM_UNSPECIFIED;
      case 1: return METADATA_UPDATE_ENUM_EXTEND;
      case 2: return METADATA_UPDATE_ENUM_REPLACE;
      default: return null;
    }
  }

  public static com.google.protobuf.Internal.EnumLiteMap<MetadataUpdateEnum>
      internalGetValueMap() {
    return internalValueMap;
  }
  private static final com.google.protobuf.Internal.EnumLiteMap<
      MetadataUpdateEnum> internalValueMap =
        new com.google.protobuf.Internal.EnumLiteMap<MetadataUpdateEnum>() {
          public MetadataUpdateEnum findValueByNumber(int number) {
            return MetadataUpdateEnum.forNumber(number);
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
    return io.opentdf.platform.common.CommonProto.getDescriptor().getEnumTypes().get(0);
  }

  private static final MetadataUpdateEnum[] VALUES = values();

  public static MetadataUpdateEnum valueOf(
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

  private MetadataUpdateEnum(int value) {
    this.value = value;
  }

  // @@protoc_insertion_point(enum_scope:common.MetadataUpdateEnum)
}

