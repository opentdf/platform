// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: policy/subjectmapping/subject_mapping.proto

// Protobuf Java Version: 3.25.3
package io.opentdf.platform.subjectmapping;

/**
 * <pre>
 * buflint ENUM_VALUE_PREFIX: to make sure that C++ scoping rules aren't violated when users add new enum values to an enum in a given package
 * </pre>
 *
 * Protobuf enum {@code subjectmapping.SubjectMappingOperatorEnum}
 */
public enum SubjectMappingOperatorEnum
    implements com.google.protobuf.ProtocolMessageEnum {
  /**
   * <code>SUBJECT_MAPPING_OPERATOR_ENUM_UNSPECIFIED = 0;</code>
   */
  SUBJECT_MAPPING_OPERATOR_ENUM_UNSPECIFIED(0),
  /**
   * <code>SUBJECT_MAPPING_OPERATOR_ENUM_IN = 1;</code>
   */
  SUBJECT_MAPPING_OPERATOR_ENUM_IN(1),
  /**
   * <code>SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN = 2;</code>
   */
  SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN(2),
  UNRECOGNIZED(-1),
  ;

  /**
   * <code>SUBJECT_MAPPING_OPERATOR_ENUM_UNSPECIFIED = 0;</code>
   */
  public static final int SUBJECT_MAPPING_OPERATOR_ENUM_UNSPECIFIED_VALUE = 0;
  /**
   * <code>SUBJECT_MAPPING_OPERATOR_ENUM_IN = 1;</code>
   */
  public static final int SUBJECT_MAPPING_OPERATOR_ENUM_IN_VALUE = 1;
  /**
   * <code>SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN = 2;</code>
   */
  public static final int SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN_VALUE = 2;


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
  public static SubjectMappingOperatorEnum valueOf(int value) {
    return forNumber(value);
  }

  /**
   * @param value The numeric wire value of the corresponding enum entry.
   * @return The enum associated with the given numeric wire value.
   */
  public static SubjectMappingOperatorEnum forNumber(int value) {
    switch (value) {
      case 0: return SUBJECT_MAPPING_OPERATOR_ENUM_UNSPECIFIED;
      case 1: return SUBJECT_MAPPING_OPERATOR_ENUM_IN;
      case 2: return SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN;
      default: return null;
    }
  }

  public static com.google.protobuf.Internal.EnumLiteMap<SubjectMappingOperatorEnum>
      internalGetValueMap() {
    return internalValueMap;
  }
  private static final com.google.protobuf.Internal.EnumLiteMap<
      SubjectMappingOperatorEnum> internalValueMap =
        new com.google.protobuf.Internal.EnumLiteMap<SubjectMappingOperatorEnum>() {
          public SubjectMappingOperatorEnum findValueByNumber(int number) {
            return SubjectMappingOperatorEnum.forNumber(number);
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
    return io.opentdf.platform.subjectmapping.SubjectMappingProto.getDescriptor().getEnumTypes().get(0);
  }

  private static final SubjectMappingOperatorEnum[] VALUES = values();

  public static SubjectMappingOperatorEnum valueOf(
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

  private SubjectMappingOperatorEnum(int value) {
    this.value = value;
  }

  // @@protoc_insertion_point(enum_scope:subjectmapping.SubjectMappingOperatorEnum)
}

