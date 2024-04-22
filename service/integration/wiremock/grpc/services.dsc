
�y
google/api/http.proto
google.api"y
Http*
rules (2.google.api.HttpRuleRrulesE
fully_decode_reserved_expansion (RfullyDecodeReservedExpansion"�
HttpRule
selector (	Rselector
get (	H Rget
put (	H Rput
post (	H Rpost
delete (	H Rdelete
patch (	H Rpatch7
custom (2.google.api.CustomHttpPatternH Rcustom
body (	Rbody#
response_body (	RresponseBodyE
additional_bindings (2.google.api.HttpRuleRadditionalBindingsB	
pattern";
CustomHttpPattern
kind (	Rkind
path (	RpathBj
com.google.apiB	HttpProtoPZAgoogle.golang.org/genproto/googleapis/api/annotations;annotations��GAPIJ�s
 �
�
 2� Copyright 2023 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.


 

 
	
 

 X
	
 X

 "
	

 "

 *
	
 *

 '
	
 '

 "
	
$ "
�
  )� Defines the HTTP configuration for an API service. It contains a list of
 [HttpRule][google.api.HttpRule], each specifying the mapping of an RPC method
 to one or more HTTP REST API methods.



 
�
   � A list of HTTP configuration rules that apply to individual API methods.

 **NOTE:** All service configuration rules follow "last one wins" order.


   


   

   

   
�
 (+� When set to true, URL path parameters will be fully URI-decoded except in
 cases of single segment matches in reserved expansion, where "%2F" will be
 left encoded.

 The default behavior is to not decode RFC 6570 reserved characters in multi
 segment matches.


 (

 (&

 ()*
�S
� ��S # gRPC Transcoding

 gRPC Transcoding is a feature for mapping between a gRPC method and one or
 more HTTP REST endpoints. It allows developers to build a single API service
 that supports both gRPC APIs and REST APIs. Many systems, including [Google
 APIs](https://github.com/googleapis/googleapis),
 [Cloud Endpoints](https://cloud.google.com/endpoints), [gRPC
 Gateway](https://github.com/grpc-ecosystem/grpc-gateway),
 and [Envoy](https://github.com/envoyproxy/envoy) proxy support this feature
 and use it for large scale production services.

 `HttpRule` defines the schema of the gRPC/REST mapping. The mapping specifies
 how different portions of the gRPC request message are mapped to the URL
 path, URL query parameters, and HTTP request body. It also controls how the
 gRPC response message is mapped to the HTTP response body. `HttpRule` is
 typically specified as an `google.api.http` annotation on the gRPC method.

 Each mapping specifies a URL path template and an HTTP method. The path
 template may refer to one or more fields in the gRPC request message, as long
 as each field is a non-repeated field with a primitive (non-message) type.
 The path template controls how fields of the request message are mapped to
 the URL path.

 Example:

     service Messaging {
       rpc GetMessage(GetMessageRequest) returns (Message) {
         option (google.api.http) = {
             get: "/v1/{name=messages/*}"
         };
       }
     }
     message GetMessageRequest {
       string name = 1; // Mapped to URL path.
     }
     message Message {
       string text = 1; // The resource content.
     }

 This enables an HTTP REST to gRPC mapping as below:

 HTTP | gRPC
 -----|-----
 `GET /v1/messages/123456`  | `GetMessage(name: "messages/123456")`

 Any fields in the request message which are not bound by the path template
 automatically become HTTP query parameters if there is no HTTP request body.
 For example:

     service Messaging {
       rpc GetMessage(GetMessageRequest) returns (Message) {
         option (google.api.http) = {
             get:"/v1/messages/{message_id}"
         };
       }
     }
     message GetMessageRequest {
       message SubMessage {
         string subfield = 1;
       }
       string message_id = 1; // Mapped to URL path.
       int64 revision = 2;    // Mapped to URL query parameter `revision`.
       SubMessage sub = 3;    // Mapped to URL query parameter `sub.subfield`.
     }

 This enables a HTTP JSON to RPC mapping as below:

 HTTP | gRPC
 -----|-----
 `GET /v1/messages/123456?revision=2&sub.subfield=foo` |
 `GetMessage(message_id: "123456" revision: 2 sub: SubMessage(subfield:
 "foo"))`

 Note that fields which are mapped to URL query parameters must have a
 primitive type or a repeated primitive type or a non-repeated message type.
 In the case of a repeated type, the parameter can be repeated in the URL
 as `...?param=A&param=B`. In the case of a message type, each field of the
 message is mapped to a separate parameter, such as
 `...?foo.a=A&foo.b=B&foo.c=C`.

 For HTTP methods that allow a request body, the `body` field
 specifies the mapping. Consider a REST update method on the
 message resource collection:

     service Messaging {
       rpc UpdateMessage(UpdateMessageRequest) returns (Message) {
         option (google.api.http) = {
           patch: "/v1/messages/{message_id}"
           body: "message"
         };
       }
     }
     message UpdateMessageRequest {
       string message_id = 1; // mapped to the URL
       Message message = 2;   // mapped to the body
     }

 The following HTTP JSON to RPC mapping is enabled, where the
 representation of the JSON in the request body is determined by
 protos JSON encoding:

 HTTP | gRPC
 -----|-----
 `PATCH /v1/messages/123456 { "text": "Hi!" }` | `UpdateMessage(message_id:
 "123456" message { text: "Hi!" })`

 The special name `*` can be used in the body mapping to define that
 every field not bound by the path template should be mapped to the
 request body.  This enables the following alternative definition of
 the update method:

     service Messaging {
       rpc UpdateMessage(Message) returns (Message) {
         option (google.api.http) = {
           patch: "/v1/messages/{message_id}"
           body: "*"
         };
       }
     }
     message Message {
       string message_id = 1;
       string text = 2;
     }


 The following HTTP JSON to RPC mapping is enabled:

 HTTP | gRPC
 -----|-----
 `PATCH /v1/messages/123456 { "text": "Hi!" }` | `UpdateMessage(message_id:
 "123456" text: "Hi!")`

 Note that when using `*` in the body mapping, it is not possible to
 have HTTP parameters, as all fields not bound by the path end in
 the body. This makes this option more rarely used in practice when
 defining REST APIs. The common usage of `*` is in custom methods
 which don't use the URL at all for transferring data.

 It is possible to define multiple HTTP methods for one RPC by using
 the `additional_bindings` option. Example:

     service Messaging {
       rpc GetMessage(GetMessageRequest) returns (Message) {
         option (google.api.http) = {
           get: "/v1/messages/{message_id}"
           additional_bindings {
             get: "/v1/users/{user_id}/messages/{message_id}"
           }
         };
       }
     }
     message GetMessageRequest {
       string message_id = 1;
       string user_id = 2;
     }

 This enables the following two alternative HTTP JSON to RPC mappings:

 HTTP | gRPC
 -----|-----
 `GET /v1/messages/123456` | `GetMessage(message_id: "123456")`
 `GET /v1/users/me/messages/123456` | `GetMessage(user_id: "me" message_id:
 "123456")`

 ## Rules for HTTP mapping

 1. Leaf request fields (recursive expansion nested messages in the request
    message) are classified into three categories:
    - Fields referred by the path template. They are passed via the URL path.
    - Fields referred by the [HttpRule.body][google.api.HttpRule.body]. They
    are passed via the HTTP
      request body.
    - All other fields are passed via the URL query parameters, and the
      parameter name is the field path in the request message. A repeated
      field can be represented as multiple query parameters under the same
      name.
  2. If [HttpRule.body][google.api.HttpRule.body] is "*", there is no URL
  query parameter, all fields
     are passed via URL path and HTTP request body.
  3. If [HttpRule.body][google.api.HttpRule.body] is omitted, there is no HTTP
  request body, all
     fields are passed via URL path and URL query parameters.

 ### Path template syntax

     Template = "/" Segments [ Verb ] ;
     Segments = Segment { "/" Segment } ;
     Segment  = "*" | "**" | LITERAL | Variable ;
     Variable = "{" FieldPath [ "=" Segments ] "}" ;
     FieldPath = IDENT { "." IDENT } ;
     Verb     = ":" LITERAL ;

 The syntax `*` matches a single URL path segment. The syntax `**` matches
 zero or more URL path segments, which must be the last part of the URL path
 except the `Verb`.

 The syntax `Variable` matches part of the URL path as specified by its
 template. A variable template must not contain other variables. If a variable
 matches a single path segment, its template may be omitted, e.g. `{var}`
 is equivalent to `{var=*}`.

 The syntax `LITERAL` matches literal text in the URL path. If the `LITERAL`
 contains any reserved character, such characters should be percent-encoded
 before the matching.

 If a variable contains exactly one path segment, such as `"{var}"` or
 `"{var=*}"`, when such a variable is expanded into a URL path on the client
 side, all characters except `[-_.~0-9a-zA-Z]` are percent-encoded. The
 server side does the reverse decoding. Such variables show up in the
 [Discovery
 Document](https://developers.google.com/discovery/v1/reference/apis) as
 `{var}`.

 If a variable contains multiple path segments, such as `"{var=foo/*}"`
 or `"{var=**}"`, when such a variable is expanded into a URL path on the
 client side, all characters except `[-_.~/0-9a-zA-Z]` are percent-encoded.
 The server side does the reverse decoding, except "%2F" and "%2f" are left
 unchanged. Such variables show up in the
 [Discovery
 Document](https://developers.google.com/discovery/v1/reference/apis) as
 `{+var}`.

 ## Using gRPC API Service Configuration

 gRPC API Service Configuration (service config) is a configuration language
 for configuring a gRPC service to become a user-facing product. The
 service config is simply the YAML representation of the `google.api.Service`
 proto message.

 As an alternative to annotating your proto file, you can configure gRPC
 transcoding in your service config YAML files. You do this by specifying a
 `HttpRule` that maps the gRPC method to a REST endpoint, achieving the same
 effect as the proto annotation. This can be particularly useful if you
 have a proto that is reused in multiple services. Note that any transcoding
 specified in the service config will override any matching transcoding
 configuration in the proto.

 Example:

     http:
       rules:
         # Selects a gRPC method and applies HttpRule to it.
         - selector: example.v1.Messaging.GetMessage
           get: /v1/messages/{message_id}/{sub.subfield}

 ## Special notes

 When gRPC Transcoding is used to map a gRPC to JSON REST endpoints, the
 proto to JSON conversion must follow the [proto3
 specification](https://developers.google.com/protocol-buffers/docs/proto3#json).

 While the single segment variable follows the semantics of
 [RFC 6570](https://tools.ietf.org/html/rfc6570) Section 3.2.2 Simple String
 Expansion, the multi segment variable **does not** follow RFC 6570 Section
 3.2.3 Reserved Expansion. The reason is that the Reserved Expansion
 does not expand special characters like `?` and `#`, which would lead
 to invalid URLs. As the result, gRPC Transcoding uses a custom encoding
 for multi segment variables.

 The path variables **must not** refer to any repeated or mapped field,
 because client libraries are not capable of handling such variable expansion.

 The path variables **must not** capture the leading "/" character. The reason
 is that the most common use case "{var}" does not capture the leading "/"
 character. For consistency, all path variables must share the same behavior.

 Repeated message fields must not be mapped to URL query parameters, because
 no client library can support such complicated mapping.

 If an API needs to use a JSON array for request or response body, it can map
 the request or response body to a repeated field. However, some gRPC
 Transcoding implementations may not support this feature.


�
�
 �� Selects a method to which this rule applies.

 Refer to [selector][google.api.DocumentationRule.selector] for syntax
 details.


 �

 �	

 �
�
 ��� Determines the URL pattern is matched by this rules. This pattern can be
 used with any of the {get|put|post|delete|patch} methods. A custom method
 can be defined using the 'custom' field.


 �
\
�N Maps to HTTP GET. Used for listing and getting information about
 resources.


�


�

�
@
�2 Maps to HTTP PUT. Used for replacing a resource.


�


�

�
X
�J Maps to HTTP POST. Used for creating a resource or performing an action.


�


�

�
B
�4 Maps to HTTP DELETE. Used for deleting a resource.


�


�

�
A
�3 Maps to HTTP PATCH. Used for updating a resource.


�


�

�
�
�!� The custom pattern is used for specifying an HTTP method that is not
 included in the `pattern` field, such as HEAD, or "*" to leave the
 HTTP method unspecified for this rule. The wild-card rule is useful
 for services that provide content to Web (HTML) clients.


�

�

� 
�
�� The name of the request field whose value is mapped to the HTTP request
 body, or `*` for mapping all request fields not captured by the path
 pattern to the HTTP body, or omitted for not having any HTTP request body.

 NOTE: the referred field must be present at the top-level of the request
 message type.


�

�	

�
�
�� Optional. The name of the response field whose value is mapped to the HTTP
 response body. When omitted, the entire response message will be used
 as the HTTP response body.

 NOTE: The referred field must be present at the top-level of the response
 message type.


�

�	

�
�
	�-� Additional HTTP bindings for the selector. Nested bindings must
 not contain an `additional_bindings` field themselves (that is,
 the nesting may only be one level deep).


	�


	�

	�'

	�*,
G
� �9 A custom pattern is used for defining custom HTTP verb.


�
2
 �$ The name of this custom HTTP verb.


 �

 �	

 �
5
�' The path matched by this custom verb.


�

�	

�bproto3��MG
#
	buf.build
googleapis
googleapis a86849a25cc04f4dbe9b15ddddfbc488 
��
 google/protobuf/descriptor.protogoogle.protobuf"M
FileDescriptorSet8
file (2$.google.protobuf.FileDescriptorProtoRfile"�
FileDescriptorProto
name (	Rname
package (	Rpackage

dependency (	R
dependency+
public_dependency
 (RpublicDependency'
weak_dependency (RweakDependencyC
message_type (2 .google.protobuf.DescriptorProtoRmessageTypeA
	enum_type (2$.google.protobuf.EnumDescriptorProtoRenumTypeA
service (2'.google.protobuf.ServiceDescriptorProtoRserviceC
	extension (2%.google.protobuf.FieldDescriptorProtoR	extension6
options (2.google.protobuf.FileOptionsRoptionsI
source_code_info	 (2.google.protobuf.SourceCodeInfoRsourceCodeInfo
syntax (	Rsyntax2
edition (2.google.protobuf.EditionRedition"�
DescriptorProto
name (	Rname;
field (2%.google.protobuf.FieldDescriptorProtoRfieldC
	extension (2%.google.protobuf.FieldDescriptorProtoR	extensionA
nested_type (2 .google.protobuf.DescriptorProtoR
nestedTypeA
	enum_type (2$.google.protobuf.EnumDescriptorProtoRenumTypeX
extension_range (2/.google.protobuf.DescriptorProto.ExtensionRangeRextensionRangeD

oneof_decl (2%.google.protobuf.OneofDescriptorProtoR	oneofDecl9
options (2.google.protobuf.MessageOptionsRoptionsU
reserved_range	 (2..google.protobuf.DescriptorProto.ReservedRangeRreservedRange#
reserved_name
 (	RreservedNamez
ExtensionRange
start (Rstart
end (Rend@
options (2&.google.protobuf.ExtensionRangeOptionsRoptions7
ReservedRange
start (Rstart
end (Rend"�
ExtensionRangeOptionsX
uninterpreted_option� (2$.google.protobuf.UninterpretedOptionRuninterpretedOptionY
declaration (22.google.protobuf.ExtensionRangeOptions.DeclarationB�Rdeclaration7
features2 (2.google.protobuf.FeatureSetRfeaturesh
verification (28.google.protobuf.ExtensionRangeOptions.VerificationState:
UNVERIFIEDRverification�
Declaration
number (Rnumber
	full_name (	RfullName
type (	Rtype
reserved (Rreserved
repeated (RrepeatedJ"4
VerificationState
DECLARATION 

UNVERIFIED*	�����"�
FieldDescriptorProto
name (	Rname
number (RnumberA
label (2+.google.protobuf.FieldDescriptorProto.LabelRlabel>
type (2*.google.protobuf.FieldDescriptorProto.TypeRtype
	type_name (	RtypeName
extendee (	Rextendee#
default_value (	RdefaultValue
oneof_index	 (R
oneofIndex
	json_name
 (	RjsonName7
options (2.google.protobuf.FieldOptionsRoptions'
proto3_optional (Rproto3Optional"�
Type
TYPE_DOUBLE

TYPE_FLOAT

TYPE_INT64
TYPE_UINT64

TYPE_INT32
TYPE_FIXED64
TYPE_FIXED32
	TYPE_BOOL
TYPE_STRING	

TYPE_GROUP

TYPE_MESSAGE

TYPE_BYTES
TYPE_UINT32
	TYPE_ENUM
TYPE_SFIXED32
TYPE_SFIXED64
TYPE_SINT32
TYPE_SINT64"C
Label
LABEL_OPTIONAL
LABEL_REPEATED
LABEL_REQUIRED"c
OneofDescriptorProto
name (	Rname7
options (2.google.protobuf.OneofOptionsRoptions"�
EnumDescriptorProto
name (	Rname?
value (2).google.protobuf.EnumValueDescriptorProtoRvalue6
options (2.google.protobuf.EnumOptionsRoptions]
reserved_range (26.google.protobuf.EnumDescriptorProto.EnumReservedRangeRreservedRange#
reserved_name (	RreservedName;
EnumReservedRange
start (Rstart
end (Rend"�
EnumValueDescriptorProto
name (	Rname
number (Rnumber;
options (2!.google.protobuf.EnumValueOptionsRoptions"�
ServiceDescriptorProto
name (	Rname>
method (2&.google.protobuf.MethodDescriptorProtoRmethod9
options (2.google.protobuf.ServiceOptionsRoptions"�
MethodDescriptorProto
name (	Rname

input_type (	R	inputType
output_type (	R
outputType8
options (2.google.protobuf.MethodOptionsRoptions0
client_streaming (:falseRclientStreaming0
server_streaming (:falseRserverStreaming"�	
FileOptions!
java_package (	RjavaPackage0
java_outer_classname (	RjavaOuterClassname5
java_multiple_files
 (:falseRjavaMultipleFilesD
java_generate_equals_and_hash (BRjavaGenerateEqualsAndHash:
java_string_check_utf8 (:falseRjavaStringCheckUtf8S
optimize_for	 (2).google.protobuf.FileOptions.OptimizeMode:SPEEDRoptimizeFor

go_package (	R	goPackage5
cc_generic_services (:falseRccGenericServices9
java_generic_services (:falseRjavaGenericServices5
py_generic_services (:falseRpyGenericServices7
php_generic_services* (:falseRphpGenericServices%

deprecated (:falseR
deprecated.
cc_enable_arenas (:trueRccEnableArenas*
objc_class_prefix$ (	RobjcClassPrefix)
csharp_namespace% (	RcsharpNamespace!
swift_prefix' (	RswiftPrefix(
php_class_prefix( (	RphpClassPrefix#
php_namespace) (	RphpNamespace4
php_metadata_namespace, (	RphpMetadataNamespace!
ruby_package- (	RrubyPackage7
features2 (2.google.protobuf.FeatureSetRfeaturesX
uninterpreted_option� (2$.google.protobuf.UninterpretedOptionRuninterpretedOption":
OptimizeMode	
SPEED
	CODE_SIZE
LITE_RUNTIME*	�����J&'"�
MessageOptions<
message_set_wire_format (:falseRmessageSetWireFormatL
no_standard_descriptor_accessor (:falseRnoStandardDescriptorAccessor%

deprecated (:falseR
deprecated
	map_entry (RmapEntryV
&deprecated_legacy_json_field_conflicts (BR"deprecatedLegacyJsonFieldConflicts7
features (2.google.protobuf.FeatureSetRfeaturesX
uninterpreted_option� (2$.google.protobuf.UninterpretedOptionRuninterpretedOption*	�����JJJJ	J	
"�

FieldOptionsA
ctype (2#.google.protobuf.FieldOptions.CType:STRINGRctype
packed (RpackedG
jstype (2$.google.protobuf.FieldOptions.JSType:	JS_NORMALRjstype
lazy (:falseRlazy.
unverified_lazy (:falseRunverifiedLazy%

deprecated (:falseR
deprecated
weak
 (:falseRweak(
debug_redact (:falseRdebugRedactK
	retention (2-.google.protobuf.FieldOptions.OptionRetentionR	retentionH
targets (2..google.protobuf.FieldOptions.OptionTargetTypeRtargetsW
edition_defaults (2,.google.protobuf.FieldOptions.EditionDefaultReditionDefaults7
features (2.google.protobuf.FeatureSetRfeaturesX
uninterpreted_option� (2$.google.protobuf.UninterpretedOptionRuninterpretedOptionZ
EditionDefault2
edition (2.google.protobuf.EditionRedition
value (	Rvalue"/
CType

STRING 
CORD
STRING_PIECE"5
JSType
	JS_NORMAL 
	JS_STRING
	JS_NUMBER"U
OptionRetention
RETENTION_UNKNOWN 
RETENTION_RUNTIME
RETENTION_SOURCE"�
OptionTargetType
TARGET_TYPE_UNKNOWN 
TARGET_TYPE_FILE
TARGET_TYPE_EXTENSION_RANGE
TARGET_TYPE_MESSAGE
TARGET_TYPE_FIELD
TARGET_TYPE_ONEOF
TARGET_TYPE_ENUM
TARGET_TYPE_ENUM_ENTRY
TARGET_TYPE_SERVICE
TARGET_TYPE_METHOD	*	�����JJ"�
OneofOptions7
features (2.google.protobuf.FeatureSetRfeaturesX
uninterpreted_option� (2$.google.protobuf.UninterpretedOptionRuninterpretedOption*	�����"�
EnumOptions
allow_alias (R
allowAlias%

deprecated (:falseR
deprecatedV
&deprecated_legacy_json_field_conflicts (BR"deprecatedLegacyJsonFieldConflicts7
features (2.google.protobuf.FeatureSetRfeaturesX
uninterpreted_option� (2$.google.protobuf.UninterpretedOptionRuninterpretedOption*	�����J"�
EnumValueOptions%

deprecated (:falseR
deprecated7
features (2.google.protobuf.FeatureSetRfeatures(
debug_redact (:falseRdebugRedactX
uninterpreted_option� (2$.google.protobuf.UninterpretedOptionRuninterpretedOption*	�����"�
ServiceOptions7
features" (2.google.protobuf.FeatureSetRfeatures%

deprecated! (:falseR
deprecatedX
uninterpreted_option� (2$.google.protobuf.UninterpretedOptionRuninterpretedOption*	�����"�
MethodOptions%

deprecated! (:falseR
deprecatedq
idempotency_level" (2/.google.protobuf.MethodOptions.IdempotencyLevel:IDEMPOTENCY_UNKNOWNRidempotencyLevel7
features# (2.google.protobuf.FeatureSetRfeaturesX
uninterpreted_option� (2$.google.protobuf.UninterpretedOptionRuninterpretedOption"P
IdempotencyLevel
IDEMPOTENCY_UNKNOWN 
NO_SIDE_EFFECTS

IDEMPOTENT*	�����"�
UninterpretedOptionA
name (2-.google.protobuf.UninterpretedOption.NamePartRname)
identifier_value (	RidentifierValue,
positive_int_value (RpositiveIntValue,
negative_int_value (RnegativeIntValue!
double_value (RdoubleValue!
string_value (RstringValue'
aggregate_value (	RaggregateValueJ
NamePart
	name_part (	RnamePart!
is_extension (RisExtension"�	

FeatureSet�
field_presence (2).google.protobuf.FeatureSet.FieldPresenceB9����EXPLICIT��IMPLICIT��EXPLICIT�RfieldPresencef
	enum_type (2$.google.protobuf.FeatureSet.EnumTypeB#����CLOSED��	OPEN�RenumType�
repeated_field_encoding (21.google.protobuf.FeatureSet.RepeatedFieldEncodingB'����EXPANDED��PACKED�RrepeatedFieldEncodingx
utf8_validation (2*.google.protobuf.FeatureSet.Utf8ValidationB#����	NONE��VERIFY�Rutf8Validationx
message_encoding (2+.google.protobuf.FeatureSet.MessageEncodingB ����LENGTH_PREFIXED�RmessageEncoding|
json_format (2&.google.protobuf.FeatureSet.JsonFormatB3�����LEGACY_BEST_EFFORT��
ALLOW�R
jsonFormat"\
FieldPresence
FIELD_PRESENCE_UNKNOWN 
EXPLICIT
IMPLICIT
LEGACY_REQUIRED"7
EnumType
ENUM_TYPE_UNKNOWN 
OPEN

CLOSED"V
RepeatedFieldEncoding#
REPEATED_FIELD_ENCODING_UNKNOWN 

PACKED
EXPANDED"C
Utf8Validation
UTF8_VALIDATION_UNKNOWN 
NONE

VERIFY"S
MessageEncoding
MESSAGE_ENCODING_UNKNOWN 
LENGTH_PREFIXED
	DELIMITED"H

JsonFormat
JSON_FORMAT_UNKNOWN 	
ALLOW
LEGACY_BEST_EFFORT*��*��*�N�NJ��"�
FeatureSetDefaultsX
defaults (2<.google.protobuf.FeatureSetDefaults.FeatureSetEditionDefaultRdefaultsA
minimum_edition (2.google.protobuf.EditionRminimumEditionA
maximum_edition (2.google.protobuf.EditionRmaximumEdition�
FeatureSetEditionDefault2
edition (2.google.protobuf.EditionRedition7
features (2.google.protobuf.FeatureSetRfeatures"�
SourceCodeInfoD
location (2(.google.protobuf.SourceCodeInfo.LocationRlocation�
Location
path (BRpath
span (BRspan)
leading_comments (	RleadingComments+
trailing_comments (	RtrailingComments:
leading_detached_comments (	RleadingDetachedComments"�
GeneratedCodeInfoM

annotation (2-.google.protobuf.GeneratedCodeInfo.AnnotationR
annotation�

Annotation
path (BRpath
source_file (	R
sourceFile
begin (Rbegin
end (RendR
semantic (26.google.protobuf.GeneratedCodeInfo.Annotation.SemanticRsemantic"(
Semantic
NONE 
SET	
ALIAS*�
Edition
EDITION_UNKNOWN 
EDITION_PROTO2�
EDITION_PROTO3�
EDITION_2023�
EDITION_1_TEST_ONLY
EDITION_2_TEST_ONLY
EDITION_99997_TEST_ONLY��
EDITION_99998_TEST_ONLY��
EDITION_99999_TEST_ONLY��B~
com.google.protobufBDescriptorProtosHZ-google.golang.org/protobuf/types/descriptorpb��GPB�Google.Protobuf.ReflectionJ��
& �	
�
& 2� Protocol Buffers - Google's data interchange format
 Copyright 2008 Google Inc.  All rights reserved.
 https://developers.google.com/protocol-buffers/

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are
 met:

     * Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above
 copyright notice, this list of conditions and the following disclaimer
 in the documentation and/or other materials provided with the
 distribution.
     * Neither the name of Google Inc. nor the names of its
 contributors may be used to endorse or promote products derived from
 this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
2� Author: kenton@google.com (Kenton Varda)
  Based on original Protocol Buffers design by
  Sanjay Ghemawat, Jeff Dean, and others.

 The messages in this file describe the definitions found in .proto files.
 A valid .proto file can be translated directly to a FileDescriptorProto
 without any other information (e.g. without reading its imports).


( 

* D
	
* D

+ ,
	
+ ,

, 1
	
, 1

- 7
	
%- 7

. !
	
$. !

/ 
	
/ 

3 

	3 t descriptor.proto must be optimized for speed because reflection-based
 algorithms don't work during bootstrapping.

j
 7 9^ The protocol compiler can output a FileDescriptorSet containing the .proto
 files it parses.



 7

  8(

  8


  8

  8#

  8&'
-
 < S! The full set of known editions.



 <
:
  >- A placeholder for an unknown edition value.


  >

  >
�
 D� Legacy syntax "editions".  These pre-date editions, but behave much like
 distinct editions.  These can't be used to specify the edition of proto
 files, but feature definitions must supply proto2/proto3 defaults for
 backwards compatibility.


 D

 D

 E

 E

 E
�
 J� Editions that have been released.  The specific values are arbitrary and
 should not be depended on, but they will always be time-ordered for easy
 comparison.


 J

 J
}
 Np Placeholder editions for testing feature resolution.  These should not be
 used or relyed on outside of tests.


 N

 N

 O

 O

 O

 P"

 P

 P!

 Q"

 Q

 Q!

 R"

 R

 R!
/
V x# Describes a complete .proto file.



V
9
 W", file name, relative to root of source tree


 W


 W

 W

 W
*
X" e.g. "foo", "foo.bar", etc.


X


X

X

X
4
[!' Names of files imported by this file.


[


[

[

[ 
Q
](D Indexes of the public imported files in the dependency list above.


]


]

]"

]%'
z
`&m Indexes of the weak imported files in the dependency list.
 For Google-internal migration only. Do not use.


`


`

` 

`#%
6
c,) All top-level definitions in this file.


c


c

c'

c*+

d-

d


d

d(

d+,

e.

e


e!

e")

e,-

f.

f


f

f )

f,-

	h#

	h


	h

	h

	h!"
�

n/� This field contains optional information about the original source code.
 You may safely remove this entire field without harming runtime
 functionality of the descriptors -- the information is needed only by
 development tools.



n



n


n*


n-.
�
t� The syntax of the proto file.
 The supported values are "proto2", "proto3", and "editions".

 If `edition` is present, this value must be "editions".


t


t

t

t
-
w   The edition of the proto file.


w


w

w

w
(
{ � Describes a message type.



{

 |

 |


 |

 |

 |

~*

~


~

~ %

~()

.






 )

,-

�+

�


�

�&

�)*

�-

�


�

�(

�+,

 ��

 �


  �" Inclusive.


  �

  �

  �

  �

 �" Exclusive.


 �

 �

 �

 �

 �/

 �

 �"

 �#*

 �-.

�.

�


�

�)

�,-

�/

�


�

� *

�-.

�&

�


�

�!

�$%
�
��� Range of reserved tag numbers. Reserved tag numbers may not be used by
 fields or extension ranges in the same message. Reserved ranges may
 not overlap.


�


 �" Inclusive.


 �

 �

 �

 �

�" Exclusive.


�

�

�

�

�,

�


�

�'

�*+
�
	�%u Reserved field names, which may not be used by fields in the same message.
 A given name may only be reserved once.


	�


	�

	�

	�"$

� �

�
O
 �:A The parser stores options it doesn't recognize here. See above.


 �


 �

 �3

 �69

 ��

 �

K
  �; The extension number declared within the extension range.


  �

  �

  �

  �
z
 �"j The fully-qualified name of the extension field. There must be a leading
 dot in front of the full name.


 �

 �

 �

 � !
�
 �� The fully-qualified type name of the extension field. Unlike
 Metadata.type, Declaration.type must have a leading dot for messages
 and enums.


 �

 �

 �

 �
�
 �� If true, indicates that the number is reserved in the extension range,
 and any extension field with the number will fail to compile. Set this
 when a declared extension field is deleted.


 �

 �

 �

 �
�
 �z If true, indicates that the extension must be defined as repeated.
 Otherwise the extension must be defined as optional.


 �

 �

 �

 �
$
 	�" removed is_repeated


 	 �

 	 �

 	 �
�
�F� For external users: DO NOT USE. We are in the process of open sourcing
 extension declaration and executing internal cleanups before it can be
 used externally.


�


�

�"

�%&

�'E

�(D
=
�$/ Any features defined in the specific edition.


�


�

�

�!#
@
 ��0 The verification state of the extension range.


 �
C
  �3 All the extensions of the range must be declared.


  �

  �

 �

 �

 �
�
�E~ The verification state of the range.
 TODO: flip the default to DECLARATION once all empty ranges
 are marked as UNVERIFIED.


�


�

�)

�,-

�.D

�/C
Z
�M Clients can define custom options in extensions of this message. See above.


 �

 �

 �
3
� �% Describes a field within a message.


�

 ��

 �
S
  �C 0 is reserved for errors.
 Order is weird for historical reasons.


  �

  �

 �

 �

 �
w
 �g Not ZigZag encoded.  Negative numbers take 10 bytes.  Use TYPE_SINT64 if
 negative values are likely.


 �

 �

 �

 �

 �
w
 �g Not ZigZag encoded.  Negative numbers take 10 bytes.  Use TYPE_SINT32 if
 negative values are likely.


 �

 �

 �

 �

 �

 �

 �

 �

 �

 �

 �

 �

 �

 �
�
 	�� Tag-delimited aggregate.
 Group type is deprecated and not supported after google.protobuf. However, Proto3
 implementations should still be able to parse the group wire format and
 treat group fields as unknown fields.  In Editions, the group wire format
 can be enabled via the `message_encoding` feature.


 	�

 	�
-
 
�" Length-delimited aggregate.


 
�

 
�
#
 � New in version 2.


 �

 �

 �

 �

 �

 �

 �

 �

 �

 �

 �

 �

 �

 �
'
 �" Uses ZigZag encoding.


 �

 �
'
 �" Uses ZigZag encoding.


 �

 �

��

�
*
 � 0 is reserved for errors


 �

 �

�

�

�
�
�� The required label is only allowed in google.protobuf.  In proto3 and Editions
 it's explicitly prohibited.  In Editions, the `field_presence` feature
 can be used to get this behavior.


�

�

 �

 �


 �

 �

 �

�

�


�

�

�

�

�


�

�

�
�
�� If type_name is set, this need not be set.  If both this and type_name
 are set, this must be one of TYPE_ENUM, TYPE_MESSAGE or TYPE_GROUP.


�


�

�

�
�
� � For message and enum types, this is the name of the type.  If the name
 starts with a '.', it is fully-qualified.  Otherwise, C++-like scoping
 rules are used to find the type (i.e. first the nested types within this
 message are searched, then within the parent, on up to the root
 namespace).


�


�

�

�
~
�p For extensions, this is the name of the type being extended.  It is
 resolved in the same manner as type_name.


�


�

�

�
�
�$� For numeric types, contains the original text representation of the value.
 For booleans, "true" or "false".
 For strings, contains the default text contents (not escaped in any way).
 For bytes, contains the C escaped value.  All bytes >= 128 are escaped.


�


�

�

�"#
�
�!v If set, gives the index of a oneof in the containing type's oneof_decl
 list.  This field is a member of that oneof.


�


�

�

� 
�
�!� JSON name of this field. The value is set by protocol compiler. If the
 user has set a "json_name" option on this field, that option's value
 will be used. Otherwise, it's deduced from the field's name by converting
 it to camelCase.


�


�

�

� 

	�$

	�


	�

	�

	�"#
�	

�%�	 If true, this is a proto3 "optional". When a proto3 field is optional, it
 tracks presence regardless of field type.

 When proto3_optional is true, this field must be belong to a oneof to
 signal to old proto3 clients that presence is tracked for this field. This
 oneof is known as a "synthetic" oneof, and this field must be its sole
 member (each proto3 optional field gets its own synthetic oneof). Synthetic
 oneofs exist in the descriptor only, and do not generate any API. Synthetic
 oneofs must be ordered after all "real" oneofs.

 For message fields, proto3_optional doesn't create any semantic change,
 since non-repeated message fields always track presence. However it still
 indicates the semantic detail of whether the user wrote "optional" or not.
 This can be useful for round-tripping the .proto file. For consistency we
 give message fields a synthetic oneof also, even though it is not required
 to track presence. This is especially important because the parser can't
 tell if a field is a message or an enum, so it must always create a
 synthetic oneof.

 Proto2 optional fields do not set this flag, because they already indicate
 optional with `LABEL_OPTIONAL`.



�



�


�


�"$
"
� � Describes a oneof.


�

 �

 �


 �

 �

 �

�$

�


�

�

�"#
'
� � Describes an enum type.


�

 �

 �


 �

 �

 �

�.

�


�#

�$)

�,-

�#

�


�

�

�!"
�
 ��� Range of reserved numeric values. Reserved values may not be used by
 entries in the same enum. Reserved ranges may not overlap.

 Note that this is distinct from DescriptorProto.ReservedRange in that it
 is inclusive such that it can appropriately represent the entire int32
 domain.


 �


  �" Inclusive.


  �

  �

  �

  �

 �" Inclusive.


 �

 �

 �

 �
�
�0� Range of reserved numeric values. Reserved numeric values may not be used
 by enum values in the same enum declaration. Reserved ranges may not
 overlap.


�


�

�+

�./
l
�$^ Reserved enum value names, which may not be reused. A given name may only
 be reserved once.


�


�

�

�"#
1
� �# Describes a value within an enum.


� 

 �

 �


 �

 �

 �

�

�


�

�

�

�(

�


�

�#

�&'
$
� � Describes a service.


�

 �

 �


 �

 �

 �

�,

�


� 

�!'

�*+

�&

�


�

�!

�$%
0
	� �" Describes a method of a service.


	�

	 �

	 �


	 �

	 �

	 �
�
	�!� Input and output type names.  These are resolved in the same way as
 FieldDescriptorProto.type_name, but must refer to a message type.


	�


	�

	�

	� 

	�"

	�


	�

	�

	� !

	�%

	�


	�

	� 

	�#$
E
	�77 Identifies if client streams multiple client messages


	�


	�

	� 

	�#$

	�%6

	�&5
E
	�77 Identifies if server streams multiple server messages


	�


	�

	� 

	�#$

	�%6

	�&5
�

� �2N ===================================================================
 Options
2� Each of the definitions above may have "options" attached.  These are
 just annotations which may cause code to be generated slightly differently
 or may contain hints for code that manipulates protocol messages.

 Clients may define custom options as extensions of the *Options messages.
 These extensions may not yet be known at parsing time, so the parser cannot
 store the values in them.  Instead it stores them in a field in the *Options
 message called uninterpreted_option. This field must have the same name
 across all *Options messages. We then use this field to populate the
 extensions when we build a descriptor, at which point all protos have been
 parsed and so all extensions are known.

 Extension numbers for custom options may be chosen as follows:
 * For options which will only be used within a single application or
   organization, or for experimental options, use field numbers 50000
   through 99999.  It is up to you to ensure that you do not use the
   same number for multiple options.
 * For options which will be published and used publicly by multiple
   independent entities, e-mail protobuf-global-extension-registry@google.com
   to reserve extension numbers. Simply provide your project name (e.g.
   Objective-C plugin) and your project website (if available) -- there's no
   need to explain how you intend to use them. Usually you only need one
   extension number. You can declare multiple options with only one extension
   number by putting them in a sub-message. See the Custom Options section of
   the docs for examples:
   https://developers.google.com/protocol-buffers/docs/proto#options
   If this turns out to be popular, a web service will be set up
   to automatically assign option numbers.



�
�

 �#� Sets the Java package where classes generated from this .proto will be
 placed.  By default, the proto package is used, but this is often
 inappropriate because proto packages do not normally start with backwards
 domain names.



 �



 �


 �


 �!"
�

�+� Controls the name of the wrapper Java class generated for the .proto file.
 That class will always contain the .proto file's getDescriptor() method as
 well as any top-level extensions defined in the .proto file.
 If java_multiple_files is disabled, then all the other classes from the
 .proto file will be nested inside the single wrapper outer class.



�



�


�&


�)*
�

�;� If enabled, then the Java code generator will generate a separate .java
 file for each top-level message, enum, and service defined in the .proto
 file.  Thus, these types will *not* be nested inside the wrapper class
 named by java_outer_classname.  However, the wrapper class will still be
 generated to contain the file's getDescriptor() method as well as any
 top-level extensions defined in the file.



�



�


�#


�&(


�):


�*9
)

�E This option does nothing.



�



�


�-


�02


�3D


�4C
�

�>� If set true, then the Java2 code generator will generate code that
 throws an exception whenever an attempt is made to assign a non-UTF-8
 byte sequence to a string field.
 Message reflection will do the same.
 However, an extension field still accepts non-UTF-8 byte sequences.
 This option has no effect on when used with the lite runtime.



�



�


�&


�)+


�,=


�-<
L

 ��< Generated classes can be optimized for speed or code size.



 �
D

  �"4 Generate complete code for parsing, serialization,



  �	


  �
G

 � etc.
"/ Use ReflectionOps to implement these methods.



 �


 �
G

 �"7 Generate code using MessageLite and the lite runtime.



 �


 �


�;


�



�


�$


�'(


�):


�*9
�

�"� Sets the Go package where structs generated from this .proto will be
 placed. If omitted, the Go package will be derived from the following:
   - The basename of the package import path, if provided.
   - Otherwise, the package statement in the .proto file, if present.
   - Otherwise, the basename of the .proto file, without extension.



�



�


�


�!
�

�;� Should generic services be generated in each language?  "Generic" services
 are not specific to any particular RPC system.  They are generated by the
 main code generators in each language (without additional plugins).
 Generic services were the only kind of service generation supported by
 early versions of google.protobuf.

 Generic services are now considered deprecated in favor of using plugins
 that generate code specific to your particular RPC system.  Therefore,
 these default to false.  Old code which depends on generic services should
 explicitly set them to true.



�



�


�#


�&(


�):


�*9


�=


�



�


�%


�(*


�+<


�,;


	�;


	�



	�


	�#


	�&(


	�):


	�*9



�<



�




�



�$



�')



�*;



�+:
�

�2� Is this file deprecated?
 Depending on the target platform, this can emit Deprecated annotations
 for everything in the file, or it will be completely ignored; in the very
 least, this is a formalization for deprecating files.



�



�


�


�


� 1


�!0


�7q Enables the use of arenas for the proto messages in this file. This applies
 only to generated classes for C++.



�



�


� 


�#%


�&6


�'5
�

�)� Sets the objective c class prefix which is prepended to all objective c
 generated classes from this .proto. There is no default.



�



�


�#


�&(
I

�(; Namespace for generated classes; defaults to the package.



�



�


�"


�%'
�

�$� By default Swift generators will take the proto package and CamelCase it
 replacing '.' with underscore and use that to prefix the types/symbols
 defined. When this options is provided, they will use this value instead
 to prefix the types/symbols defined.



�



�


�


�!#
~

�(p Sets the php class prefix which is prepended to all php generated classes
 from this .proto. Default is empty.



�



�


�"


�%'
�

�%� Use this option to change the namespace of php generated classes. Default
 is empty. When this option is empty, the package name will be used for
 determining the namespace.



�



�


�


�"$
�

�.� Use this option to change the namespace of php generated metadata classes.
 Default is empty. When this option is empty, the proto file name will be
 used for determining the namespace.



�



�


�(


�+-
�

�$� Use this option to change the package of ruby generated classes. Default
 is empty. When this option is not set, the package name will be used for
 determining the ruby package.



�



�


�


�!#
=

�$/ Any features defined in the specific edition.



�



�


�


�!#
|

�:n The parser stores options it doesn't recognize here.
 See the documentation for the "Options" section above.



�



�


�3


�69
�

�z Clients can define custom options in extensions of this message.
 See the documentation for the "Options" section above.



 �


 �


 �


	�


	 �


	 �


	 �

� �

�
�
 �>� Set true to use the old proto1 MessageSet wire format for extensions.
 This is provided for backwards-compatibility with the MessageSet wire
 format.  You should not use this for any other reason:  It's less
 efficient, has fewer features, and is more complicated.

 The message must be defined exactly as follows:
   message Foo {
     option message_set_wire_format = true;
     extensions 4 to max;
   }
 Note that the message cannot have any defined fields; MessageSets only
 have extensions.

 All extensions of your type must be singular messages; e.g. they cannot
 be int32s, enums, or repeated messages.

 Because this is an option, the above two restrictions are not enforced by
 the protocol compiler.


 �


 �

 �'

 �*+

 �,=

 �-<
�
�F� Disables the generation of the standard "descriptor()" accessor, which can
 conflict with a field of the same name.  This is meant to make migration
 from proto1 easier; new code should avoid fields named "descriptor".


�


�

�/

�23

�4E

�5D
�
�1� Is this message deprecated?
 Depending on the target platform, this can emit Deprecated annotations
 for the message, or it will be completely ignored; in the very least,
 this is a formalization for deprecating messages.


�


�

�

�

�0

� /

	�

	 �

	 �

	 �

	�

	�

	�

	�

	�

	�
�
�� NOTE: Do not set the option in .proto files. Always use the maps syntax
 instead. The option should only be implicitly set by the proto compiler
 parser.

 Whether the message is an automatically generated map entry type for the
 maps field.

 For maps fields:
     map<KeyType, ValueType> map_field = 1;
 The parsed descriptor looks like:
     message MapFieldEntry {
         option map_entry = true;
         optional KeyType key = 1;
         optional ValueType value = 2;
     }
     repeated MapFieldEntry map_field = 1;

 Implementations may choose not to generate the map_entry=true message, but
 use a native map in the target language to hold the keys and values.
 The reflection APIs in such implementations still need to work as
 if the field is a repeated message field.


�


�

�

�
$
	�" javalite_serializable


	�

	�

	�

	�" javanano_as_lite


	�

	�

	�
�
�P� Enable the legacy handling of JSON field name conflicts.  This lowercases
 and strips underscored from the fields before comparison in proto3 only.
 The new behavior takes `json_name` into account and applies to proto2 as
 well.

 This should only be used as a temporary measure against broken builds due
 to the change in behavior for JSON field name conflicts.

 TODO This is legacy behavior we plan to remove once downstream
 teams have had time to migrate.


�


�

�6

�9;

�<O

�=N
=
�$/ Any features defined in the specific edition.


�


�

�

�!#
O
�:A The parser stores options it doesn't recognize here. See above.


�


�

�3

�69
Z
�M Clients can define custom options in extensions of this message. See above.


 �

 �

 �

� �

�
�
 �.� The ctype option instructs the C++ code generator to use a different
 representation of the field than it normally would.  See the specific
 options below.  This option is only implemented to support use of
 [ctype=CORD] and [ctype=STRING] (the default) on non-repeated fields of
 type "bytes" in the open source release -- sorry, we'll try to include
 other types in a future version!


 �


 �

 �

 �

 �-

 �,

 ��

 �

  � Default mode.


  �


  �
�
 �� The option [ctype=CORD] may be applied to a non-repeated field of type
 "bytes". It indicates that in C++, the data should be stored in a Cord
 instead of a string.  For very large strings, this may reduce memory
 fragmentation. It may also allow better performance when parsing from a
 Cord, or when parsing with aliasing enabled, as the parsed Cord may then
 alias the original buffer.


 �

 �

 �

 �

 �
�
�� The packed option can be enabled for repeated primitive fields to enable
 a more efficient representation on the wire. Rather than repeatedly
 writing the tag and type for each element, the entire array is encoded as
 a single length-delimited blob. In proto3, only explicit setting it to
 false will avoid using packed encoding.  This option is prohibited in
 Editions, but the `repeated_field_encoding` feature can be used to control
 the behavior.


�


�

�

�
�
�3� The jstype option determines the JavaScript type used for values of the
 field.  The option is permitted only for 64 bit integral and fixed types
 (int64, uint64, sint64, fixed64, sfixed64).  A field with jstype JS_STRING
 is represented as JavaScript string, which avoids loss of precision that
 can happen when a large value is converted to a floating point JavaScript.
 Specifying JS_NUMBER for the jstype causes the generated JavaScript code to
 use the JavaScript "number" type.  The behavior of the default option
 JS_NORMAL is implementation dependent.

 This option is an enum to permit additional types to be added, e.g.
 goog.math.Integer.


�


�

�

�

�2

�1

��

�
'
 � Use the default type.


 �

 �
)
� Use JavaScript strings.


�

�
)
� Use JavaScript numbers.


�

�
�
�+� Should this field be parsed lazily?  Lazy applies only to message-type
 fields.  It means that when the outer message is initially parsed, the
 inner message's contents will not be parsed but instead stored in encoded
 form.  The inner message will actually be parsed when it is first accessed.

 This is only a hint.  Implementations are free to choose whether to use
 eager or lazy parsing regardless of the value of this option.  However,
 setting this option true suggests that the protocol author believes that
 using lazy parsing on this field is worth the additional bookkeeping
 overhead typically needed to implement it.

 This option does not affect the public interface of any generated code;
 all method signatures remain the same.  Furthermore, thread-safety of the
 interface is not affected by this option; const methods remain safe to
 call from multiple threads concurrently, while non-const methods continue
 to require exclusive access.

 Note that implementations may choose not to check required fields within
 a lazy sub-message.  That is, calling IsInitialized() on the outer message
 may return true even if the inner message has missing required fields.
 This is necessary because otherwise the inner message would have to be
 parsed in order to perform the check, defeating the purpose of lazy
 parsing.  An implementation which chooses not to check required fields
 must be consistent about it.  That is, for any particular sub-message, the
 implementation must either *always* check its required fields, or *never*
 check its required fields, regardless of whether or not the message has
 been parsed.

 As of May 2022, lazy verifies the contents of the byte stream during
 parsing.  An invalid byte stream will cause the overall parsing to fail.


�


�

�

�

�*

�)
�
�7� unverified_lazy does no correctness checks on the byte stream. This should
 only be used where lazy with verification is prohibitive for performance
 reasons.


�


�

�

�"$

�%6

�&5
�
�1� Is this field deprecated?
 Depending on the target platform, this can emit Deprecated annotations
 for accessors, or it will be completely ignored; in the very least, this
 is a formalization for deprecating fields.


�


�

�

�

�0

� /
?
�,1 For Google-internal migration only. Do not use.


�


�

�

�

�+

�*
�
�4� Indicate that the field value should not be printed out when using debug
 formats, e.g. when the field contains sensitive credentials.


�


�

�

�!

�"3

�#2
�
��� If set to RETENTION_SOURCE, the option will be omitted from the binary.
 Note: as of January 2023, support for this is in progress and does not yet
 have an effect (b/264593489).


�

 �

 �

 �

�

�

�

�

�

�

�*

�


�

�$

�')
�
��� This indicates the types of entities that the field may apply to when used
 as an option. If it is unset, then the field may be freely used as an
 option on any kind of entity. Note: as of January 2023, support for this is
 in progress and does not yet have an effect (b/264593489).


�

 �

 �

 �

�

�

�

�$

�

�"#

�

�

�

�

�

�

�

�

�

�

�

�

�

�

�

�

�

�

	�

	�

	�

	�)

	�


	�

	�#

	�&(

 ��

 �


  �!

  �

  �

  �

  � 
"
 �" Textproto value.


 �

 �

 �

 �


�0


�



�


�*


�-/
=
�$/ Any features defined in the specific edition.


�


�

�

�!#
O
�:A The parser stores options it doesn't recognize here. See above.


�


�

�3

�69
Z
�M Clients can define custom options in extensions of this message. See above.


 �

 �

 �

	�" removed jtype


	 �

	 �

	 �
9
	�", reserve target, target_obsolete_do_not_use


	�

	�

	�

� �

�
=
 �#/ Any features defined in the specific edition.


 �


 �

 �

 �!"
O
�:A The parser stores options it doesn't recognize here. See above.


�


�

�3

�69
Z
�M Clients can define custom options in extensions of this message. See above.


 �

 �

 �

� �

�
`
 � R Set this option to true to allow mapping different tag names to the same
 value.


 �


 �

 �

 �
�
�1� Is this enum deprecated?
 Depending on the target platform, this can emit Deprecated annotations
 for the enum, or it will be completely ignored; in the very least, this
 is a formalization for deprecating enums.


�


�

�

�

�0

� /

	�" javanano_as_lite


	 �

	 �

	 �
�
�O� Enable the legacy handling of JSON field name conflicts.  This lowercases
 and strips underscored from the fields before comparison in proto3 only.
 The new behavior takes `json_name` into account and applies to proto2 as
 well.
 TODO Remove this legacy behavior once downstream teams have
 had time to migrate.


�


�

�6

�9:

�;N

�<M
=
�#/ Any features defined in the specific edition.


�


�

�

�!"
O
�:A The parser stores options it doesn't recognize here. See above.


�


�

�3

�69
Z
�M Clients can define custom options in extensions of this message. See above.


 �

 �

 �

� �

�
�
 �1� Is this enum value deprecated?
 Depending on the target platform, this can emit Deprecated annotations
 for the enum value, or it will be completely ignored; in the very least,
 this is a formalization for deprecating enum values.


 �


 �

 �

 �

 �0

 � /
=
�#/ Any features defined in the specific edition.


�


�

�

�!"
�
�3� Indicate that fields annotated with this enum value should not be printed
 out when using debug formats, e.g. when the field contains sensitive
 credentials.


�


�

�

� 

�!2

�"1
O
�:A The parser stores options it doesn't recognize here. See above.


�


�

�3

�69
Z
�M Clients can define custom options in extensions of this message. See above.


 �

 �

 �

� �

�
=
 �$/ Any features defined in the specific edition.


 �


 �

 �

 �!#
�
�2� Is this service deprecated?
 Depending on the target platform, this can emit Deprecated annotations
 for the service, or it will be completely ignored; in the very least,
 this is a formalization for deprecating services.
2� Note:  Field numbers 1 through 32 are reserved for Google's internal RPC
   framework.  We apologize for hoarding these numbers to ourselves, but
   we were already using them long before we decided to release Protocol
   Buffers.


�


�

�

�

� 1

�!0
O
�:A The parser stores options it doesn't recognize here. See above.


�


�

�3

�69
Z
�M Clients can define custom options in extensions of this message. See above.


 �

 �

 �

� �

�
�
 �2� Is this method deprecated?
 Depending on the target platform, this can emit Deprecated annotations
 for the method, or it will be completely ignored; in the very least,
 this is a formalization for deprecating methods.
2� Note:  Field numbers 1 through 32 are reserved for Google's internal RPC
   framework.  We apologize for hoarding these numbers to ourselves, but
   we were already using them long before we decided to release Protocol
   Buffers.


 �


 �

 �

 �

 � 1

 �!0
�
 ��� Is this method side-effect-free (or safe in HTTP parlance), or idempotent,
 or neither? HTTP based RPC implementation may choose GET verb for safe
 methods, and PUT verb for idempotent methods instead of the default POST.


 �

  �

  �

  �
$
 �" implies idempotent


 �

 �
7
 �"' idempotent, but may have side effects


 �

 �

��&

�


�

�-

�02

�%

�$
=
�$/ Any features defined in the specific edition.


�


�

�

�!#
O
�:A The parser stores options it doesn't recognize here. See above.


�


�

�3

�69
Z
�M Clients can define custom options in extensions of this message. See above.


 �

 �

 �
�
� �� A message representing a option the parser does not recognize. This only
 appears in options protos created by the compiler::Parser class.
 DescriptorPool resolves these when building Descriptor objects. Therefore,
 options protos in descriptor objects (e.g. returned by Descriptor::options(),
 or produced by Descriptor::CopyTo()) will never have UninterpretedOptions
 in them.


�
�
 ��� The name of the uninterpreted option.  Each string represents a segment in
 a dot-separated name.  is_extension is true iff a segment represents an
 extension (denoted with parentheses in options specs in .proto files).
 E.g.,{ ["foo", false], ["bar.baz", true], ["moo", false] } represents
 "foo.(bar.baz).moo".


 �


  �"

  �

  �

  �

  � !

 �#

 �

 �

 �

 �!"

 �

 �


 �

 �

 �
�
�'� The value of the uninterpreted option, in whatever type the tokenizer
 identified it as during parsing. Exactly one of these should be set.


�


�

�"

�%&

�)

�


�

�$

�'(

�(

�


�

�#

�&'

�#

�


�

�

�!"

�"

�


�

�

� !

�&

�


�

�!

�$%
�
� �� TODO Enums in C++ gencode (and potentially other languages) are
 not well scoped.  This means that each of the feature enums below can clash
 with each other.  The short names we've chosen maximize call-site
 readability, but leave us very open to this scenario.  A future feature will
 be designed and implemented to handle this, hopefully before we ever hit a
 conflict here.
2O ===================================================================
 Features


�

 ��

 �

  �

  �

  �

 �

 �

 �

 �

 �

 �

 �

 �

 �

 ��

 �


 �

 �'

 �*+

 �,�

 �!

  �

 �

  �E

 �E

 �C

��

�

 �

 �

 �

�

�

�

�

�


�

��

�


�

�

� !

�"�

�!

 �

�

 �C

�A

��

�

 �(

 �#

 �&'

�

�


�

�

�

�

��

�


� 

�!8

�;<

�=�

�!

 �

�

 �E

�C

��

�

 � 

 �

 �

�

�

�

�

�


�

��

�


�

�)

�,-

�.�

�!

 �

�

 �A

�C

��

�

 �!

 �

 � 

�

�

�

�

�

�

��

�


�

�+

�./

�0�

�!

 �

�

 �L

��

�

 �

 �

 �

�

�	

�

�

�

�

��

�


�

�!

�$%

�&�

�!

 �!

�

�

 �O

�B

	�

	 �

	 �

	 �

�" for Protobuf C++


 �

 �

 �
 
�" for Protobuf Java


�

�

�
#
�" For internal testing


�

�

�
�
� �� A compiled specification for the defaults of a set of features.  These
 messages are generated from FeatureSet extensions and can be used to seed
 feature resolution. The resolution with this object becomes a simple search
 for the closest matching edition, followed by proto merges.


�
�
 ��� A map from every known edition with a unique set of defaults to its
 defaults. Not all editions may be contained here.  For a given edition,
 the defaults at the closest matching edition ordered at or before it should
 be used.  This field must be in strict ascending order by edition.


 �
"

  �!

  �

  �

  �

  � 

 �%

 �

 �

 � 

 �#$

 �1

 �


 �#

 �$,

 �/0
�
�'t The minimum supported edition (inclusive) when this was constructed.
 Editions before this will not have defaults.


�


�

�"

�%&
�
�'x The maximum known edition (inclusive) when this was constructed. Editions
 after this will not have reliable defaults.


�


�

�"

�%&
�
� �	j Encapsulates information about the original source file from which a
 FileDescriptorProto was generated.
2` ===================================================================
 Optional source code info


�
�
 �!� A Location identifies a piece of source code in a .proto file which
 corresponds to a particular definition.  This information is intended
 to be useful to IDEs, code indexers, documentation generators, and similar
 tools.

 For example, say we have a file like:
   message Foo {
     optional string foo = 1;
   }
 Let's look at just the field definition:
   optional string foo = 1;
   ^       ^^     ^^  ^  ^^^
   a       bc     de  f  ghi
 We have the following locations:
   span   path               represents
   [a,i)  [ 4, 0, 2, 0 ]     The whole field definition.
   [a,b)  [ 4, 0, 2, 0, 4 ]  The label (optional).
   [c,d)  [ 4, 0, 2, 0, 5 ]  The type (string).
   [e,f)  [ 4, 0, 2, 0, 1 ]  The name (foo).
   [g,h)  [ 4, 0, 2, 0, 3 ]  The number (1).

 Notes:
 - A location may refer to a repeated field itself (i.e. not to any
   particular index within it).  This is used whenever a set of elements are
   logically enclosed in a single code segment.  For example, an entire
   extend block (possibly containing multiple extension definitions) will
   have an outer location whose path refers to the "extensions" repeated
   field without an index.
 - Multiple locations may have the same path.  This happens when a single
   logical declaration is spread out across multiple places.  The most
   obvious example is the "extend" block again -- there may be multiple
   extend blocks in the same scope, each of which will have the same path.
 - A location's span is not always a subset of its parent's span.  For
   example, the "extendee" of an extension declaration appears at the
   beginning of the "extend" block and is shared by all extensions within
   the block.
 - Just because a location's span is a subset of some other location's span
   does not mean that it is a descendant.  For example, a "group" defines
   both a type and a field in a single declaration.  Thus, the locations
   corresponding to the type and field and their components will overlap.
 - Code which tries to interpret locations should probably be designed to
   ignore those that it doesn't understand, as more types of locations could
   be recorded in the future.


 �


 �

 �

 � 

 ��	

 �

�
  �,� Identifies which part of the FileDescriptorProto was defined at this
 location.

 Each element is a field number or an index.  They form a path from
 the root FileDescriptorProto to the place where the definition occurs.
 For example, this path:
   [ 4, 3, 2, 7, 1 ]
 refers to:
   file.message_type(3)  // 4, 3
       .field(7)         // 2, 7
       .name()           // 1
 This is because FileDescriptorProto.message_type has field number 4:
   repeated DescriptorProto message_type = 4;
 and DescriptorProto.field has field number 2:
   repeated FieldDescriptorProto field = 2;
 and FieldDescriptorProto.name has field number 1:
   optional string name = 1;

 Thus, the above path gives the location of a field name.  If we removed
 the last element:
   [ 4, 3, 2, 7 ]
 this path refers to the whole field declaration (from the beginning
 of the label to the terminating semicolon).


  �

  �

  �

  �

  �+

  �*
�
 �,� Always has exactly three or four elements: start line, start column,
 end line (optional, otherwise assumed same as start line), end column.
 These are packed into a single field for efficiency.  Note that line
 and column numbers are zero-based -- typically you will want to add
 1 to each before displaying to a user.


 �

 �

 �

 �

 �+

 �*
�
 �	)� If this SourceCodeInfo represents a complete declaration, these are any
 comments appearing before and after the declaration which appear to be
 attached to the declaration.

 A series of line comments appearing on consecutive lines, with no other
 tokens appearing on those lines, will be treated as a single comment.

 leading_detached_comments will keep paragraphs of comments that appear
 before (but not connected to) the current element. Each paragraph,
 separated by empty lines, will be one comment element in the repeated
 field.

 Only the comment content is provided; comment markers (e.g. //) are
 stripped out.  For block comments, leading whitespace and an asterisk
 will be stripped from the beginning of each line other than the first.
 Newlines are included in the output.

 Examples:

   optional int32 foo = 1;  // Comment attached to foo.
   // Comment attached to bar.
   optional int32 bar = 2;

   optional string baz = 3;
   // Comment attached to baz.
   // Another line attached to baz.

   // Comment attached to moo.
   //
   // Another line attached to moo.
   optional double moo = 4;

   // Detached comment for corge. This is not leading or trailing comments
   // to moo or corge because there are blank lines separating it from
   // both.

   // Detached comment for corge paragraph 2.

   optional string corge = 5;
   /* Block comment attached
    * to corge.  Leading asterisks
    * will be removed. */
   /* Block comment attached to
    * grault. */
   optional int32 grault = 6;

   // ignored detached comments.


 �	

 �	

 �	$

 �	'(

 �	*

 �	

 �	

 �	%

 �	()

 �	2

 �	

 �	

 �	-

 �	01
�
�	 �	� Describes the relationship between generated code and its original source
 file. A GeneratedCodeInfo message is associated with only one generated
 source file, but may contain references to different source .proto files.


�	
x
 �	%j An Annotation connects some span of text in generated code to an element
 of its generating .proto file.


 �	


 �	

 �	 

 �	#$

 �	�	

 �	

�
  �	, Identifies the element in the original source .proto file. This field
 is formatted the same as SourceCodeInfo.Location.path.


  �	

  �	

  �	

  �	

  �	+

  �	*
O
 �	$? Identifies the filesystem path to the original source .proto.


 �	

 �	

 �	

 �	"#
w
 �	g Identifies the starting offset in bytes in the generated code
 that relates to the identified object.


 �	

 �	

 �	

 �	
�
 �	� Identifies the ending offset in bytes in the generated code that
 relates to the identified object. The end offset should be one past
 the last relevant byte (so the length of the text = end - begin).


 �	

 �	

 �	

 �	
j
  �	�	X Represents the identified object's effect on the element in the original
 .proto file.


  �		
F
   �	4 There is no effect or the effect is indescribable.


	   �	


	   �	
<
  �	* The element is set or otherwise mutated.


	  �		

	  �	
8
  �	& An alias to the element is returned.


	  �	

	  �	

 �	#

 �	

 �	

 �	

 �	!"�� 
�	
google/api/annotations.proto
google.apigoogle/api/http.proto google/protobuf/descriptor.proto:K
http.google.protobuf.MethodOptions�ʼ" (2.google.api.HttpRuleRhttpBn
com.google.apiBAnnotationsProtoPZAgoogle.golang.org/genproto/googleapis/api/annotations;annotations�GAPIJ�
 
�
 2� Copyright 2015 Google LLC

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.


 
	
  
	
 *

 X
	
 X

 "
	

 "

 1
	
 1

 '
	
 '

 "
	
$ "
	
 

  See `HttpRule`.



 $


 



 


 bproto3��MG
#
	buf.build
googleapis
googleapis a86849a25cc04f4dbe9b15ddddfbc488 
�.
google/protobuf/any.protogoogle.protobuf"6
Any
type_url (	RtypeUrl
value (RvalueBv
com.google.protobufBAnyProtoPZ,google.golang.org/protobuf/types/known/anypb�GPB�Google.Protobuf.WellKnownTypesJ�,
 �
�
 2� Protocol Buffers - Google's data interchange format
 Copyright 2008 Google Inc.  All rights reserved.
 https://developers.google.com/protocol-buffers/

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are
 met:

     * Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above
 copyright notice, this list of conditions and the following disclaimer
 in the documentation and/or other materials provided with the
 distribution.
     * Neither the name of Google Inc. nor the names of its
 contributors may be used to endorse or promote products derived from
 this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


  

" C
	
" C

# ,
	
# ,

$ )
	
$ )

% "
	

% "

& !
	
$& !

' ;
	
%' ;
�
  �� `Any` contains an arbitrary serialized protocol buffer message along with a
 URL that describes the type of the serialized message.

 Protobuf library provides support to pack/unpack Any values in the form
 of utility functions or additional generated methods of the Any type.

 Example 1: Pack and unpack a message in C++.

     Foo foo = ...;
     Any any;
     any.PackFrom(foo);
     ...
     if (any.UnpackTo(&foo)) {
       ...
     }

 Example 2: Pack and unpack a message in Java.

     Foo foo = ...;
     Any any = Any.pack(foo);
     ...
     if (any.is(Foo.class)) {
       foo = any.unpack(Foo.class);
     }
     // or ...
     if (any.isSameTypeAs(Foo.getDefaultInstance())) {
       foo = any.unpack(Foo.getDefaultInstance());
     }

  Example 3: Pack and unpack a message in Python.

     foo = Foo(...)
     any = Any()
     any.Pack(foo)
     ...
     if any.Is(Foo.DESCRIPTOR):
       any.Unpack(foo)
       ...

  Example 4: Pack and unpack a message in Go

      foo := &pb.Foo{...}
      any, err := anypb.New(foo)
      if err != nil {
        ...
      }
      ...
      foo := &pb.Foo{}
      if err := any.UnmarshalTo(foo); err != nil {
        ...
      }

 The pack methods provided by protobuf library will by default use
 'type.googleapis.com/full.type.name' as the type URL and the unpack
 methods only use the fully qualified type name after the last '/'
 in the type URL, for example "foo.bar.com/x/y.z" will yield type
 name "y.z".

 JSON
 ====
 The JSON representation of an `Any` value uses the regular
 representation of the deserialized, embedded message, with an
 additional field `@type` which contains the type URL. Example:

     package google.profile;
     message Person {
       string first_name = 1;
       string last_name = 2;
     }

     {
       "@type": "type.googleapis.com/google.profile.Person",
       "firstName": <string>,
       "lastName": <string>
     }

 If the embedded message type is well-known and has a custom JSON
 representation, that representation will be embedded adding a field
 `value` which holds the custom JSON in addition to the `@type`
 field. Example (for message [google.protobuf.Duration][]):

     {
       "@type": "type.googleapis.com/google.protobuf.Duration",
       "value": "1.212s"
     }




 
�
  �� A URL/resource name that uniquely identifies the type of the serialized
 protocol buffer message. This string must contain at least
 one "/" character. The last segment of the URL's path must represent
 the fully qualified name of the type (as in
 `path/google.protobuf.Duration`). The name should be in a canonical form
 (e.g., leading "." is not accepted).

 In practice, teams usually precompile into the binary all types that they
 expect it to use in the context of Any. However, for URLs which use the
 scheme `http`, `https`, or no scheme, one can optionally set up a type
 server that maps type URLs to message definitions as follows:

 * If no scheme is provided, `https` is assumed.
 * An HTTP GET on the URL must yield a [google.protobuf.Type][]
   value in binary format, or produce an error.
 * Applications are allowed to cache lookup results based on the
   URL, or have them precompiled into a binary to avoid any
   lookup. Therefore, binary compatibility needs to be preserved
   on changes to types. (Use versioned type names to manage
   breaking changes.)

 Note: this functionality is not currently available in the official
 protobuf release, and it is not used for type URLs beginning with
 type.googleapis.com. As of May 2023, there are no widely used type server
 implementations and no plans to implement one.

 Schemes other than `http`, `https` (or the empty scheme) might be
 used with implementation specific semantics.



  �

  �	

  �
W
 �I Must be a valid serialized protocol buffer of the above specified type.


 �

 �

 �bproto3�� 
�#
buf/validate/expression.protobuf.validate"V

Constraint
id (	Rid
message (	Rmessage

expression (	R
expression"E

Violations7

violations (2.buf.validate.ViolationR
violations"�
	Violation

field_path (	R	fieldPath#
constraint_id (	RconstraintId
message (	Rmessage
for_key (RforKeyBp
build.buf.validateBExpressionProtoPZGbuf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validateJ�
 [
�
 2� Copyright 2023 Buf Technologies, Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.


 

 ^
	
 ^

 "
	

 "

 0
	
 0

 +
	
 +
�
 & 6� `Constraint` represents a validation rule written in the Common Expression
 Language (CEL) syntax. Each Constraint includes a unique identifier, an
 optional error message, and the CEL expression to evaluate. For more
 information on CEL, [see our documentation](https://github.com/bufbuild/protovalidate/blob/main/docs/cel.md).

 ```proto
 message Foo {
   option (buf.validate.message).cel = {
     id: "foo.bar"
     message: "bar must be greater than 0"
     expression: "this.bar > 0"
   };
   int32 bar = 1;
 }
 ```



 &
�
  )� `id` is a string that serves as a machine-readable name for this Constraint.
 It should be unique within its scope, which could be either a message or a field.


  )

  )	

  )
�
 /� `message` is an optional field that provides a human-readable error message
 for this Constraint when the CEL expression evaluates to false. If a
 non-empty message is provided, any strings resulting from the CEL
 expression evaluation are ignored.


 /

 /	

 /
�
 5� `expression` is the actual CEL expression that will be evaluated for
 validation. This string must resolve to either a boolean or a string
 value. If the expression evaluates to false or a non-empty string, the
 validation is considered failed, and the message is rejected.


 5

 5	

 5
�
; >� `Violations` is a collection of `Violation` messages. This message type is returned by
 protovalidate when a proto message fails to meet the requirements set by the `Constraint` validation rules.
 Each individual violation is represented by a `Violation` message.



;
�
 =$w `violations` is a repeated field that contains all the `Violation` messages corresponding to the violations detected.


 =


 =

 =

 ="#
�
L [� `Violation` represents a single instance where a validation rule, expressed
 as a `Constraint`, was not met. It provides information about the field that
 caused the violation, the specific constraint that wasn't fulfilled, and a
 human-readable error message.

 ```json
 {
   "fieldPath": "bar",
   "constraintId": "foo.bar",
   "message": "bar must be greater than 0"
 }
 ```



L
�
 O� `field_path` is a machine-readable identifier that points to the specific field that failed the validation.
 This could be a nested field, in which case the path will include all the parent fields leading to the actual field that caused the violation.


 O

 O	

 O
�
S� `constraint_id` is the unique identifier of the `Constraint` that was not fulfilled.
 This is the same `id` that was specified in the `Constraint` message, allowing easy tracing of which rule was violated.


S

S	

S
�
W� `message` is a human-readable error message that describes the nature of the violation.
 This can be the default error message from the violated `Constraint`, or it can be a custom message that gives more context about the violation.


W

W	

W
f
ZY `for_key` indicates whether the violation was caused by a map key, rather than a value.


Z

Z

Zbproto3��NH
$
	buf.buildbufbuildprotovalidate e097f827e65240ac9fd4b1158849a8fc 
�
buf/validate/priv/private.protobuf.validate.priv google/protobuf/descriptor.proto"C
FieldConstraints/
cel (2.buf.validate.priv.ConstraintRcel"V

Constraint
id (	Rid
message (	Rmessage

expression (	R
expression:\
field.google.protobuf.FieldOptions�	 (2#.buf.validate.priv.FieldConstraintsRfield�Bw
build.buf.validate.privBPrivateProtoPZLbuf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate/privJ�	
 (
�
 2� Copyright 2023 Buf Technologies, Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.


 
	
  *

 c
	
 c

 "
	

 "

 -
	
 -

 0
	
 0
	
 
:
 )/ Do not use. Internal to protovalidate library



 #


 



 


 !


 $(
;
  !/ Do not use. Internal to protovalidate library



 

   

   


   

   

   
;
$ (/ Do not use. Internal to protovalidate library



$

 %

 %

 %	

 %

&

&

&	

&

'

'

'	

'bproto3��NH
$
	buf.buildbufbuildprotovalidate e097f827e65240ac9fd4b1158849a8fc 
�%
google/protobuf/duration.protogoogle.protobuf":
Duration
seconds (Rseconds
nanos (RnanosB�
com.google.protobufBDurationProtoPZ1google.golang.org/protobuf/types/known/durationpb��GPB�Google.Protobuf.WellKnownTypesJ�#
 r
�
 2� Protocol Buffers - Google's data interchange format
 Copyright 2008 Google Inc.  All rights reserved.
 https://developers.google.com/protocol-buffers/

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are
 met:

     * Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above
 copyright notice, this list of conditions and the following disclaimer
 in the documentation and/or other materials provided with the
 distribution.
     * Neither the name of Google Inc. nor the names of its
 contributors may be used to endorse or promote products derived from
 this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


  

" 
	
" 

# H
	
# H

$ ,
	
$ ,

% .
	
% .

& "
	

& "

' !
	
$' !

( ;
	
%( ;
�
 e r� A Duration represents a signed, fixed-length span of time represented
 as a count of seconds and fractions of seconds at nanosecond
 resolution. It is independent of any calendar and concepts like "day"
 or "month". It is related to Timestamp in that the difference between
 two Timestamp values is a Duration and it can be added or subtracted
 from a Timestamp. Range is approximately +-10,000 years.

 # Examples

 Example 1: Compute Duration from two Timestamps in pseudo code.

     Timestamp start = ...;
     Timestamp end = ...;
     Duration duration = ...;

     duration.seconds = end.seconds - start.seconds;
     duration.nanos = end.nanos - start.nanos;

     if (duration.seconds < 0 && duration.nanos > 0) {
       duration.seconds += 1;
       duration.nanos -= 1000000000;
     } else if (duration.seconds > 0 && duration.nanos < 0) {
       duration.seconds -= 1;
       duration.nanos += 1000000000;
     }

 Example 2: Compute Timestamp from Timestamp + Duration in pseudo code.

     Timestamp start = ...;
     Duration duration = ...;
     Timestamp end = ...;

     end.seconds = start.seconds + duration.seconds;
     end.nanos = start.nanos + duration.nanos;

     if (end.nanos < 0) {
       end.seconds -= 1;
       end.nanos += 1000000000;
     } else if (end.nanos >= 1000000000) {
       end.seconds += 1;
       end.nanos -= 1000000000;
     }

 Example 3: Compute Duration from datetime.timedelta in Python.

     td = datetime.timedelta(days=3, minutes=10)
     duration = Duration()
     duration.FromTimedelta(td)

 # JSON Mapping

 In JSON format, the Duration type is encoded as a string rather than an
 object, where the string ends in the suffix "s" (indicating seconds) and
 is preceded by the number of seconds, with nanoseconds expressed as
 fractional seconds. For example, 3 seconds with 0 nanoseconds should be
 encoded in JSON format as "3s", while 3 seconds and 1 nanosecond should
 be expressed in JSON format as "3.000000001s", and 3 seconds and 1
 microsecond should be expressed in JSON format as "3.000001s".




 e
�
  i� Signed seconds of the span of time. Must be from -315,576,000,000
 to +315,576,000,000 inclusive. Note: these bounds are computed from:
 60 sec/min * 60 min/hr * 24 hr/day * 365.25 days/year * 10000 years


  i

  i

  i
�
 q� Signed fractions of a second at nanosecond resolution of the span
 of time. Durations less than one second are represented with a 0
 `seconds` field and a positive or negative `nanos` field. For durations
 of one second or more, a non-zero value for the `nanos` field must be
 of the same sign as the `seconds` field. Must be from -999,999,999
 to +999,999,999 inclusive.


 q

 q

 qbproto3�� 
�1
google/protobuf/timestamp.protogoogle.protobuf";
	Timestamp
seconds (Rseconds
nanos (RnanosB�
com.google.protobufBTimestampProtoPZ2google.golang.org/protobuf/types/known/timestamppb��GPB�Google.Protobuf.WellKnownTypesJ�/
 �
�
 2� Protocol Buffers - Google's data interchange format
 Copyright 2008 Google Inc.  All rights reserved.
 https://developers.google.com/protocol-buffers/

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are
 met:

     * Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above
 copyright notice, this list of conditions and the following disclaimer
 in the documentation and/or other materials provided with the
 distribution.
     * Neither the name of Google Inc. nor the names of its
 contributors may be used to endorse or promote products derived from
 this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


  

" 
	
" 

# I
	
# I

$ ,
	
$ ,

% /
	
% /

& "
	

& "

' !
	
$' !

( ;
	
%( ;
�
 � �� A Timestamp represents a point in time independent of any time zone or local
 calendar, encoded as a count of seconds and fractions of seconds at
 nanosecond resolution. The count is relative to an epoch at UTC midnight on
 January 1, 1970, in the proleptic Gregorian calendar which extends the
 Gregorian calendar backwards to year one.

 All minutes are 60 seconds long. Leap seconds are "smeared" so that no leap
 second table is needed for interpretation, using a [24-hour linear
 smear](https://developers.google.com/time/smear).

 The range is from 0001-01-01T00:00:00Z to 9999-12-31T23:59:59.999999999Z. By
 restricting to that range, we ensure that we can convert to and from [RFC
 3339](https://www.ietf.org/rfc/rfc3339.txt) date strings.

 # Examples

 Example 1: Compute Timestamp from POSIX `time()`.

     Timestamp timestamp;
     timestamp.set_seconds(time(NULL));
     timestamp.set_nanos(0);

 Example 2: Compute Timestamp from POSIX `gettimeofday()`.

     struct timeval tv;
     gettimeofday(&tv, NULL);

     Timestamp timestamp;
     timestamp.set_seconds(tv.tv_sec);
     timestamp.set_nanos(tv.tv_usec * 1000);

 Example 3: Compute Timestamp from Win32 `GetSystemTimeAsFileTime()`.

     FILETIME ft;
     GetSystemTimeAsFileTime(&ft);
     UINT64 ticks = (((UINT64)ft.dwHighDateTime) << 32) | ft.dwLowDateTime;

     // A Windows tick is 100 nanoseconds. Windows epoch 1601-01-01T00:00:00Z
     // is 11644473600 seconds before Unix epoch 1970-01-01T00:00:00Z.
     Timestamp timestamp;
     timestamp.set_seconds((INT64) ((ticks / 10000000) - 11644473600LL));
     timestamp.set_nanos((INT32) ((ticks % 10000000) * 100));

 Example 4: Compute Timestamp from Java `System.currentTimeMillis()`.

     long millis = System.currentTimeMillis();

     Timestamp timestamp = Timestamp.newBuilder().setSeconds(millis / 1000)
         .setNanos((int) ((millis % 1000) * 1000000)).build();

 Example 5: Compute Timestamp from Java `Instant.now()`.

     Instant now = Instant.now();

     Timestamp timestamp =
         Timestamp.newBuilder().setSeconds(now.getEpochSecond())
             .setNanos(now.getNano()).build();

 Example 6: Compute Timestamp from current time in Python.

     timestamp = Timestamp()
     timestamp.GetCurrentTime()

 # JSON Mapping

 In JSON format, the Timestamp type is encoded as a string in the
 [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format. That is, the
 format is "{year}-{month}-{day}T{hour}:{min}:{sec}[.{frac_sec}]Z"
 where {year} is always expressed using four digits while {month}, {day},
 {hour}, {min}, and {sec} are zero-padded to two digits each. The fractional
 seconds, which can go up to 9 digits (i.e. up to 1 nanosecond resolution),
 are optional. The "Z" suffix indicates the timezone ("UTC"); the timezone
 is required. A proto3 JSON serializer should always use UTC (as indicated by
 "Z") when printing the Timestamp type and a proto3 JSON parser should be
 able to accept both UTC and other timezones (as indicated by an offset).

 For example, "2017-01-15T01:30:15.01Z" encodes 15.01 seconds past
 01:30 UTC on January 15, 2017.

 In JavaScript, one can convert a Date object to this format using the
 standard
 [toISOString()](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/toISOString)
 method. In Python, a standard `datetime.datetime` object can be converted
 to this format using
 [`strftime`](https://docs.python.org/2/library/time.html#time.strftime) with
 the time format spec '%Y-%m-%dT%H:%M:%S.%fZ'. Likewise, in Java, one can use
 the Joda Time's [`ISODateTimeFormat.dateTime()`](
 http://joda-time.sourceforge.net/apidocs/org/joda/time/format/ISODateTimeFormat.html#dateTime()
 ) to obtain a formatter capable of generating timestamps in this format.



 �
�
  �� Represents seconds of UTC time since Unix epoch
 1970-01-01T00:00:00Z. Must be from 0001-01-01T00:00:00Z to
 9999-12-31T23:59:59Z inclusive.


  �

  �

  �
�
 �� Non-negative fractions of a second at nanosecond resolution. Negative
 second values with fractions must still have non-negative nanos values
 that count forward in time. Must be from 0 to 999,999,999
 inclusive.


 �

 �

 �bproto3�� 
Ϙ	
buf/validate/validate.protobuf.validatebuf/validate/expression.protobuf/validate/priv/private.proto google/protobuf/descriptor.protogoogle/protobuf/duration.protogoogle/protobuf/timestamp.proto"n
MessageConstraints
disabled (H Rdisabled�*
cel (2.buf.validate.ConstraintRcelB
	_disabled"@
OneofConstraints
required (H Rrequired�B
	_required"�	
FieldConstraints*
cel (2.buf.validate.ConstraintRcel
skipped (Rskipped
required (Rrequired!
ignore_empty (RignoreEmpty0
float (2.buf.validate.FloatRulesH Rfloat3
double (2.buf.validate.DoubleRulesH Rdouble0
int32 (2.buf.validate.Int32RulesH Rint320
int64 (2.buf.validate.Int64RulesH Rint643
uint32 (2.buf.validate.UInt32RulesH Ruint323
uint64 (2.buf.validate.UInt64RulesH Ruint643
sint32 (2.buf.validate.SInt32RulesH Rsint323
sint64 (2.buf.validate.SInt64RulesH Rsint646
fixed32	 (2.buf.validate.Fixed32RulesH Rfixed326
fixed64
 (2.buf.validate.Fixed64RulesH Rfixed649
sfixed32 (2.buf.validate.SFixed32RulesH Rsfixed329
sfixed64 (2.buf.validate.SFixed64RulesH Rsfixed64-
bool (2.buf.validate.BoolRulesH Rbool3
string (2.buf.validate.StringRulesH Rstring0
bytes (2.buf.validate.BytesRulesH Rbytes-
enum (2.buf.validate.EnumRulesH Renum9
repeated (2.buf.validate.RepeatedRulesH Rrepeated*
map (2.buf.validate.MapRulesH Rmap*
any (2.buf.validate.AnyRulesH Rany9
duration (2.buf.validate.DurationRulesH Rduration<
	timestamp (2.buf.validate.TimestampRulesH R	timestampB
type"�

FloatRulesu
const (BZ�HW
U
float.constFthis != rules.const ? 'value must equal %s'.format([rules.const]) : ''HRconst��
lt (B��H�
�
float.lt}!has(rules.gte) && !has(rules.gt) && (this.isNan() || this >= rules.lt)? 'value must be less than %s'.format([rules.lt]) : ''H Rlt�
lte (B��H�
�
	float.lte�!has(rules.gte) && !has(rules.gt) && (this.isNan() || this > rules.lte)? 'value must be less than or equal to %s'.format([rules.lte]) : ''H Rlte�
gt (B��H�
�
float.gt�!has(rules.lt) && !has(rules.lte) && (this.isNan() || this <= rules.gt)? 'value must be greater than %s'.format([rules.gt]) : ''
�
float.gt_lt�has(rules.lt) && rules.lt >= rules.gt && (this.isNan() || this >= rules.lt || this <= rules.gt)? 'value must be greater than %s and less than %s'.format([rules.gt, rules.lt]) : ''
�
float.gt_lt_exclusive�has(rules.lt) && rules.lt < rules.gt && (this.isNan() || (rules.lt <= this && this <= rules.gt))? 'value must be greater than %s or less than %s'.format([rules.gt, rules.lt]) : ''
�
float.gt_lte�has(rules.lte) && rules.lte >= rules.gt && (this.isNan() || this > rules.lte || this <= rules.gt)? 'value must be greater than %s and less than or equal to %s'.format([rules.gt, rules.lte]) : ''
�
float.gt_lte_exclusive�has(rules.lte) && rules.lte < rules.gt && (this.isNan() || (rules.lte < this && this <= rules.gt))? 'value must be greater than %s or less than or equal to %s'.format([rules.gt, rules.lte]) : ''HRgt�
gte (B��H�
�
	float.gte�!has(rules.lt) && !has(rules.lte) && (this.isNan() || this < rules.gte)? 'value must be greater than or equal to %s'.format([rules.gte]) : ''
�
float.gte_lt�has(rules.lt) && rules.lt >= rules.gte && (this.isNan() || this >= rules.lt || this < rules.gte)? 'value must be greater than or equal to %s and less than %s'.format([rules.gte, rules.lt]) : ''
�
float.gte_lt_exclusive�has(rules.lt) && rules.lt < rules.gte && (this.isNan() || (rules.lt <= this && this < rules.gte))? 'value must be greater than or equal to %s or less than %s'.format([rules.gte, rules.lt]) : ''
�
float.gte_lte�has(rules.lte) && rules.lte >= rules.gte && (this.isNan() || this > rules.lte || this < rules.gte)? 'value must be greater than or equal to %s and less than or equal to %s'.format([rules.gte, rules.lte]) : ''
�
float.gte_lte_exclusive�has(rules.lte) && rules.lte < rules.gte && (this.isNan() || (rules.lte < this && this < rules.gte))? 'value must be greater than or equal to %s or less than or equal to %s'.format([rules.gte, rules.lte]) : ''HRgtey
in (Bi�Hf
d
float.inX!(this in dyn(rules)['in']) ? 'value must be in list %s'.format([dyn(rules)['in']]) : ''Rin}
not_in (Bf�Hc
a
float.not_inQthis in rules.not_in ? 'value must not be in list %s'.format([rules.not_in]) : ''RnotIng
finite (BO�HL
J
float.finite:this.isNan() || this.isInf() ? 'value must be finite' : ''RfiniteB
	less_thanB
greater_thanB
_const"�
DoubleRulesv
const (B[�HX
V
double.constFthis != rules.const ? 'value must equal %s'.format([rules.const]) : ''HRconst��
lt (B��H�
�
	double.lt}!has(rules.gte) && !has(rules.gt) && (this.isNan() || this >= rules.lt)? 'value must be less than %s'.format([rules.lt]) : ''H Rlt�
lte (B��H�
�

double.lte�!has(rules.gte) && !has(rules.gt) && (this.isNan() || this > rules.lte)? 'value must be less than or equal to %s'.format([rules.lte]) : ''H Rlte�
gt (B��H�
�
	double.gt�!has(rules.lt) && !has(rules.lte) && (this.isNan() || this <= rules.gt)? 'value must be greater than %s'.format([rules.gt]) : ''
�
double.gt_lt�has(rules.lt) && rules.lt >= rules.gt && (this.isNan() || this >= rules.lt || this <= rules.gt)? 'value must be greater than %s and less than %s'.format([rules.gt, rules.lt]) : ''
�
double.gt_lt_exclusive�has(rules.lt) && rules.lt < rules.gt && (this.isNan() || (rules.lt <= this && this <= rules.gt))? 'value must be greater than %s or less than %s'.format([rules.gt, rules.lt]) : ''
�
double.gt_lte�has(rules.lte) && rules.lte >= rules.gt && (this.isNan() || this > rules.lte || this <= rules.gt)? 'value must be greater than %s and less than or equal to %s'.format([rules.gt, rules.lte]) : ''
�
double.gt_lte_exclusive�has(rules.lte) && rules.lte < rules.gt && (this.isNan() || (rules.lte < this && this <= rules.gt))? 'value must be greater than %s or less than or equal to %s'.format([rules.gt, rules.lte]) : ''HRgt�
gte (B��H�
�

double.gte�!has(rules.lt) && !has(rules.lte) && (this.isNan() || this < rules.gte)? 'value must be greater than or equal to %s'.format([rules.gte]) : ''
�
double.gte_lt�has(rules.lt) && rules.lt >= rules.gte && (this.isNan() || this >= rules.lt || this < rules.gte)? 'value must be greater than or equal to %s and less than %s'.format([rules.gte, rules.lt]) : ''
�
double.gte_lt_exclusive�has(rules.lt) && rules.lt < rules.gte && (this.isNan() || (rules.lt <= this && this < rules.gte))? 'value must be greater than or equal to %s or less than %s'.format([rules.gte, rules.lt]) : ''
�
double.gte_lte�has(rules.lte) && rules.lte >= rules.gte && (this.isNan() || this > rules.lte || this < rules.gte)? 'value must be greater than or equal to %s and less than or equal to %s'.format([rules.gte, rules.lte]) : ''
�
double.gte_lte_exclusive�has(rules.lte) && rules.lte < rules.gte && (this.isNan() || (rules.lte < this && this < rules.gte))? 'value must be greater than or equal to %s or less than or equal to %s'.format([rules.gte, rules.lte]) : ''HRgtez
in (Bj�Hg
e
	double.inX!(this in dyn(rules)['in']) ? 'value must be in list %s'.format([dyn(rules)['in']]) : ''Rin~
not_in (Bg�Hd
b
double.not_inQthis in rules.not_in ? 'value must not be in list %s'.format([rules.not_in]) : ''RnotInh
finite (BP�HM
K
double.finite:this.isNan() || this.isInf() ? 'value must be finite' : ''RfiniteB
	less_thanB
greater_thanB
_const"�

Int32Rulesu
const (BZ�HW
U
int32.constFthis != rules.const ? 'value must equal %s'.format([rules.const]) : ''HRconst��
lt (B|�Hy
w
int32.ltk!has(rules.gte) && !has(rules.gt) && this >= rules.lt? 'value must be less than %s'.format([rules.lt]) : ''H Rlt�
lte (B��H�
�
	int32.ltex!has(rules.gte) && !has(rules.gt) && this > rules.lte? 'value must be less than or equal to %s'.format([rules.lte]) : ''H Rlte�
gt (B��H�
z
int32.gtn!has(rules.lt) && !has(rules.lte) && this <= rules.gt? 'value must be greater than %s'.format([rules.gt]) : ''
�
int32.gt_lt�has(rules.lt) && rules.lt >= rules.gt && (this >= rules.lt || this <= rules.gt)? 'value must be greater than %s and less than %s'.format([rules.gt, rules.lt]) : ''
�
int32.gt_lt_exclusive�has(rules.lt) && rules.lt < rules.gt && (rules.lt <= this && this <= rules.gt)? 'value must be greater than %s or less than %s'.format([rules.gt, rules.lt]) : ''
�
int32.gt_lte�has(rules.lte) && rules.lte >= rules.gt && (this > rules.lte || this <= rules.gt)? 'value must be greater than %s and less than or equal to %s'.format([rules.gt, rules.lte]) : ''
�
int32.gt_lte_exclusive�has(rules.lte) && rules.lte < rules.gt && (rules.lte < this && this <= rules.gt)? 'value must be greater than %s or less than or equal to %s'.format([rules.gt, rules.lte]) : ''HRgt�
gte (B��H�
�
	int32.gte{!has(rules.lt) && !has(rules.lte) && this < rules.gte? 'value must be greater than or equal to %s'.format([rules.gte]) : ''
�
int32.gte_lt�has(rules.lt) && rules.lt >= rules.gte && (this >= rules.lt || this < rules.gte)? 'value must be greater than or equal to %s and less than %s'.format([rules.gte, rules.lt]) : ''
�
int32.gte_lt_exclusive�has(rules.lt) && rules.lt < rules.gte && (rules.lt <= this && this < rules.gte)? 'value must be greater than or equal to %s or less than %s'.format([rules.gte, rules.lt]) : ''
�
int32.gte_lte�has(rules.lte) && rules.lte >= rules.gte && (this > rules.lte || this < rules.gte)? 'value must be greater than or equal to %s and less than or equal to %s'.format([rules.gte, rules.lte]) : ''
�
int32.gte_lte_exclusive�has(rules.lte) && rules.lte < rules.gte && (rules.lte < this && this < rules.gte)? 'value must be greater than or equal to %s or less than or equal to %s'.format([rules.gte, rules.lte]) : ''HRgtey
in (Bi�Hf
d
int32.inX!(this in dyn(rules)['in']) ? 'value must be in list %s'.format([dyn(rules)['in']]) : ''Rin}
not_in (Bf�Hc
a
int32.not_inQthis in rules.not_in ? 'value must not be in list %s'.format([rules.not_in]) : ''RnotInB
	less_thanB
greater_thanB
_const"�

Int64Rulesu
const (BZ�HW
U
int64.constFthis != rules.const ? 'value must equal %s'.format([rules.const]) : ''HRconst��
lt (B|�Hy
w
int64.ltk!has(rules.gte) && !has(rules.gt) && this >= rules.lt? 'value must be less than %s'.format([rules.lt]) : ''H Rlt�
lte (B��H�
�
	int64.ltex!has(rules.gte) && !has(rules.gt) && this > rules.lte? 'value must be less than or equal to %s'.format([rules.lte]) : ''H Rlte�
gt (B��H�
z
int64.gtn!has(rules.lt) && !has(rules.lte) && this <= rules.gt? 'value must be greater than %s'.format([rules.gt]) : ''
�
int64.gt_lt�has(rules.lt) && rules.lt >= rules.gt && (this >= rules.lt || this <= rules.gt)? 'value must be greater than %s and less than %s'.format([rules.gt, rules.lt]) : ''
�
int64.gt_lt_exclusive�has(rules.lt) && rules.lt < rules.gt && (rules.lt <= this && this <= rules.gt)? 'value must be greater than %s or less than %s'.format([rules.gt, rules.lt]) : ''
�
int64.gt_lte�has(rules.lte) && rules.lte >= rules.gt && (this > rules.lte || this <= rules.gt)? 'value must be greater than %s and less than or equal to %s'.format([rules.gt, rules.lte]) : ''
�
int64.gt_lte_exclusive�has(rules.lte) && rules.lte < rules.gt && (rules.lte < this && this <= rules.gt)? 'value must be greater than %s or less than or equal to %s'.format([rules.gt, rules.lte]) : ''HRgt�
gte (B��H�
�
	int64.gte{!has(rules.lt) && !has(rules.lte) && this < rules.gte? 'value must be greater than or equal to %s'.format([rules.gte]) : ''
�
int64.gte_lt�has(rules.lt) && rules.lt >= rules.gte && (this >= rules.lt || this < rules.gte)? 'value must be greater than or equal to %s and less than %s'.format([rules.gte, rules.lt]) : ''
�
int64.gte_lt_exclusive�has(rules.lt) && rules.lt < rules.gte && (rules.lt <= this && this < rules.gte)? 'value must be greater than or equal to %s or less than %s'.format([rules.gte, rules.lt]) : ''
�
int64.gte_lte�has(rules.lte) && rules.lte >= rules.gte && (this > rules.lte || this < rules.gte)? 'value must be greater than or equal to %s and less than or equal to %s'.format([rules.gte, rules.lte]) : ''
�
int64.gte_lte_exclusive�has(rules.lte) && rules.lte < rules.gte && (rules.lte < this && this < rules.gte)? 'value must be greater than or equal to %s or less than or equal to %s'.format([rules.gte, rules.lte]) : ''HRgtey
in (Bi�Hf
d
int64.inX!(this in dyn(rules)['in']) ? 'value must be in list %s'.format([dyn(rules)['in']]) : ''Rin}
not_in (Bf�Hc
a
int64.not_inQthis in rules.not_in ? 'value must not be in list %s'.format([rules.not_in]) : ''RnotInB
	less_thanB
greater_thanB
_const"�
UInt32Rulesv
const (B[�HX
V
uint32.constFthis != rules.const ? 'value must equal %s'.format([rules.const]) : ''HRconst��
lt (B}�Hz
x
	uint32.ltk!has(rules.gte) && !has(rules.gt) && this >= rules.lt? 'value must be less than %s'.format([rules.lt]) : ''H Rlt�
lte (B��H�
�

uint32.ltex!has(rules.gte) && !has(rules.gt) && this > rules.lte? 'value must be less than or equal to %s'.format([rules.lte]) : ''H Rlte�
gt (B��H�
{
	uint32.gtn!has(rules.lt) && !has(rules.lte) && this <= rules.gt? 'value must be greater than %s'.format([rules.gt]) : ''
�
uint32.gt_lt�has(rules.lt) && rules.lt >= rules.gt && (this >= rules.lt || this <= rules.gt)? 'value must be greater than %s and less than %s'.format([rules.gt, rules.lt]) : ''
�
uint32.gt_lt_exclusive�has(rules.lt) && rules.lt < rules.gt && (rules.lt <= this && this <= rules.gt)? 'value must be greater than %s or less than %s'.format([rules.gt, rules.lt]) : ''
�
uint32.gt_lte�has(rules.lte) && rules.lte >= rules.gt && (this > rules.lte || this <= rules.gt)? 'value must be greater than %s and less than or equal to %s'.format([rules.gt, rules.lte]) : ''
�
uint32.gt_lte_exclusive�has(rules.lte) && rules.lte < rules.gt && (rules.lte < this && this <= rules.gt)? 'value must be greater than %s or less than or equal to %s'.format([rules.gt, rules.lte]) : ''HRgt�
gte (B��H�
�

uint32.gte{!has(rules.lt) && !has(rules.lte) && this < rules.gte? 'value must be greater than or equal to %s'.format([rules.gte]) : ''
�
uint32.gte_lt�has(rules.lt) && rules.lt >= rules.gte && (this >= rules.lt || this < rules.gte)? 'value must be greater than or equal to %s and less than %s'.format([rules.gte, rules.lt]) : ''
�
uint32.gte_lt_exclusive�has(rules.lt) && rules.lt < rules.gte && (rules.lt <= this && this < rules.gte)? 'value must be greater than or equal to %s or less than %s'.format([rules.gte, rules.lt]) : ''
�
uint32.gte_lte�has(rules.lte) && rules.lte >= rules.gte && (this > rules.lte || this < rules.gte)? 'value must be greater than or equal to %s and less than or equal to %s'.format([rules.gte, rules.lte]) : ''
�
uint32.gte_lte_exclusive�has(rules.lte) && rules.lte < rules.gte && (rules.lte < this && this < rules.gte)? 'value must be greater than or equal to %s or less than or equal to %s'.format([rules.gte, rules.lte]) : ''HRgtez
in (Bj�Hg
e
	uint32.inX!(this in dyn(rules)['in']) ? 'value must be in list %s'.format([dyn(rules)['in']]) : ''Rin~
not_in (Bg�Hd
b
uint32.not_inQthis in rules.not_in ? 'value must not be in list %s'.format([rules.not_in]) : ''RnotInB
	less_thanB
greater_thanB
_const"�
UInt64Rulesv
const (B[�HX
V
uint64.constFthis != rules.const ? 'value must equal %s'.format([rules.const]) : ''HRconst��
lt (B}�Hz
x
	uint64.ltk!has(rules.gte) && !has(rules.gt) && this >= rules.lt? 'value must be less than %s'.format([rules.lt]) : ''H Rlt�
lte (B��H�
�

uint64.ltex!has(rules.gte) && !has(rules.gt) && this > rules.lte? 'value must be less than or equal to %s'.format([rules.lte]) : ''H Rlte�
gt (B��H�
{
	uint64.gtn!has(rules.lt) && !has(rules.lte) && this <= rules.gt? 'value must be greater than %s'.format([rules.gt]) : ''
�
uint64.gt_lt�has(rules.lt) && rules.lt >= rules.gt && (this >= rules.lt || this <= rules.gt)? 'value must be greater than %s and less than %s'.format([rules.gt, rules.lt]) : ''
�
uint64.gt_lt_exclusive�has(rules.lt) && rules.lt < rules.gt && (rules.lt <= this && this <= rules.gt)? 'value must be greater than %s or less than %s'.format([rules.gt, rules.lt]) : ''
�
uint64.gt_lte�has(rules.lte) && rules.lte >= rules.gt && (this > rules.lte || this <= rules.gt)? 'value must be greater than %s and less than or equal to %s'.format([rules.gt, rules.lte]) : ''
�
uint64.gt_lte_exclusive�has(rules.lte) && rules.lte < rules.gt && (rules.lte < this && this <= rules.gt)? 'value must be greater than %s or less than or equal to %s'.format([rules.gt, rules.lte]) : ''HRgt�
gte (B��H�
�

uint64.gte{!has(rules.lt) && !has(rules.lte) && this < rules.gte? 'value must be greater than or equal to %s'.format([rules.gte]) : ''
�
uint64.gte_lt�has(rules.lt) && rules.lt >= rules.gte && (this >= rules.lt || this < rules.gte)? 'value must be greater than or equal to %s and less than %s'.format([rules.gte, rules.lt]) : ''
�
uint64.gte_lt_exclusive�has(rules.lt) && rules.lt < rules.gte && (rules.lt <= this && this < rules.gte)? 'value must be greater than or equal to %s or less than %s'.format([rules.gte, rules.lt]) : ''
�
uint64.gte_lte�has(rules.lte) && rules.lte >= rules.gte && (this > rules.lte || this < rules.gte)? 'value must be greater than or equal to %s and less than or equal to %s'.format([rules.gte, rules.lte]) : ''
�
uint64.gte_lte_exclusive�has(rules.lte) && rules.lte < rules.gte && (rules.lte < this && this < rules.gte)? 'value must be greater than or equal to %s or less than or equal to %s'.format([rules.gte, rules.lte]) : ''HRgtez
in (Bj�Hg
e
	uint64.inX!(this in dyn(rules)['in']) ? 'value must be in list %s'.format([dyn(rules)['in']]) : ''Rin~
not_in (Bg�Hd
b
uint64.not_inQthis in rules.not_in ? 'value must not be in list %s'.format([rules.not_in]) : ''RnotInB
	less_thanB
greater_thanB
_const"�
SInt32Rulesv
const (B[�HX
V
sint32.constFthis != rules.const ? 'value must equal %s'.format([rules.const]) : ''HRconst��
lt (B}�Hz
x
	sint32.ltk!has(rules.gte) && !has(rules.gt) && this >= rules.lt? 'value must be less than %s'.format([rules.lt]) : ''H Rlt�
lte (B��H�
�

sint32.ltex!has(rules.gte) && !has(rules.gt) && this > rules.lte? 'value must be less than or equal to %s'.format([rules.lte]) : ''H Rlte�
gt (B��H�
{
	sint32.gtn!has(rules.lt) && !has(rules.lte) && this <= rules.gt? 'value must be greater than %s'.format([rules.gt]) : ''
�
sint32.gt_lt�has(rules.lt) && rules.lt >= rules.gt && (this >= rules.lt || this <= rules.gt)? 'value must be greater than %s and less than %s'.format([rules.gt, rules.lt]) : ''
�
sint32.gt_lt_exclusive�has(rules.lt) && rules.lt < rules.gt && (rules.lt <= this && this <= rules.gt)? 'value must be greater than %s or less than %s'.format([rules.gt, rules.lt]) : ''
�
sint32.gt_lte�has(rules.lte) && rules.lte >= rules.gt && (this > rules.lte || this <= rules.gt)? 'value must be greater than %s and less than or equal to %s'.format([rules.gt, rules.lte]) : ''
�
sint32.gt_lte_exclusive�has(rules.lte) && rules.lte < rules.gt && (rules.lte < this && this <= rules.gt)? 'value must be greater than %s or less than or equal to %s'.format([rules.gt, rules.lte]) : ''HRgt�
gte (B��H�
�

sint32.gte{!has(rules.lt) && !has(rules.lte) && this < rules.gte? 'value must be greater than or equal to %s'.format([rules.gte]) : ''
�
sint32.gte_lt�has(rules.lt) && rules.lt >= rules.gte && (this >= rules.lt || this < rules.gte)? 'value must be greater than or equal to %s and less than %s'.format([rules.gte, rules.lt]) : ''
�
sint32.gte_lt_exclusive�has(rules.lt) && rules.lt < rules.gte && (rules.lt <= this && this < rules.gte)? 'value must be greater than or equal to %s or less than %s'.format([rules.gte, rules.lt]) : ''
�
sint32.gte_lte�has(rules.lte) && rules.lte >= rules.gte && (this > rules.lte || this < rules.gte)? 'value must be greater than or equal to %s and less than or equal to %s'.format([rules.gte, rules.lte]) : ''
�
sint32.gte_lte_exclusive�has(rules.lte) && rules.lte < rules.gte && (rules.lte < this && this < rules.gte)? 'value must be greater than or equal to %s or less than or equal to %s'.format([rules.gte, rules.lte]) : ''HRgtez
in (Bj�Hg
e
	sint32.inX!(this in dyn(rules)['in']) ? 'value must be in list %s'.format([dyn(rules)['in']]) : ''Rin~
not_in (Bg�Hd
b
sint32.not_inQthis in rules.not_in ? 'value must not be in list %s'.format([rules.not_in]) : ''RnotInB
	less_thanB
greater_thanB
_const"�
SInt64Rulesv
const (B[�HX
V
sint64.constFthis != rules.const ? 'value must equal %s'.format([rules.const]) : ''HRconst��
lt (B}�Hz
x
	sint64.ltk!has(rules.gte) && !has(rules.gt) && this >= rules.lt? 'value must be less than %s'.format([rules.lt]) : ''H Rlt�
lte (B��H�
�

sint64.ltex!has(rules.gte) && !has(rules.gt) && this > rules.lte? 'value must be less than or equal to %s'.format([rules.lte]) : ''H Rlte�
gt (B��H�
{
	sint64.gtn!has(rules.lt) && !has(rules.lte) && this <= rules.gt? 'value must be greater than %s'.format([rules.gt]) : ''
�
sint64.gt_lt�has(rules.lt) && rules.lt >= rules.gt && (this >= rules.lt || this <= rules.gt)? 'value must be greater than %s and less than %s'.format([rules.gt, rules.lt]) : ''
�
sint64.gt_lt_exclusive�has(rules.lt) && rules.lt < rules.gt && (rules.lt <= this && this <= rules.gt)? 'value must be greater than %s or less than %s'.format([rules.gt, rules.lt]) : ''
�
sint64.gt_lte�has(rules.lte) && rules.lte >= rules.gt && (this > rules.lte || this <= rules.gt)? 'value must be greater than %s and less than or equal to %s'.format([rules.gt, rules.lte]) : ''
�
sint64.gt_lte_exclusive�has(rules.lte) && rules.lte < rules.gt && (rules.lte < this && this <= rules.gt)? 'value must be greater than %s or less than or equal to %s'.format([rules.gt, rules.lte]) : ''HRgt�
gte (B��H�
�

sint64.gte{!has(rules.lt) && !has(rules.lte) && this < rules.gte? 'value must be greater than or equal to %s'.format([rules.gte]) : ''
�
sint64.gte_lt�has(rules.lt) && rules.lt >= rules.gte && (this >= rules.lt || this < rules.gte)? 'value must be greater than or equal to %s and less than %s'.format([rules.gte, rules.lt]) : ''
�
sint64.gte_lt_exclusive�has(rules.lt) && rules.lt < rules.gte && (rules.lt <= this && this < rules.gte)? 'value must be greater than or equal to %s or less than %s'.format([rules.gte, rules.lt]) : ''
�
sint64.gte_lte�has(rules.lte) && rules.lte >= rules.gte && (this > rules.lte || this < rules.gte)? 'value must be greater than or equal to %s and less than or equal to %s'.format([rules.gte, rules.lte]) : ''
�
sint64.gte_lte_exclusive�has(rules.lte) && rules.lte < rules.gte && (rules.lte < this && this < rules.gte)? 'value must be greater than or equal to %s or less than or equal to %s'.format([rules.gte, rules.lte]) : ''HRgtez
in (Bj�Hg
e
	sint64.inX!(this in dyn(rules)['in']) ? 'value must be in list %s'.format([dyn(rules)['in']]) : ''Rin~
not_in (Bg�Hd
b
sint64.not_inQthis in rules.not_in ? 'value must not be in list %s'.format([rules.not_in]) : ''RnotInB
	less_thanB
greater_thanB
_const"�
Fixed32Rulesw
const (B\�HY
W
fixed32.constFthis != rules.const ? 'value must equal %s'.format([rules.const]) : ''HRconst��
lt (B~�H{
y

fixed32.ltk!has(rules.gte) && !has(rules.gt) && this >= rules.lt? 'value must be less than %s'.format([rules.lt]) : ''H Rlt�
lte (B��H�
�
fixed32.ltex!has(rules.gte) && !has(rules.gt) && this > rules.lte? 'value must be less than or equal to %s'.format([rules.lte]) : ''H Rlte�
gt (B��H�
|

fixed32.gtn!has(rules.lt) && !has(rules.lte) && this <= rules.gt? 'value must be greater than %s'.format([rules.gt]) : ''
�
fixed32.gt_lt�has(rules.lt) && rules.lt >= rules.gt && (this >= rules.lt || this <= rules.gt)? 'value must be greater than %s and less than %s'.format([rules.gt, rules.lt]) : ''
�
fixed32.gt_lt_exclusive�has(rules.lt) && rules.lt < rules.gt && (rules.lt <= this && this <= rules.gt)? 'value must be greater than %s or less than %s'.format([rules.gt, rules.lt]) : ''
�
fixed32.gt_lte�has(rules.lte) && rules.lte >= rules.gt && (this > rules.lte || this <= rules.gt)? 'value must be greater than %s and less than or equal to %s'.format([rules.gt, rules.lte]) : ''
�
fixed32.gt_lte_exclusive�has(rules.lte) && rules.lte < rules.gt && (rules.lte < this && this <= rules.gt)? 'value must be greater than %s or less than or equal to %s'.format([rules.gt, rules.lte]) : ''HRgt�
gte (B��H�
�
fixed32.gte{!has(rules.lt) && !has(rules.lte) && this < rules.gte? 'value must be greater than or equal to %s'.format([rules.gte]) : ''
�
fixed32.gte_lt�has(rules.lt) && rules.lt >= rules.gte && (this >= rules.lt || this < rules.gte)? 'value must be greater than or equal to %s and less than %s'.format([rules.gte, rules.lt]) : ''
�
fixed32.gte_lt_exclusive�has(rules.lt) && rules.lt < rules.gte && (rules.lt <= this && this < rules.gte)? 'value must be greater than or equal to %s or less than %s'.format([rules.gte, rules.lt]) : ''
�
fixed32.gte_lte�has(rules.lte) && rules.lte >= rules.gte && (this > rules.lte || this < rules.gte)? 'value must be greater than or equal to %s and less than or equal to %s'.format([rules.gte, rules.lte]) : ''
�
fixed32.gte_lte_exclusive�has(rules.lte) && rules.lte < rules.gte && (rules.lte < this && this < rules.gte)? 'value must be greater than or equal to %s or less than or equal to %s'.format([rules.gte, rules.lte]) : ''HRgte{
in (Bk�Hh
f

fixed32.inX!(this in dyn(rules)['in']) ? 'value must be in list %s'.format([dyn(rules)['in']]) : ''Rin
not_in (Bh�He
c
fixed32.not_inQthis in rules.not_in ? 'value must not be in list %s'.format([rules.not_in]) : ''RnotInB
	less_thanB
greater_thanB
_const"�
Fixed64Rulesw
const (B\�HY
W
fixed64.constFthis != rules.const ? 'value must equal %s'.format([rules.const]) : ''HRconst��
lt (B~�H{
y

fixed64.ltk!has(rules.gte) && !has(rules.gt) && this >= rules.lt? 'value must be less than %s'.format([rules.lt]) : ''H Rlt�
lte (B��H�
�
fixed64.ltex!has(rules.gte) && !has(rules.gt) && this > rules.lte? 'value must be less than or equal to %s'.format([rules.lte]) : ''H Rlte�
gt (B��H�
|

fixed64.gtn!has(rules.lt) && !has(rules.lte) && this <= rules.gt? 'value must be greater than %s'.format([rules.gt]) : ''
�
fixed64.gt_lt�has(rules.lt) && rules.lt >= rules.gt && (this >= rules.lt || this <= rules.gt)? 'value must be greater than %s and less than %s'.format([rules.gt, rules.lt]) : ''
�
fixed64.gt_lt_exclusive�has(rules.lt) && rules.lt < rules.gt && (rules.lt <= this && this <= rules.gt)? 'value must be greater than %s or less than %s'.format([rules.gt, rules.lt]) : ''
�
fixed64.gt_lte�has(rules.lte) && rules.lte >= rules.gt && (this > rules.lte || this <= rules.gt)? 'value must be greater than %s and less than or equal to %s'.format([rules.gt, rules.lte]) : ''
�
fixed64.gt_lte_exclusive�has(rules.lte) && rules.lte < rules.gt && (rules.lte < this && this <= rules.gt)? 'value must be greater than %s or less than or equal to %s'.format([rules.gt, rules.lte]) : ''HRgt�
gte (B��H�
�
fixed64.gte{!has(rules.lt) && !has(rules.lte) && this < rules.gte? 'value must be greater than or equal to %s'.format([rules.gte]) : ''
�
fixed64.gte_lt�has(rules.lt) && rules.lt >= rules.gte && (this >= rules.lt || this < rules.gte)? 'value must be greater than or equal to %s and less than %s'.format([rules.gte, rules.lt]) : ''
�
fixed64.gte_lt_exclusive�has(rules.lt) && rules.lt < rules.gte && (rules.lt <= this && this < rules.gte)? 'value must be greater than or equal to %s or less than %s'.format([rules.gte, rules.lt]) : ''
�
fixed64.gte_lte�has(rules.lte) && rules.lte >= rules.gte && (this > rules.lte || this < rules.gte)? 'value must be greater than or equal to %s and less than or equal to %s'.format([rules.gte, rules.lte]) : ''
�
fixed64.gte_lte_exclusive�has(rules.lte) && rules.lte < rules.gte && (rules.lte < this && this < rules.gte)? 'value must be greater than or equal to %s or less than or equal to %s'.format([rules.gte, rules.lte]) : ''HRgte{
in (Bk�Hh
f

fixed64.inX!(this in dyn(rules)['in']) ? 'value must be in list %s'.format([dyn(rules)['in']]) : ''Rin
not_in (Bh�He
c
fixed64.not_inQthis in rules.not_in ? 'value must not be in list %s'.format([rules.not_in]) : ''RnotInB
	less_thanB
greater_thanB
_const"�
SFixed32Rulesx
const (B]�HZ
X
sfixed32.constFthis != rules.const ? 'value must equal %s'.format([rules.const]) : ''HRconst��
lt (B�H|
z
sfixed32.ltk!has(rules.gte) && !has(rules.gt) && this >= rules.lt? 'value must be less than %s'.format([rules.lt]) : ''H Rlt�
lte (B��H�
�
sfixed32.ltex!has(rules.gte) && !has(rules.gt) && this > rules.lte? 'value must be less than or equal to %s'.format([rules.lte]) : ''H Rlte�
gt (B��H�
}
sfixed32.gtn!has(rules.lt) && !has(rules.lte) && this <= rules.gt? 'value must be greater than %s'.format([rules.gt]) : ''
�
sfixed32.gt_lt�has(rules.lt) && rules.lt >= rules.gt && (this >= rules.lt || this <= rules.gt)? 'value must be greater than %s and less than %s'.format([rules.gt, rules.lt]) : ''
�
sfixed32.gt_lt_exclusive�has(rules.lt) && rules.lt < rules.gt && (rules.lt <= this && this <= rules.gt)? 'value must be greater than %s or less than %s'.format([rules.gt, rules.lt]) : ''
�
sfixed32.gt_lte�has(rules.lte) && rules.lte >= rules.gt && (this > rules.lte || this <= rules.gt)? 'value must be greater than %s and less than or equal to %s'.format([rules.gt, rules.lte]) : ''
�
sfixed32.gt_lte_exclusive�has(rules.lte) && rules.lte < rules.gt && (rules.lte < this && this <= rules.gt)? 'value must be greater than %s or less than or equal to %s'.format([rules.gt, rules.lte]) : ''HRgt�
gte (B��H�
�
sfixed32.gte{!has(rules.lt) && !has(rules.lte) && this < rules.gte? 'value must be greater than or equal to %s'.format([rules.gte]) : ''
�
sfixed32.gte_lt�has(rules.lt) && rules.lt >= rules.gte && (this >= rules.lt || this < rules.gte)? 'value must be greater than or equal to %s and less than %s'.format([rules.gte, rules.lt]) : ''
�
sfixed32.gte_lt_exclusive�has(rules.lt) && rules.lt < rules.gte && (rules.lt <= this && this < rules.gte)? 'value must be greater than or equal to %s or less than %s'.format([rules.gte, rules.lt]) : ''
�
sfixed32.gte_lte�has(rules.lte) && rules.lte >= rules.gte && (this > rules.lte || this < rules.gte)? 'value must be greater than or equal to %s and less than or equal to %s'.format([rules.gte, rules.lte]) : ''
�
sfixed32.gte_lte_exclusive�has(rules.lte) && rules.lte < rules.gte && (rules.lte < this && this < rules.gte)? 'value must be greater than or equal to %s or less than or equal to %s'.format([rules.gte, rules.lte]) : ''HRgte|
in (Bl�Hi
g
sfixed32.inX!(this in dyn(rules)['in']) ? 'value must be in list %s'.format([dyn(rules)['in']]) : ''Rin�
not_in (Bi�Hf
d
sfixed32.not_inQthis in rules.not_in ? 'value must not be in list %s'.format([rules.not_in]) : ''RnotInB
	less_thanB
greater_thanB
_const"�
SFixed64Rulesx
const (B]�HZ
X
sfixed64.constFthis != rules.const ? 'value must equal %s'.format([rules.const]) : ''HRconst��
lt (B�H|
z
sfixed64.ltk!has(rules.gte) && !has(rules.gt) && this >= rules.lt? 'value must be less than %s'.format([rules.lt]) : ''H Rlt�
lte (B��H�
�
sfixed64.ltex!has(rules.gte) && !has(rules.gt) && this > rules.lte? 'value must be less than or equal to %s'.format([rules.lte]) : ''H Rlte�
gt (B��H�
}
sfixed64.gtn!has(rules.lt) && !has(rules.lte) && this <= rules.gt? 'value must be greater than %s'.format([rules.gt]) : ''
�
sfixed64.gt_lt�has(rules.lt) && rules.lt >= rules.gt && (this >= rules.lt || this <= rules.gt)? 'value must be greater than %s and less than %s'.format([rules.gt, rules.lt]) : ''
�
sfixed64.gt_lt_exclusive�has(rules.lt) && rules.lt < rules.gt && (rules.lt <= this && this <= rules.gt)? 'value must be greater than %s or less than %s'.format([rules.gt, rules.lt]) : ''
�
sfixed64.gt_lte�has(rules.lte) && rules.lte >= rules.gt && (this > rules.lte || this <= rules.gt)? 'value must be greater than %s and less than or equal to %s'.format([rules.gt, rules.lte]) : ''
�
sfixed64.gt_lte_exclusive�has(rules.lte) && rules.lte < rules.gt && (rules.lte < this && this <= rules.gt)? 'value must be greater than %s or less than or equal to %s'.format([rules.gt, rules.lte]) : ''HRgt�
gte (B��H�
�
sfixed64.gte{!has(rules.lt) && !has(rules.lte) && this < rules.gte? 'value must be greater than or equal to %s'.format([rules.gte]) : ''
�
sfixed64.gte_lt�has(rules.lt) && rules.lt >= rules.gte && (this >= rules.lt || this < rules.gte)? 'value must be greater than or equal to %s and less than %s'.format([rules.gte, rules.lt]) : ''
�
sfixed64.gte_lt_exclusive�has(rules.lt) && rules.lt < rules.gte && (rules.lt <= this && this < rules.gte)? 'value must be greater than or equal to %s or less than %s'.format([rules.gte, rules.lt]) : ''
�
sfixed64.gte_lte�has(rules.lte) && rules.lte >= rules.gte && (this > rules.lte || this < rules.gte)? 'value must be greater than or equal to %s and less than or equal to %s'.format([rules.gte, rules.lte]) : ''
�
sfixed64.gte_lte_exclusive�has(rules.lte) && rules.lte < rules.gte && (rules.lte < this && this < rules.gte)? 'value must be greater than or equal to %s or less than or equal to %s'.format([rules.gte, rules.lte]) : ''HRgte|
in (Bl�Hi
g
sfixed64.inX!(this in dyn(rules)['in']) ? 'value must be in list %s'.format([dyn(rules)['in']]) : ''Rin�
not_in (Bi�Hf
d
sfixed64.not_inQthis in rules.not_in ? 'value must not be in list %s'.format([rules.not_in]) : ''RnotInB
	less_thanB
greater_thanB
_const"�
	BoolRulest
const (BY�HV
T

bool.constFthis != rules.const ? 'value must equal %s'.format([rules.const]) : ''H Rconst�B
_const"�$
StringRulesx
const (	B]�HZ
X
string.constHthis != rules.const ? 'value must equal `%s`'.format([rules.const]) : ''HRconst��
len (Bq�Hn
l

string.len^uint(this.size()) != rules.len ? 'value length must be %s characters'.format([rules.len]) : ''HRlen��
min_len (B��H�
�
string.min_lennuint(this.size()) < rules.min_len ? 'value length must be at least %s characters'.format([rules.min_len]) : ''HRminLen��
max_len (B��H�

string.max_lenmuint(this.size()) > rules.max_len ? 'value length must be at most %s characters'.format([rules.max_len]) : ''HRmaxLen��
	len_bytes (B��H�
�
string.len_bytesluint(bytes(this).size()) != rules.len_bytes ? 'value length must be %s bytes'.format([rules.len_bytes]) : ''HRlenBytes��
	min_bytes (B��H�
�
string.min_bytestuint(bytes(this).size()) < rules.min_bytes ? 'value length must be at least %s bytes'.format([rules.min_bytes]) : ''HRminBytes��
	max_bytes (B��H�
�
string.max_bytessuint(bytes(this).size()) > rules.max_bytes ? 'value length must be at most %s bytes'.format([rules.max_bytes]) : ''HRmaxBytes��
pattern (	B|�Hy
w
string.patterne!this.matches(rules.pattern) ? 'value does not match regex pattern `%s`'.format([rules.pattern]) : ''HRpattern��
prefix (	Bt�Hq
o
string.prefix^!this.startsWith(rules.prefix) ? 'value does not have prefix `%s`'.format([rules.prefix]) : ''H	Rprefix��
suffix (	Br�Ho
m
string.suffix\!this.endsWith(rules.suffix) ? 'value does not have suffix `%s`'.format([rules.suffix]) : ''H
Rsuffix��
contains	 (	B~�H{
y
string.containsf!this.contains(rules.contains) ? 'value does not contain substring `%s`'.format([rules.contains]) : ''HRcontains��
not_contains (	B��H~
|
string.not_containsethis.contains(rules.not_contains) ? 'value contains substring `%s`'.format([rules.not_contains]) : ''HRnotContains�z
in
 (	Bj�Hg
e
	string.inX!(this in dyn(rules)['in']) ? 'value must be in list %s'.format([dyn(rules)['in']]) : ''Rin~
not_in (	Bg�Hd
b
string.not_inQthis in rules.not_in ? 'value must not be in list %s'.format([rules.not_in]) : ''RnotIn`
email (BH�HE
C
string.email#value must be a valid email addressthis.isEmail()H Remailg
hostname (BI�HF
D
string.hostnamevalue must be a valid hostnamethis.isHostname()H RhostnameQ
ip (B?�H<
:
	string.ip value must be a valid IP addressthis.isIp()H RipZ
ipv4 (BD�HA
?
string.ipv4"value must be a valid IPv4 addressthis.isIp(4)H Ripv4Z
ipv6 (BD�HA
?
string.ipv6"value must be a valid IPv6 addressthis.isIp(6)H Ripv6N
uri (B:�H7
5

string.urivalue must be a valid URIthis.isUri()H Ruri\
uri_ref (BA�H>
<
string.uri_refvalue must be a valid URIthis.isUriRef()H RuriRef�
address (Bf�Hc
a
string.address-value must be a valid hostname, or ip address this.isHostname() || this.isIp()H Raddress�
uuid (B��H�
�
string.uuid�!this.matches('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') ? 'value must be a valid UUID' : ''H Ruuid�
ip_with_prefixlen (BS�HP
N
string.ip_with_prefixlenvalue must be a valid IP prefixthis.isIpPrefix()H RipWithPrefixlen�
ipv4_with_prefixlen (Bl�Hi
g
string.ipv4_with_prefixlen5value must be a valid IPv4 address with prefix lengththis.isIpPrefix(4)H Ripv4WithPrefixlen�
ipv6_with_prefixlen (Bl�Hi
g
string.ipv6_with_prefixlen5value must be a valid IPv6 address with prefix lengththis.isIpPrefix(6)H Ripv6WithPrefixlenn
	ip_prefix (BO�HL
J
string.ip_prefixvalue must be a valid IP prefixthis.isIpPrefix(true)H RipPrefixy
ipv4_prefix (BV�HS
Q
string.ipv4_prefix!value must be a valid IPv4 prefixthis.isIpPrefix(4, true)H R
ipv4Prefixy
ipv6_prefix (BV�HS
Q
string.ipv6_prefix!value must be a valid IPv6 prefixthis.isIpPrefix(6, true)H R
ipv6Prefix�
well_known_regex (2.buf.validate.KnownRegexB��H�
�
#string.well_known_regex.header_name�rules.well_known_regex == 1 && !this.matches(!has(rules.strict) || rules.strict ?'^:?[0-9a-zA-Z!#$%&\'*+-.^_|~\x60]+$' :'^[^\u0000\u000A\u000D]+$') ? 'value must be a valid HTTP header name' : ''
�
$string.well_known_regex.header_value�rules.well_known_regex == 2 && !this.matches(!has(rules.strict) || rules.strict ?'^[^\u0000-\u0008\u000A-\u001F\u007F]*$' :'^[^\u0000\u000A\u000D]*$') ? 'value must be a valid HTTP header value' : ''H RwellKnownRegex
strict (HRstrict�B

well_knownB
_constB
_lenB

_min_lenB

_max_lenB

_len_bytesB

_min_bytesB

_max_bytesB

_patternB	
_prefixB	
_suffixB
	_containsB
_not_containsB	
_strict"�

BytesRulesr
const (BW�HT
R
bytes.constCthis != rules.const ? 'value must be %x'.format([rules.const]) : ''HRconst��
len (Bk�Hh
f
	bytes.lenYuint(this.size()) != rules.len ? 'value length must be %s bytes'.format([rules.len]) : ''HRlen��
min_len (B�H|
z
bytes.min_leniuint(this.size()) < rules.min_len ? 'value length must be at least %s bytes'.format([rules.min_len]) : ''HRminLen��
max_len (Bw�Ht
r
bytes.max_lenauint(this.size()) > rules.max_len ? 'value must be at most %s bytes'.format([rules.max_len]) : ''HRmaxLen��
pattern (	B�H|
z
bytes.patterni!string(this).matches(rules.pattern) ? 'value must match regex pattern `%s`'.format([rules.pattern]) : ''HRpattern��
prefix (Bq�Hn
l
bytes.prefix\!this.startsWith(rules.prefix) ? 'value does not have prefix %x'.format([rules.prefix]) : ''HRprefix��
suffix (Bo�Hl
j
bytes.suffixZ!this.endsWith(rules.suffix) ? 'value does not have suffix %x'.format([rules.suffix]) : ''HRsuffix��
contains (Bq�Hn
l
bytes.containsZ!this.contains(rules.contains) ? 'value does not contain %x'.format([rules.contains]) : ''HRcontains��
in (B��H�
�
bytes.inwdyn(rules)['in'].size() > 0 && !(this in dyn(rules)['in']) ? 'value must be in list %s'.format([dyn(rules)['in']]) : ''Rin}
not_in	 (Bf�Hc
a
bytes.not_inQthis in rules.not_in ? 'value must not be in list %s'.format([rules.not_in]) : ''RnotInr
ip
 (B`�H]
[
bytes.ipOthis.size() != 4 && this.size() != 16 ? 'value must be a valid IP address' : ''H Ripe
ipv4 (BO�HL
J

bytes.ipv4<this.size() != 4 ? 'value must be a valid IPv4 address' : ''H Ripv4f
ipv6 (BP�HM
K

bytes.ipv6=this.size() != 16 ? 'value must be a valid IPv6 address' : ''H Ripv6B

well_knownB
_constB
_lenB

_min_lenB

_max_lenB

_patternB	
_prefixB	
_suffixB
	_contains"�
	EnumRulest
const (BY�HV
T

enum.constFthis != rules.const ? 'value must equal %s'.format([rules.const]) : ''H Rconst�&
defined_only (HRdefinedOnly�x
in (Bh�He
c
enum.inX!(this in dyn(rules)['in']) ? 'value must be in list %s'.format([dyn(rules)['in']]) : ''Rin|
not_in (Be�Hb
`
enum.not_inQthis in rules.not_in ? 'value must not be in list %s'.format([rules.not_in]) : ''RnotInB
_constB
_defined_only"�
RepeatedRules�
	min_items (B��H�
�
repeated.min_itemsmuint(this.size()) < rules.min_items ? 'value must contain at least %d item(s)'.format([rules.min_items]) : ''H RminItems��
	max_items (B��H�
�
repeated.max_itemsquint(this.size()) > rules.max_items ? 'value must contain no more than %s item(s)'.format([rules.max_items]) : ''HRmaxItems�l
unique (BO�HL
J
repeated.unique(repeated value must contain unique itemsthis.unique()HRunique�9
items (2.buf.validate.FieldConstraintsHRitems�B

_min_itemsB

_max_itemsB	
_uniqueB
_items"�
MapRules�
	min_pairs (B|�Hy
w
map.min_pairsfuint(this.size()) < rules.min_pairs ? 'map must be at least %d entries'.format([rules.min_pairs]) : ''H RminPairs��
	max_pairs (B{�Hx
v
map.max_pairseuint(this.size()) > rules.max_pairs ? 'map must be at most %d entries'.format([rules.max_pairs]) : ''HRmaxPairs�7
keys (2.buf.validate.FieldConstraintsHRkeys�;
values (2.buf.validate.FieldConstraintsHRvalues�B

_min_pairsB

_max_pairsB
_keysB	
_values"1
AnyRules
in (	Rin
not_in (	RnotIn"�
DurationRules�
const (2.google.protobuf.DurationB]�HZ
X
duration.constFthis != rules.const ? 'value must equal %s'.format([rules.const]) : ''HRconst��
lt (2.google.protobuf.DurationB�H|
z
duration.ltk!has(rules.gte) && !has(rules.gt) && this >= rules.lt? 'value must be less than %s'.format([rules.lt]) : ''H Rlt�
lte (2.google.protobuf.DurationB��H�
�
duration.ltex!has(rules.gte) && !has(rules.gt) && this > rules.lte? 'value must be less than or equal to %s'.format([rules.lte]) : ''H Rlte�
gt (2.google.protobuf.DurationB��H�
}
duration.gtn!has(rules.lt) && !has(rules.lte) && this <= rules.gt? 'value must be greater than %s'.format([rules.gt]) : ''
�
duration.gt_lt�has(rules.lt) && rules.lt >= rules.gt && (this >= rules.lt || this <= rules.gt)? 'value must be greater than %s and less than %s'.format([rules.gt, rules.lt]) : ''
�
duration.gt_lt_exclusive�has(rules.lt) && rules.lt < rules.gt && (rules.lt <= this && this <= rules.gt)? 'value must be greater than %s or less than %s'.format([rules.gt, rules.lt]) : ''
�
duration.gt_lte�has(rules.lte) && rules.lte >= rules.gt && (this > rules.lte || this <= rules.gt)? 'value must be greater than %s and less than or equal to %s'.format([rules.gt, rules.lte]) : ''
�
duration.gt_lte_exclusive�has(rules.lte) && rules.lte < rules.gt && (rules.lte < this && this <= rules.gt)? 'value must be greater than %s or less than or equal to %s'.format([rules.gt, rules.lte]) : ''HRgt�
gte (2.google.protobuf.DurationB��H�
�
duration.gte{!has(rules.lt) && !has(rules.lte) && this < rules.gte? 'value must be greater than or equal to %s'.format([rules.gte]) : ''
�
duration.gte_lt�has(rules.lt) && rules.lt >= rules.gte && (this >= rules.lt || this < rules.gte)? 'value must be greater than or equal to %s and less than %s'.format([rules.gte, rules.lt]) : ''
�
duration.gte_lt_exclusive�has(rules.lt) && rules.lt < rules.gte && (rules.lt <= this && this < rules.gte)? 'value must be greater than or equal to %s or less than %s'.format([rules.gte, rules.lt]) : ''
�
duration.gte_lte�has(rules.lte) && rules.lte >= rules.gte && (this > rules.lte || this < rules.gte)? 'value must be greater than or equal to %s and less than or equal to %s'.format([rules.gte, rules.lte]) : ''
�
duration.gte_lte_exclusive�has(rules.lte) && rules.lte < rules.gte && (rules.lte < this && this < rules.gte)? 'value must be greater than or equal to %s or less than or equal to %s'.format([rules.gte, rules.lte]) : ''HRgte�
in (2.google.protobuf.DurationBl�Hi
g
duration.inX!(this in dyn(rules)['in']) ? 'value must be in list %s'.format([dyn(rules)['in']]) : ''Rin�
not_in (2.google.protobuf.DurationBi�Hf
d
duration.not_inQthis in rules.not_in ? 'value must not be in list %s'.format([rules.not_in]) : ''RnotInB
	less_thanB
greater_thanB
_const"�
TimestampRules�
const (2.google.protobuf.TimestampB^�H[
Y
timestamp.constFthis != rules.const ? 'value must equal %s'.format([rules.const]) : ''HRconst��
lt (2.google.protobuf.TimestampB��H}
{
timestamp.ltk!has(rules.gte) && !has(rules.gt) && this >= rules.lt? 'value must be less than %s'.format([rules.lt]) : ''H Rlt�
lte (2.google.protobuf.TimestampB��H�
�
timestamp.ltex!has(rules.gte) && !has(rules.gt) && this > rules.lte? 'value must be less than or equal to %s'.format([rules.lte]) : ''H Rltea
lt_now (BH�HE
C
timestamp.lt_now/this > now ? 'value must be less than now' : ''H RltNow�
gt (2.google.protobuf.TimestampB��H�
~
timestamp.gtn!has(rules.lt) && !has(rules.lte) && this <= rules.gt? 'value must be greater than %s'.format([rules.gt]) : ''
�
timestamp.gt_lt�has(rules.lt) && rules.lt >= rules.gt && (this >= rules.lt || this <= rules.gt)? 'value must be greater than %s and less than %s'.format([rules.gt, rules.lt]) : ''
�
timestamp.gt_lt_exclusive�has(rules.lt) && rules.lt < rules.gt && (rules.lt <= this && this <= rules.gt)? 'value must be greater than %s or less than %s'.format([rules.gt, rules.lt]) : ''
�
timestamp.gt_lte�has(rules.lte) && rules.lte >= rules.gt && (this > rules.lte || this <= rules.gt)? 'value must be greater than %s and less than or equal to %s'.format([rules.gt, rules.lte]) : ''
�
timestamp.gt_lte_exclusive�has(rules.lte) && rules.lte < rules.gt && (rules.lte < this && this <= rules.gt)? 'value must be greater than %s or less than or equal to %s'.format([rules.gt, rules.lte]) : ''HRgt�
gte (2.google.protobuf.TimestampB��H�
�
timestamp.gte{!has(rules.lt) && !has(rules.lte) && this < rules.gte? 'value must be greater than or equal to %s'.format([rules.gte]) : ''
�
timestamp.gte_lt�has(rules.lt) && rules.lt >= rules.gte && (this >= rules.lt || this < rules.gte)? 'value must be greater than or equal to %s and less than %s'.format([rules.gte, rules.lt]) : ''
�
timestamp.gte_lt_exclusive�has(rules.lt) && rules.lt < rules.gte && (rules.lt <= this && this < rules.gte)? 'value must be greater than or equal to %s or less than %s'.format([rules.gte, rules.lt]) : ''
�
timestamp.gte_lte�has(rules.lte) && rules.lte >= rules.gte && (this > rules.lte || this < rules.gte)? 'value must be greater than or equal to %s and less than or equal to %s'.format([rules.gte, rules.lte]) : ''
�
timestamp.gte_lte_exclusive�has(rules.lte) && rules.lte < rules.gte && (rules.lte < this && this < rules.gte)? 'value must be greater than or equal to %s or less than or equal to %s'.format([rules.gte, rules.lte]) : ''HRgted
gt_now (BK�HH
F
timestamp.gt_now2this < now ? 'value must be greater than now' : ''HRgtNow�
within	 (2.google.protobuf.DurationB��H�
�
timestamp.withinqthis < now-rules.within || this > now+rules.within ? 'value must be within %s of now'.format([rules.within]) : ''HRwithin�B
	less_thanB
greater_thanB
_constB	
_within*n

KnownRegex
KNOWN_REGEX_UNSPECIFIED  
KNOWN_REGEX_HTTP_HEADER_NAME!
KNOWN_REGEX_HTTP_HEADER_VALUE:_
message.google.protobuf.MessageOptions�	 (2 .buf.validate.MessageConstraintsRmessage�:W
oneof.google.protobuf.OneofOptions�	 (2.buf.validate.OneofConstraintsRoneof�:W
field.google.protobuf.FieldOptions�	 (2.buf.validate.FieldConstraintsRfield�Bn
build.buf.validateBValidateProtoPZGbuf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validateJ��
 �
�
 2� Copyright 2023 Buf Technologies, Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.


 
	
  '
	
 )
	
 *
	
 (
	
 )

 ^
	
 ^

 "
	

 "

 .
	
 .

 +
	
 +
�
! %� MessageOptions is an extension to google.protobuf.MessageOptions. It allows
 the addition of validation rules at the message level. These rules can be
 applied to incoming messages to ensure they meet certain criteria before
 being processed.

�
 $-{ Rules specify the validations to be performed on this message. By default,
 no validation is performed against a message.



 !%


 $



 $


 $%


 $(,
�
+ /� OneofOptions is an extension to google.protobuf.OneofOptions. It allows
 the addition of validation rules on a oneof. These rules can be
 applied to incoming messages to ensure they meet certain criteria before
 being processed.

�
.)w Rules specify the validations to be performed on this oneof. By default,
 no validation is performed against a oneof.



+#


.



.


.!


.$(
�
5 9� FieldOptions is an extension to google.protobuf.FieldOptions. It allows
 the addition of validation rules at the field level. These rules can be
 applied to incoming messages to ensure they meet certain criteria before
 being processed.

�
8)w Rules specify the validations to be performed on this field. By default,
 no validation is performed against a field.



5#


8



8


8!


8$(
�
 = Z� MessageConstraints represents validation rules that are applied to the entire message.
 It includes disabling options and a list of Constraint messages representing Common Expression Language (CEL) validation rules.



 =
�
  G� `disabled` is a boolean flag that, when set to true, nullifies any validation rules for this message.
 This includes any fields within the message that would otherwise support validation.

 ```proto
 message MyMessage {
   // validation will be bypassed for this message
   option (buf.validate.message).disabled = true;
 }
 ```


  G


  G

  G

  G
�
 Y� `cel` is a repeated field of type Constraint. Each Constraint specifies a validation rule to be applied to this message.
 These constraints are written in Common Expression Language (CEL) syntax. For more information on
 CEL, [see our documentation](https://github.com/bufbuild/protovalidate/blob/main/docs/cel.md).


 ```proto
 message MyMessage {
   // The field `foo` must be greater than 42.
   option (buf.validate.message).cel = {
     id: "my_message.value",
     message: "value must be greater than 42",
     expression: "this.foo > 42",
   };
   optional int32 foo = 1;
 }
 ```


 Y


 Y

 Y

 Y
�
^ qt The `OneofConstraints` message type enables you to manage constraints for
 oneof fields in your protobuf messages.



^
�
 p� If `required` is true, exactly one field of the oneof must be present. A
 validation error is returned if no fields in the oneof are present. The
 field itself may still be a default value; further constraints
 should be placed on the fields themselves to ensure they are valid values,
 such as `min_len` or `gt`.

 ```proto
 message MyMessage {
   oneof value {
     // Either `a` or `b` must be set. If `a` is set, it must also be
     // non-empty; whereas if `b` is set, it can still be an empty string.
     option (buf.validate.oneof).required = true;
     string a = 1 [(buf.validate.field).string.min_len = 1];
     string b = 2;
   }
 }
 ```


 p


 p

 p

 p
�
u �� FieldRules encapsulates the rules for each type of field. Depending on the
 field, the correct set should be used to ensure proper validations.



u
�
 �� `cel` is a repeated field used to represent a textual expression
 in the Common Expression Language (CEL) syntax. For more information on
 CEL, [see our documentation](https://github.com/bufbuild/protovalidate/blob/main/docs/cel.md).

 ```proto
 message MyMessage {
   // The field `value` must be greater than 42.
   optional int32 value = 1 [(buf.validate.field).cel = {
     id: "my_message.value",
     message: "value must be greater than 42",
     expression: "this > 42",
   }];
 }
 ```


 �


 �

 �

 �
�
�� `skipped` is an optional boolean attribute that specifies that the
 validation rules of this field should not be evaluated. If skipped is set to
 true, any validation rules set for the field will be ignored.

 ```proto
 message MyMessage {
   // The field `value` must not be set.
   optional MyOtherMessage value = 1 [(buf.validate.field).skipped = true];
 }
 ```


�

�

�
�
�� If `required` is true, the field must be populated. Field presence can be
 described as "serialized in the wire format," which follows the following rules:

 - the following "nullable" fields must be explicitly set to be considered present:
   - singular message fields (may be their empty value)
   - member fields of a oneof (may be their default value)
   - proto3 optional fields (may be their default value)
   - proto2 scalar fields
 - proto3 scalar fields must be non-zero to be considered present
 - repeated and map fields must be non-empty to be considered present

 ```proto
 message MyMessage {
   // The field `value` must be set to a non-null value.
   optional MyOtherMessage value = 1 [(buf.validate.field).required = true];
 }
 ```


�

�

�
�
�� If `ignore_empty` is true and applied to a non-nullable field (see
 `required` for more details), validation is skipped on the field if it is
 the default or empty value. Adding `ignore_empty` to a "nullable" field is
 a noop as these unset fields already skip validation (with the exception
 of `required`).

 ```proto
 message MyRepeated {
   // The field `value` min_len rule is only applied if the field isn't empty.
   repeated string value = 1 [
     (buf.validate.field).ignore_empty = true,
     (buf.validate.field).min_len = 5
   ];
 }
 ```


�

�

�

 ��

 �
"
� Scalar Field Types


�

�

�

�

�

�

�

�

�

�

�

�

�

�

�

�

�

�

�

	�

	�

	�

	�


�


�


�


�

�

�

�

�

�

�

�

�

�

�

�

�

� 

�

�

�

� 

�

�

�

�

�

�

�

�

�

�

�

�

�

�

�
#
� Complex Field Types


�

�

�

� 

�

�

�

�

�

�

�
&
� Well-Known Field Types


�

�

�

� 

�

�

�

�"

�

�

�!
�
� �� FloatRules describes the constraints applied to `float` values. These
 rules may also be applied to the `google.protobuf.FloatValue` Well-Known-Type.


�
�
 ��� `const` requires the field value to exactly match the specified value. If
 the field value doesn't match, an error message is generated.

 ```proto
 message MyFloat {
   // value must equal 42.0
   float value = 1 [(buf.validate.field).float.const = 42.0];
 }
 ```


 �


 �

 �

 �

 ��

	 �	 ��

 ��

 �
�
��� `lt` requires the field value to be less than the specified value (field <
 value). If the field value is equal to or greater than the specified value,
 an error message is generated.

 ```proto
 message MyFloat {
   // value must be less than 10.0
   float value = 1 [(buf.validate.field).float.lt = 10.0];
 }
 ```


�	

�


�

��

	�	 ��
�
��� `lte` requires the field value to be less than or equal to the specified
 value (field <= value). If the field value is greater than the specified
 value, an error message is generated.

 ```proto
 message MyFloat {
   // value must be less than or equal to 10.0
   float value = 1 [(buf.validate.field).float.lte = 10.0];
 }
 ```


�	

�


�

��

	�	 ��

��

�
�
��� `gt` requires the field value to be greater than the specified value
 (exclusive). If the value of `gt` is larger than a specified `lt` or
 `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MyFloat {
   // value must be greater than 5.0 [float.gt]
   float value = 1 [(buf.validate.field).float.gt = 5.0];

   // value must be greater than 5 and less than 10.0 [float.gt_lt]
   float other_value = 2 [(buf.validate.field).float = { gt: 5.0, lt: 10.0 }];

   // value must be greater than 10 or less than 5.0 [float.gt_lt_exclusive]
   float another_value = 3 [(buf.validate.field).float = { gt: 10.0, lt: 5.0 }];
 }
 ```


�	

�


�

��

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `gte` requires the field value to be greater than or equal to the specified
 value (exclusive). If the value of `gte` is larger than a specified `lt`
 or `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MyFloat {
   // value must be greater than or equal to 5.0 [float.gte]
   float value = 1 [(buf.validate.field).float.gte = 5.0];

   // value must be greater than or equal to 5.0 and less than 10.0 [float.gte_lt]
   float other_value = 2 [(buf.validate.field).float = { gte: 5.0, lt: 10.0 }];

   // value must be greater than or equal to 10.0 or less than 5.0 [float.gte_lt_exclusive]
   float another_value = 3 [(buf.validate.field).float = { gte: 10.0, lt: 5.0 }];
 }
 ```


�	

�


�

��

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `in` requires the field value to be equal to one of the specified values.
 If the field value isn't one of the specified values, an error message
 is generated.

 ```proto
 message MyFloat {
   // value must be in list [1.0, 2.0, 3.0]
   repeated float value = 1 (buf.validate.field).float = { in: [1.0, 2.0, 3.0] };
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `in` requires the field value to not be equal to any of the specified
 values. If the field value is one of the specified values, an error
 message is generated.

 ```proto
 message MyFloat {
   // value must not be in list [1.0, 2.0, 3.0]
   repeated float value = 1 (buf.validate.field).float = { not_in: [1.0, 2.0, 3.0] };
 }
 ```


�


�

�

�

��

	�	 ��
�
��x `finite` requires the field value to be finite. If the field value is
 infinite or NaN, an error message is generated.


�

�

�

��

	�	 ��
�
� �� DoubleRules describes the constraints applied to `double` values. These
 rules may also be applied to the `google.protobuf.DoubleValue` Well-Known-Type.


�
�
 ��� `const` requires the field value to exactly match the specified value. If
 the field value doesn't match, an error message is generated.

 ```proto
 message MyDouble {
   // value must equal 42.0
   double value = 1 [(buf.validate.field).double.const = 42.0];
 }
 ```


 �


 �

 �

 �

 ��

	 �	 ��

 ��

 �
�
��� `lt` requires the field value to be less than the specified value (field <
 value). If the field value is equal to or greater than the specified
 value, an error message is generated.

 ```proto
 message MyDouble {
   // value must be less than 10.0
   double value = 1 [(buf.validate.field).double.lt = 10.0];
 }
 ```


�


�

�

��

	�	 ��
�
��� `lte` requires the field value to be less than or equal to the specified value
 (field <= value). If the field value is greater than the specified value,
 an error message is generated.

 ```proto
 message MyDouble {
   // value must be less than or equal to 10.0
   double value = 1 [(buf.validate.field).double.lte = 10.0];
 }
 ```


�


�

�

��

	�	 ��

��

�
�
��� `gt` requires the field value to be greater than the specified value
 (exclusive). If the value of `gt` is larger than a specified `lt` or `lte`,
 the range is reversed, and the field value must be outside the specified
 range. If the field value doesn't meet the required conditions, an error
 message is generated.

 ```proto
 message MyDouble {
   // value must be greater than 5.0 [double.gt]
   double value = 1 [(buf.validate.field).double.gt = 5.0];

   // value must be greater than 5 and less than 10.0 [double.gt_lt]
   double other_value = 2 [(buf.validate.field).double = { gt: 5.0, lt: 10.0 }];

   // value must be greater than 10 or less than 5.0 [double.gt_lt_exclusive]
   double another_value = 3 [(buf.validate.field).double = { gt: 10.0, lt: 5.0 }];
 }
 ```


�


�

�

��

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `gte` requires the field value to be greater than or equal to the specified
 value (exclusive). If the value of `gte` is larger than a specified `lt` or
 `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MyDouble {
   // value must be greater than or equal to 5.0 [double.gte]
   double value = 1 [(buf.validate.field).double.gte = 5.0];

   // value must be greater than or equal to 5.0 and less than 10.0 [double.gte_lt]
   double other_value = 2 [(buf.validate.field).double = { gte: 5.0, lt: 10.0 }];

   // value must be greater than or equal to 10.0 or less than 5.0 [double.gte_lt_exclusive]
   double another_value = 3 [(buf.validate.field).double = { gte: 10.0, lt: 5.0 }];
 }
 ```


�


�

�

��

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `in` requires the field value to be equal to one of the specified values.
 If the field value isn't one of the specified values, an error message is
 generated.

 ```proto
 message MyDouble {
   // value must be in list [1.0, 2.0, 3.0]
   repeated double value = 1 (buf.validate.field).double = { in: [1.0, 2.0, 3.0] };
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `not_in` requires the field value to not be equal to any of the specified
 values. If the field value is one of the specified values, an error
 message is generated.

 ```proto
 message MyDouble {
   // value must not be in list [1.0, 2.0, 3.0]
   repeated double value = 1 (buf.validate.field).double = { not_in: [1.0, 2.0, 3.0] };
 }
 ```


�


�

�

�

��

	�	 ��
�
��x `finite` requires the field value to be finite. If the field value is
 infinite or NaN, an error message is generated.


�

�

�

��

	�	 ��
�
� �� Int32Rules describes the constraints applied to `int32` values. These
 rules may also be applied to the `google.protobuf.Int32Value` Well-Known-Type.


�
�
 ��� `const` requires the field value to exactly match the specified value. If
 the field value doesn't match, an error message is generated.

 ```proto
 message MyInt32 {
   // value must equal 42
   int32 value = 1 [(buf.validate.field).int32.const = 42];
 }
 ```


 �


 �

 �

 �

 ��

	 �	 ��

 ��

 �
�
��� `lt` requires the field value to be less than the specified value (field
 < value). If the field value is equal to or greater than the specified
 value, an error message is generated.

 ```proto
 message MyInt32 {
   // value must be less than 10
   int32 value = 1 [(buf.validate.field).int32.lt = 10];
 }
 ```


�	

�


�

��

	�	 ��
�
��� `lte` requires the field value to be less than or equal to the specified
 value (field <= value). If the field value is greater than the specified
 value, an error message is generated.

 ```proto
 message MyInt32 {
   // value must be less than or equal to 10
   int32 value = 1 [(buf.validate.field).int32.lte = 10];
 }
 ```


�	

�


�

��

	�	 ��

��

�
�
��� `gt` requires the field value to be greater than the specified value
 (exclusive). If the value of `gt` is larger than a specified `lt` or
 `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MyInt32 {
   // value must be greater than 5 [int32.gt]
   int32 value = 1 [(buf.validate.field).int32.gt = 5];

   // value must be greater than 5 and less than 10 [int32.gt_lt]
   int32 other_value = 2 [(buf.validate.field).int32 = { gt: 5, lt: 10 }];

   // value must be greater than 10 or less than 5 [int32.gt_lt_exclusive]
   int32 another_value = 3 [(buf.validate.field).int32 = { gt: 10, lt: 5 }];
 }
 ```


�	

�


�

��

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `gte` requires the field value to be greater than or equal to the specified value
 (exclusive). If the value of `gte` is larger than a specified `lt` or
 `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MyInt32 {
   // value must be greater than or equal to 5 [int32.gte]
   int32 value = 1 [(buf.validate.field).int32.gte = 5];

   // value must be greater than or equal to 5 and less than 10 [int32.gte_lt]
   int32 other_value = 2 [(buf.validate.field).int32 = { gte: 5, lt: 10 }];

   // value must be greater than or equal to 10 or less than 5 [int32.gte_lt_exclusive]
   int32 another_value = 3 [(buf.validate.field).int32 = { gte: 10, lt: 5 }];
 }
 ```


�	

�


�

��

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `in` requires the field value to be equal to one of the specified values.
 If the field value isn't one of the specified values, an error message is
 generated.

 ```proto
 message MyInt32 {
   // value must be in list [1, 2, 3]
   repeated int32 value = 1 (buf.validate.field).int32 = { in: [1, 2, 3] };
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `not_in` requires the field value to not be equal to any of the specified
 values. If the field value is one of the specified values, an error message
 is generated.

 ```proto
 message MyInt32 {
   // value must not be in list [1, 2, 3]
   repeated int32 value = 1 (buf.validate.field).int32 = { not_in: [1, 2, 3] };
 }
 ```


�


�

�

�

��

	�	 ��
�
� �� Int64Rules describes the constraints applied to `int64` values. These
 rules may also be applied to the `google.protobuf.Int64Value` Well-Known-Type.


�
�
 ��� `const` requires the field value to exactly match the specified value. If
 the field value doesn't match, an error message is generated.

 ```proto
 message MyInt64 {
   // value must equal 42
   int64 value = 1 [(buf.validate.field).int64.const = 42];
 }
 ```


 �


 �

 �

 �

 ��

	 �	 ��

 ��

 �
�
��� `lt` requires the field value to be less than the specified value (field <
 value). If the field value is equal to or greater than the specified value,
 an error message is generated.

 ```proto
 message MyInt64 {
   // value must be less than 10
   int64 value = 1 [(buf.validate.field).int64.lt = 10];
 }
 ```


�	

�


�

��

	�	 ��
�
��� `lte` requires the field value to be less than or equal to the specified
 value (field <= value). If the field value is greater than the specified
 value, an error message is generated.

 ```proto
 message MyInt64 {
   // value must be less than or equal to 10
   int64 value = 1 [(buf.validate.field).int64.lte = 10];
 }
 ```


�	

�


�

��

	�	 ��

��

�
�
��� `gt` requires the field value to be greater than the specified value
 (exclusive). If the value of `gt` is larger than a specified `lt` or
 `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MyInt64 {
   // value must be greater than 5 [int64.gt]
   int64 value = 1 [(buf.validate.field).int64.gt = 5];

   // value must be greater than 5 and less than 10 [int64.gt_lt]
   int64 other_value = 2 [(buf.validate.field).int64 = { gt: 5, lt: 10 }];

   // value must be greater than 10 or less than 5 [int64.gt_lt_exclusive]
   int64 another_value = 3 [(buf.validate.field).int64 = { gt: 10, lt: 5 }];
 }
 ```


�	

�


�

��

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `gte` requires the field value to be greater than or equal to the specified
 value (exclusive). If the value of `gte` is larger than a specified `lt`
 or `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MyInt64 {
   // value must be greater than or equal to 5 [int64.gte]
   int64 value = 1 [(buf.validate.field).int64.gte = 5];

   // value must be greater than or equal to 5 and less than 10 [int64.gte_lt]
   int64 other_value = 2 [(buf.validate.field).int64 = { gte: 5, lt: 10 }];

   // value must be greater than or equal to 10 or less than 5 [int64.gte_lt_exclusive]
   int64 another_value = 3 [(buf.validate.field).int64 = { gte: 10, lt: 5 }];
 }
 ```


�	

�


�

��

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `in` requires the field value to be equal to one of the specified values.
 If the field value isn't one of the specified values, an error message is
 generated.

 ```proto
 message MyInt64 {
   // value must be in list [1, 2, 3]
   repeated int64 value = 1 (buf.validate.field).int64 = { in: [1, 2, 3] };
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `not_in` requires the field value to not be equal to any of the specified
 values. If the field value is one of the specified values, an error
 message is generated.

 ```proto
 message MyInt64 {
   // value must not be in list [1, 2, 3]
   repeated int64 value = 1 (buf.validate.field).int64 = { not_in: [1, 2, 3] };
 }
 ```


�


�

�

�

��

	�	 ��
�
� �� UInt32Rules describes the constraints applied to `uint32` values. These
 rules may also be applied to the `google.protobuf.UInt32Value` Well-Known-Type.


�
�
 ��� `const` requires the field value to exactly match the specified value. If
 the field value doesn't match, an error message is generated.

 ```proto
 message MyUInt32 {
   // value must equal 42
   uint32 value = 1 [(buf.validate.field).uint32.const = 42];
 }
 ```


 �


 �

 �

 �

 ��

	 �	 ��

 ��

 �
�
��� `lt` requires the field value to be less than the specified value (field <
 value). If the field value is equal to or greater than the specified value,
 an error message is generated.

 ```proto
 message MyUInt32 {
   // value must be less than 10
   uint32 value = 1 [(buf.validate.field).uint32.lt = 10];
 }
 ```


�


�

�

��

	�	 ��
�
��� `lte` requires the field value to be less than or equal to the specified
 value (field <= value). If the field value is greater than the specified
 value, an error message is generated.

 ```proto
 message MyUInt32 {
   // value must be less than or equal to 10
   uint32 value = 1 [(buf.validate.field).uint32.lte = 10];
 }
 ```


�


�

�

��

	�	 ��

��

�
�
��� `gt` requires the field value to be greater than the specified value
 (exclusive). If the value of `gt` is larger than a specified `lt` or
 `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MyUInt32 {
   // value must be greater than 5 [uint32.gt]
   uint32 value = 1 [(buf.validate.field).uint32.gt = 5];

   // value must be greater than 5 and less than 10 [uint32.gt_lt]
   uint32 other_value = 2 [(buf.validate.field).uint32 = { gt: 5, lt: 10 }];

   // value must be greater than 10 or less than 5 [uint32.gt_lt_exclusive]
   uint32 another_value = 3 [(buf.validate.field).uint32 = { gt: 10, lt: 5 }];
 }
 ```


�


�

�

��

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `gte` requires the field value to be greater than or equal to the specified
 value (exclusive). If the value of `gte` is larger than a specified `lt`
 or `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MyUInt32 {
   // value must be greater than or equal to 5 [uint32.gte]
   uint32 value = 1 [(buf.validate.field).uint32.gte = 5];

   // value must be greater than or equal to 5 and less than 10 [uint32.gte_lt]
   uint32 other_value = 2 [(buf.validate.field).uint32 = { gte: 5, lt: 10 }];

   // value must be greater than or equal to 10 or less than 5 [uint32.gte_lt_exclusive]
   uint32 another_value = 3 [(buf.validate.field).uint32 = { gte: 10, lt: 5 }];
 }
 ```


�


�

�

��

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `in` requires the field value to be equal to one of the specified values.
 If the field value isn't one of the specified values, an error message is
 generated.

 ```proto
 message MyUInt32 {
   // value must be in list [1, 2, 3]
   repeated uint32 value = 1 (buf.validate.field).uint32 = { in: [1, 2, 3] };
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `not_in` requires the field value to not be equal to any of the specified
 values. If the field value is one of the specified values, an error
 message is generated.

 ```proto
 message MyUInt32 {
   // value must not be in list [1, 2, 3]
   repeated uint32 value = 1 (buf.validate.field).uint32 = { not_in: [1, 2, 3] };
 }
 ```


�


�

�

�

��

	�	 ��
�
�	 �
� UInt64Rules describes the constraints applied to `uint64` values. These
 rules may also be applied to the `google.protobuf.UInt64Value` Well-Known-Type.


�	
�
 �	�	� `const` requires the field value to exactly match the specified value. If
 the field value doesn't match, an error message is generated.

 ```proto
 message MyUInt64 {
   // value must equal 42
   uint64 value = 1 [(buf.validate.field).uint64.const = 42];
 }
 ```


 �	


 �	

 �	

 �	

 �	�	

	 �	 �	�	

 �	�	

 �	
�
�	�	� `lt` requires the field value to be less than the specified value (field <
 value). If the field value is equal to or greater than the specified value,
 an error message is generated.

 ```proto
 message MyUInt64 {
   // value must be less than 10
   uint64 value = 1 [(buf.validate.field).uint64.lt = 10];
 }
 ```


�	


�	

�	

�	�	

	�	 �	�	
�
�	�	� `lte` requires the field value to be less than or equal to the specified
 value (field <= value). If the field value is greater than the specified
 value, an error message is generated.

 ```proto
 message MyUInt64 {
   // value must be less than or equal to 10
   uint64 value = 1 [(buf.validate.field).uint64.lte = 10];
 }
 ```


�	


�	

�	

�	�	

	�	 �	�	

�	�


�	
�
�	�	� `gt` requires the field value to be greater than the specified value
 (exclusive). If the value of `gt` is larger than a specified `lt` or
 `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MyUInt64 {
   // value must be greater than 5 [uint64.gt]
   uint64 value = 1 [(buf.validate.field).uint64.gt = 5];

   // value must be greater than 5 and less than 10 [uint64.gt_lt]
   uint64 other_value = 2 [(buf.validate.field).uint64 = { gt: 5, lt: 10 }];

   // value must be greater than 10 or less than 5 [uint64.gt_lt_exclusive]
   uint64 another_value = 3 [(buf.validate.field).uint64 = { gt: 10, lt: 5 }];
 }
 ```


�	


�	

�	

�	�	

	�	 �	�	

	�	�	�	

	�	�	�	

	�	�	�	

	�	�	�	
�
�	�
� `gte` requires the field value to be greater than or equal to the specified
 value (exclusive). If the value of `gte` is larger than a specified `lt`
 or `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MyUInt64 {
   // value must be greater than or equal to 5 [uint64.gte]
   uint64 value = 1 [(buf.validate.field).uint64.gte = 5];

   // value must be greater than or equal to 5 and less than 10 [uint64.gte_lt]
   uint64 other_value = 2 [(buf.validate.field).uint64 = { gte: 5, lt: 10 }];

   // value must be greater than or equal to 10 or less than 5 [uint64.gte_lt_exclusive]
   uint64 another_value = 3 [(buf.validate.field).uint64 = { gte: 10, lt: 5 }];
 }
 ```


�	


�	

�	

�	�


	�	 �	�


	�	�
�


	�	�
�


	�	�
�


	�	�
�

�
�
�
� `in` requires the field value to be equal to one of the specified values.
 If the field value isn't one of the specified values, an error message is
 generated.

 ```proto
 message MyUInt64 {
   // value must be in list [1, 2, 3]
   repeated uint64 value = 1 (buf.validate.field).uint64 = { in: [1, 2, 3] };
 }
 ```


�



�


�


�


�
�


	�	 �
�

�
�
�
� `not_in` requires the field value to not be equal to any of the specified
 values. If the field value is one of the specified values, an error
 message is generated.

 ```proto
 message MyUInt64 {
   // value must not be in list [1, 2, 3]
   repeated uint64 value = 1 (buf.validate.field).uint64 = { not_in: [1, 2, 3] };
 }
 ```


�



�


�


�


�
�


	�	 �
�

Q
	�
 �C SInt32Rules describes the constraints applied to `sint32` values.


	�

�
	 �
�
� `const` requires the field value to exactly match the specified value. If
 the field value doesn't match, an error message is generated.

 ```proto
 message MySInt32 {
   // value must equal 42
   sint32 value = 1 [(buf.validate.field).sint32.const = 42];
 }
 ```


	 �



	 �


	 �


	 �


	 �
�


		 �	 �
�


	 �
�


	 �

�
	�
�
� `lt` requires the field value to be less than the specified value (field
 < value). If the field value is equal to or greater than the specified
 value, an error message is generated.

 ```proto
 message MySInt32 {
   // value must be less than 10
   sint32 value = 1 [(buf.validate.field).sint32.lt = 10];
 }
 ```


	�



	�


	�


	�
�


		�	 �
�

�
	�
�
� `lte` requires the field value to be less than or equal to the specified
 value (field <= value). If the field value is greater than the specified
 value, an error message is generated.

 ```proto
 message MySInt32 {
   // value must be less than or equal to 10
   sint32 value = 1 [(buf.validate.field).sint32.lte = 10];
 }
 ```


	�



	�


	�


	�
�


		�	 �
�


	�
�

	�

�
	�
�� `gt` requires the field value to be greater than the specified value
 (exclusive). If the value of `gt` is larger than a specified `lt` or
 `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MySInt32 {
   // value must be greater than 5 [sint32.gt]
   sint32 value = 1 [(buf.validate.field).sint32.gt = 5];

   // value must be greater than 5 and less than 10 [sint32.gt_lt]
   sint32 other_value = 2 [(buf.validate.field).sint32 = { gt: 5, lt: 10 }];

   // value must be greater than 10 or less than 5 [sint32.gt_lt_exclusive]
   sint32 another_value = 3 [(buf.validate.field).sint32 = { gt: 10, lt: 5 }];
 }
 ```


	�



	�


	�


	�
�

		�	 ��

		�	��

		�	��

		�	��

		�	��
�
	��� `gte` requires the field value to be greater than or equal to the specified
 value (exclusive). If the value of `gte` is larger than a specified `lt`
 or `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MySInt32 {
  // value must be greater than or equal to 5 [sint32.gte]
  sint32 value = 1 [(buf.validate.field).sint32.gte = 5];

  // value must be greater than or equal to 5 and less than 10 [sint32.gte_lt]
  sint32 other_value = 2 [(buf.validate.field).sint32 = { gte: 5, lt: 10 }];

  // value must be greater than or equal to 10 or less than 5 [sint32.gte_lt_exclusive]
  sint32 another_value = 3 [(buf.validate.field).sint32 = { gte: 10, lt: 5 }];
 }
 ```


	�


	�

	�

	��

		�	 ��

		�	��

		�	��

		�	��

		�	��
�
	��� `in` requires the field value to be equal to one of the specified values.
 If the field value isn't one of the specified values, an error message is
 generated.

 ```proto
 message MySInt32 {
   // value must be in list [1, 2, 3]
   repeated sint32 value = 1 (buf.validate.field).sint32 = { in: [1, 2, 3] };
 }
 ```


	�


	�

	�

	�

	��

		�	 ��
�
	��� `not_in` requires the field value to not be equal to any of the specified
 values. If the field value is one of the specified values, an error
 message is generated.

 ```proto
 message MySInt32 {
   // value must not be in list [1, 2, 3]
   repeated sint32 value = 1 (buf.validate.field).sint32 = { not_in: [1, 2, 3] };
 }
 ```


	�


	�

	�

	�

	��

		�	 ��
Q

� �C SInt64Rules describes the constraints applied to `sint64` values.



�
�

 ��� `const` requires the field value to exactly match the specified value. If
 the field value doesn't match, an error message is generated.

 ```proto
 message MySInt64 {
   // value must equal 42
   sint64 value = 1 [(buf.validate.field).sint64.const = 42];
 }
 ```



 �



 �


 �


 �


 ��

	
 �	 ��


 ��


 �
�

��� `lt` requires the field value to be less than the specified value (field
 < value). If the field value is equal to or greater than the specified
 value, an error message is generated.

 ```proto
 message MySInt64 {
   // value must be less than 10
   sint64 value = 1 [(buf.validate.field).sint64.lt = 10];
 }
 ```



�



�


�


��

	
�	 ��
�

��� `lte` requires the field value to be less than or equal to the specified
 value (field <= value). If the field value is greater than the specified
 value, an error message is generated.

 ```proto
 message MySInt64 {
   // value must be less than or equal to 10
   sint64 value = 1 [(buf.validate.field).sint64.lte = 10];
 }
 ```



�



�


�


��

	
�	 ��


��


�
�

��� `gt` requires the field value to be greater than the specified value
 (exclusive). If the value of `gt` is larger than a specified `lt` or
 `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MySInt64 {
   // value must be greater than 5 [sint64.gt]
   sint64 value = 1 [(buf.validate.field).sint64.gt = 5];

   // value must be greater than 5 and less than 10 [sint64.gt_lt]
   sint64 other_value = 2 [(buf.validate.field).sint64 = { gt: 5, lt: 10 }];

   // value must be greater than 10 or less than 5 [sint64.gt_lt_exclusive]
   sint64 another_value = 3 [(buf.validate.field).sint64 = { gt: 10, lt: 5 }];
 }
 ```



�



�


�


��

	
�	 ��

	
�	��

	
�	��

	
�	��

	
�	��
�

��� `gte` requires the field value to be greater than or equal to the specified
 value (exclusive). If the value of `gte` is larger than a specified `lt`
 or `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MySInt64 {
   // value must be greater than or equal to 5 [sint64.gte]
   sint64 value = 1 [(buf.validate.field).sint64.gte = 5];

   // value must be greater than or equal to 5 and less than 10 [sint64.gte_lt]
   sint64 other_value = 2 [(buf.validate.field).sint64 = { gte: 5, lt: 10 }];

   // value must be greater than or equal to 10 or less than 5 [sint64.gte_lt_exclusive]
   sint64 another_value = 3 [(buf.validate.field).sint64 = { gte: 10, lt: 5 }];
 }
 ```



�



�


�


��

	
�	 ��

	
�	��

	
�	��

	
�	��

	
�	��
�

��� `in` requires the field value to be equal to one of the specified values.
 If the field value isn't one of the specified values, an error message
 is generated.

 ```proto
 message MySInt64 {
   // value must be in list [1, 2, 3]
   repeated sint64 value = 1 (buf.validate.field).sint64 = { in: [1, 2, 3] };
 }
 ```



�



�


�


�


��

	
�	 ��
�

��� `not_in` requires the field value to not be equal to any of the specified
 values. If the field value is one of the specified values, an error
 message is generated.

 ```proto
 message MySInt64 {
   // value must not be in list [1, 2, 3]
   repeated sint64 value = 1 (buf.validate.field).sint64 = { not_in: [1, 2, 3] };
 }
 ```



�



�


�


�


��

	
�	 ��
S
� �E Fixed32Rules describes the constraints applied to `fixed32` values.


�
�
 ��� `const` requires the field value to exactly match the specified value.
 If the field value doesn't match, an error message is generated.

 ```proto
 message MyFixed32 {
   // value must equal 42
   fixed32 value = 1 [(buf.validate.field).fixed32.const = 42];
 }
 ```


 �


 �

 �

 �

 ��

	 �	 ��

 ��

 �
�
��� `lt` requires the field value to be less than the specified value (field <
 value). If the field value is equal to or greater than the specified value,
 an error message is generated.

 ```proto
 message MyFixed32 {
   // value must be less than 10
   fixed32 value = 1 [(buf.validate.field).fixed32.lt = 10];
 }
 ```


�

�

�

��

	�	 ��
�
��� `lte` requires the field value to be less than or equal to the specified
 value (field <= value). If the field value is greater than the specified
 value, an error message is generated.

 ```proto
 message MyFixed32 {
   // value must be less than or equal to 10
   fixed32 value = 1 [(buf.validate.field).fixed32.lte = 10];
 }
 ```


�

�

�

��

	�	 ��

��

�
�
��� `gt` requires the field value to be greater than the specified value
 (exclusive). If the value of `gt` is larger than a specified `lt` or
 `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MyFixed32 {
   // value must be greater than 5 [fixed32.gt]
   fixed32 value = 1 [(buf.validate.field).fixed32.gt = 5];

   // value must be greater than 5 and less than 10 [fixed32.gt_lt]
   fixed32 other_value = 2 [(buf.validate.field).fixed32 = { gt: 5, lt: 10 }];

   // value must be greater than 10 or less than 5 [fixed32.gt_lt_exclusive]
   fixed32 another_value = 3 [(buf.validate.field).fixed32 = { gt: 10, lt: 5 }];
 }
 ```


�

�

�

��

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `gte` requires the field value to be greater than or equal to the specified
 value (exclusive). If the value of `gte` is larger than a specified `lt`
 or `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MyFixed32 {
   // value must be greater than or equal to 5 [fixed32.gte]
   fixed32 value = 1 [(buf.validate.field).fixed32.gte = 5];

   // value must be greater than or equal to 5 and less than 10 [fixed32.gte_lt]
   fixed32 other_value = 2 [(buf.validate.field).fixed32 = { gte: 5, lt: 10 }];

   // value must be greater than or equal to 10 or less than 5 [fixed32.gte_lt_exclusive]
   fixed32 another_value = 3 [(buf.validate.field).fixed32 = { gte: 10, lt: 5 }];
 }
 ```


�

�

�

��

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `in` requires the field value to be equal to one of the specified values.
 If the field value isn't one of the specified values, an error message
 is generated.

 ```proto
 message MyFixed32 {
   // value must be in list [1, 2, 3]
   repeated fixed32 value = 1 (buf.validate.field).fixed32 = { in: [1, 2, 3] };
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `not_in` requires the field value to not be equal to any of the specified
 values. If the field value is one of the specified values, an error
 message is generated.

 ```proto
 message MyFixed32 {
   // value must not be in list [1, 2, 3]
   repeated fixed32 value = 1 (buf.validate.field).fixed32 = { not_in: [1, 2, 3] };
 }
 ```


�


�

�

�

��

	�	 ��
S
� �E Fixed64Rules describes the constraints applied to `fixed64` values.


�
�
 ��� `const` requires the field value to exactly match the specified value. If
 the field value doesn't match, an error message is generated.

 ```proto
 message MyFixed64 {
   // value must equal 42
   fixed64 value = 1 [(buf.validate.field).fixed64.const = 42];
 }
 ```


 �


 �

 �

 �

 ��

	 �	 ��

 ��

 �
�
��� `lt` requires the field value to be less than the specified value (field <
 value). If the field value is equal to or greater than the specified value,
 an error message is generated.

 ```proto
 message MyFixed64 {
   // value must be less than 10
   fixed64 value = 1 [(buf.validate.field).fixed64.lt = 10];
 }
 ```


�

�

�

��

	�	 ��
�
��� `lte` requires the field value to be less than or equal to the specified
 value (field <= value). If the field value is greater than the specified
 value, an error message is generated.

 ```proto
 message MyFixed64 {
   // value must be less than or equal to 10
   fixed64 value = 1 [(buf.validate.field).fixed64.lte = 10];
 }
 ```


�

�

�

��

	�	 ��

��

�
�
��� `gt` requires the field value to be greater than the specified value
 (exclusive). If the value of `gt` is larger than a specified `lt` or
 `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MyFixed64 {
   // value must be greater than 5 [fixed64.gt]
   fixed64 value = 1 [(buf.validate.field).fixed64.gt = 5];

   // value must be greater than 5 and less than 10 [fixed64.gt_lt]
   fixed64 other_value = 2 [(buf.validate.field).fixed64 = { gt: 5, lt: 10 }];

   // value must be greater than 10 or less than 5 [fixed64.gt_lt_exclusive]
   fixed64 another_value = 3 [(buf.validate.field).fixed64 = { gt: 10, lt: 5 }];
 }
 ```


�

�

�

��

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `gte` requires the field value to be greater than or equal to the specified
 value (exclusive). If the value of `gte` is larger than a specified `lt`
 or `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MyFixed64 {
   // value must be greater than or equal to 5 [fixed64.gte]
   fixed64 value = 1 [(buf.validate.field).fixed64.gte = 5];

   // value must be greater than or equal to 5 and less than 10 [fixed64.gte_lt]
   fixed64 other_value = 2 [(buf.validate.field).fixed64 = { gte: 5, lt: 10 }];

   // value must be greater than or equal to 10 or less than 5 [fixed64.gte_lt_exclusive]
   fixed64 another_value = 3 [(buf.validate.field).fixed64 = { gte: 10, lt: 5 }];
 }
 ```


�

�

�

��

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `in` requires the field value to be equal to one of the specified values.
 If the field value isn't one of the specified values, an error message is
 generated.

 ```proto
 message MyFixed64 {
   // value must be in list [1, 2, 3]
   repeated fixed64 value = 1 (buf.validate.field).fixed64 = { in: [1, 2, 3] };
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `not_in` requires the field value to not be equal to any of the specified
 values. If the field value is one of the specified values, an error
 message is generated.

 ```proto
 message MyFixed64 {
   // value must not be in list [1, 2, 3]
   repeated fixed64 value = 1 (buf.validate.field).fixed64 = { not_in: [1, 2, 3] };
 }
 ```


�


�

�

�

��

	�	 ��
T
� �F SFixed32Rules describes the constraints applied to `fixed32` values.


�
�
 ��� `const` requires the field value to exactly match the specified value. If
 the field value doesn't match, an error message is generated.

 ```proto
 message MySFixed32 {
   // value must equal 42
   sfixed32 value = 1 [(buf.validate.field).sfixed32.const = 42];
 }
 ```


 �


 �

 �

 �

 ��

	 �	 ��

 ��

 �
�
��� `lt` requires the field value to be less than the specified value (field <
 value). If the field value is equal to or greater than the specified value,
 an error message is generated.

 ```proto
 message MySFixed32 {
   // value must be less than 10
   sfixed32 value = 1 [(buf.validate.field).sfixed32.lt = 10];
 }
 ```


�

�

�

��

	�	 ��
�
��� `lte` requires the field value to be less than or equal to the specified
 value (field <= value). If the field value is greater than the specified
 value, an error message is generated.

 ```proto
 message MySFixed32 {
   // value must be less than or equal to 10
   sfixed32 value = 1 [(buf.validate.field).sfixed32.lte = 10];
 }
 ```


�

�

�

��

	�	 ��

��

�
�
��� `gt` requires the field value to be greater than the specified value
 (exclusive). If the value of `gt` is larger than a specified `lt` or
 `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MySFixed32 {
   // value must be greater than 5 [sfixed32.gt]
   sfixed32 value = 1 [(buf.validate.field).sfixed32.gt = 5];

   // value must be greater than 5 and less than 10 [sfixed32.gt_lt]
   sfixed32 other_value = 2 [(buf.validate.field).sfixed32 = { gt: 5, lt: 10 }];

   // value must be greater than 10 or less than 5 [sfixed32.gt_lt_exclusive]
   sfixed32 another_value = 3 [(buf.validate.field).sfixed32 = { gt: 10, lt: 5 }];
 }
 ```


�

�

�

��

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `gte` requires the field value to be greater than or equal to the specified
 value (exclusive). If the value of `gte` is larger than a specified `lt`
 or `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MySFixed32 {
   // value must be greater than or equal to 5 [sfixed32.gte]
   sfixed32 value = 1 [(buf.validate.field).sfixed32.gte = 5];

   // value must be greater than or equal to 5 and less than 10 [sfixed32.gte_lt]
   sfixed32 other_value = 2 [(buf.validate.field).sfixed32 = { gte: 5, lt: 10 }];

   // value must be greater than or equal to 10 or less than 5 [sfixed32.gte_lt_exclusive]
   sfixed32 another_value = 3 [(buf.validate.field).sfixed32 = { gte: 10, lt: 5 }];
 }
 ```


�

�

�

��

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `in` requires the field value to be equal to one of the specified values.
 If the field value isn't one of the specified values, an error message is
 generated.

 ```proto
 message MySFixed32 {
   // value must be in list [1, 2, 3]
   repeated sfixed32 value = 1 (buf.validate.field).sfixed32 = { in: [1, 2, 3] };
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `not_in` requires the field value to not be equal to any of the specified
 values. If the field value is one of the specified values, an error
 message is generated.

 ```proto
 message MySFixed32 {
   // value must not be in list [1, 2, 3]
   repeated sfixed32 value = 1 (buf.validate.field).sfixed32 = { not_in: [1, 2, 3] };
 }
 ```


�


�

�

�

��

	�	 � �
T
� �F SFixed64Rules describes the constraints applied to `fixed64` values.


�
�
 ��� `const` requires the field value to exactly match the specified value. If
 the field value doesn't match, an error message is generated.

 ```proto
 message MySFixed64 {
   // value must equal 42
   sfixed64 value = 1 [(buf.validate.field).sfixed64.const = 42];
 }
 ```


 �


 �

 �

 �

 ��

	 �	 ��

 ��

 �
�
��� `lt` requires the field value to be less than the specified value (field <
 value). If the field value is equal to or greater than the specified value,
 an error message is generated.

 ```proto
 message MySFixed64 {
   // value must be less than 10
   sfixed64 value = 1 [(buf.validate.field).sfixed64.lt = 10];
 }
 ```


�

�

�

��

	�	 ��
�
��� `lte` requires the field value to be less than or equal to the specified
 value (field <= value). If the field value is greater than the specified
 value, an error message is generated.

 ```proto
 message MySFixed64 {
   // value must be less than or equal to 10
   sfixed64 value = 1 [(buf.validate.field).sfixed64.lte = 10];
 }
 ```


�

�

�

��

	�	 ��

��

�
�
��� `gt` requires the field value to be greater than the specified value
 (exclusive). If the value of `gt` is larger than a specified `lt` or
 `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MySFixed64 {
   // value must be greater than 5 [sfixed64.gt]
   sfixed64 value = 1 [(buf.validate.field).sfixed64.gt = 5];

   // value must be greater than 5 and less than 10 [sfixed64.gt_lt]
   sfixed64 other_value = 2 [(buf.validate.field).sfixed64 = { gt: 5, lt: 10 }];

   // value must be greater than 10 or less than 5 [sfixed64.gt_lt_exclusive]
   sfixed64 another_value = 3 [(buf.validate.field).sfixed64 = { gt: 10, lt: 5 }];
 }
 ```


�

�

�

��

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `gte` requires the field value to be greater than or equal to the specified
 value (exclusive). If the value of `gte` is larger than a specified `lt`
 or `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MySFixed64 {
   // value must be greater than or equal to 5 [sfixed64.gte]
   sfixed64 value = 1 [(buf.validate.field).sfixed64.gte = 5];

   // value must be greater than or equal to 5 and less than 10 [sfixed64.gte_lt]
   sfixed64 other_value = 2 [(buf.validate.field).sfixed64 = { gte: 5, lt: 10 }];

   // value must be greater than or equal to 10 or less than 5 [sfixed64.gte_lt_exclusive]
   sfixed64 another_value = 3 [(buf.validate.field).sfixed64 = { gte: 10, lt: 5 }];
 }
 ```


�

�

�

��

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `in` requires the field value to be equal to one of the specified values.
 If the field value isn't one of the specified values, an error message is
 generated.

 ```proto
 message MySFixed64 {
   // value must be in list [1, 2, 3]
   repeated sfixed64 value = 1 (buf.validate.field).sfixed64 = { in: [1, 2, 3] };
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `not_in` requires the field value to not be equal to any of the specified
 values. If the field value is one of the specified values, an error
 message is generated.

 ```proto
 message MySFixed64 {
   // value must not be in list [1, 2, 3]
   repeated sfixed64 value = 1 (buf.validate.field).sfixed64 = { not_in: [1, 2, 3] };
 }
 ```


�


�

�

�

��

	�	 � �
�
� �� BoolRules describes the constraints applied to `bool` values. These rules
 may also be applied to the `google.protobuf.BoolValue` Well-Known-Type.


�
�
 ��� `const` requires the field value to exactly match the specified boolean value.
 If the field value doesn't match, an error message is generated.

 ```proto
 message MyBool {
   // value must equal true
   bool value = 1 [(buf.validate.field).bool.const = true];
 }
 ```


 �


 �

 �

 �

 ��

	 �	 ��
�
� �� StringRules describes the constraints applied to `string` values These
 rules may also be applied to the `google.protobuf.StringValue` Well-Known-Type.


�
�
 ��� `const` requires the field value to exactly match the specified value. If
 the field value doesn't match, an error message is generated.

 ```proto
 message MyString {
   // value must equal `hello`
   string value = 1 [(buf.validate.field).string.const = "hello"];
 }
 ```


 �


 �

 �

 �

 ��

	 �	 ��
�
��� `len` dictates that the field value must have the specified
 number of characters (Unicode code points), which may differ from the number
 of bytes in the string. If the field value does not meet the specified
 length, an error message will be generated.

 ```proto
 message MyString {
   // value length must be 5 characters
   string value = 1 [(buf.validate.field).string.len = 5];
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `min_len` specifies that the field value must have at least the specified
 number of characters (Unicode code points), which may differ from the number
 of bytes in the string. If the field value contains fewer characters, an error
 message will be generated.

 ```proto
 message MyString {
   // value length must be at least 3 characters
   string value = 1 [(buf.validate.field).string.min_len = 3];
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `max_len` specifies that the field value must have no more than the specified
 number of characters (Unicode code points), which may differ from the
 number of bytes in the string. If the field value contains more characters,
 an error message will be generated.

 ```proto
 message MyString {
   // value length must be at most 10 characters
   string value = 1 [(buf.validate.field).string.max_len = 10];
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `len_bytes` dictates that the field value must have the specified number of
 bytes. If the field value does not match the specified length in bytes,
 an error message will be generated.

 ```proto
 message MyString {
   // value length must be 6 bytes
   string value = 1 [(buf.validate.field).string.len_bytes = 6];
 }
 ```


�


�

�

� 

�!�

	�	 �"�
�
��� `min_bytes` specifies that the field value must have at least the specified
 number of bytes. If the field value contains fewer bytes, an error message
 will be generated.

 ```proto
 message MyString {
   // value length must be at least 4 bytes
   string value = 1 [(buf.validate.field).string.min_bytes = 4];
 }

 ```


�


�

�

�

� �

	�	 �!�
�
��� `max_bytes` specifies that the field value must have no more than the
specified number of bytes. If the field value contains more bytes, an
 error message will be generated.

 ```proto
 message MyString {
   // value length must be at most 8 bytes
   string value = 1 [(buf.validate.field).string.max_bytes = 8];
 }
 ```


�


�

�

�

� �

	�	 �!�
�
��� `pattern` specifies that the field value must match the specified
 regular expression (RE2 syntax), with the expression provided without any
 delimiters. If the field value doesn't match the regular expression, an
 error message will be generated.

 ```proto
 message MyString {
   // value does not match regex pattern `^[a-zA-Z]//$`
   string value = 1 [(buf.validate.field).string.pattern = "^[a-zA-Z]//$"];
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `prefix` specifies that the field value must have the
specified substring at the beginning of the string. If the field value
 doesn't start with the specified prefix, an error message will be
 generated.

 ```proto
 message MyString {
   // value does not have prefix `pre`
   string value = 1 [(buf.validate.field).string.prefix = "pre"];
 }
 ```


�


�

�

�

��

	�	 ��
�
	��� `suffix` specifies that the field value must have the
specified substring at the end of the string. If the field value doesn't
 end with the specified suffix, an error message will be generated.

 ```proto
 message MyString {
   // value does not have suffix `post`
   string value = 1 [(buf.validate.field).string.suffix = "post"];
 }
 ```


	�


	�

	�

	�

	��

		�	 ��
�

��� `contains` specifies that the field value must have the
specified substring anywhere in the string. If the field value doesn't
 contain the specified substring, an error message will be generated.

 ```proto
 message MyString {
   // value does not contain substring `inside`.
   string value = 1 [(buf.validate.field).string.contains = "inside"];
 }
 ```



�



�


�


�


��

	
�	 � �
�
��� `not_contains` specifies that the field value must not have the
specified substring anywhere in the string. If the field value contains
 the specified substring, an error message will be generated.

 ```proto
 message MyString {
   // value contains substring `inside`.
   string value = 1 [(buf.validate.field).string.not_contains = "inside"];
 }
 ```


�


�

�

�!#

�$�

	�	 �%�
�
��� `in` specifies that the field value must be equal to one of the specified
 values. If the field value isn't one of the specified values, an error
 message will be generated.

 ```proto
 message MyString {
   // value must be in list ["apple", "banana"]
   repeated string value = 1 [(buf.validate.field).string.in = "apple", (buf.validate.field).string.in = "banana"];
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `not_in` specifies that the field value cannot be equal to any
 of the specified values. If the field value is one of the specified values,
 an error message will be generated.
 ```proto
 message MyString {
   // value must not be in list ["orange", "grape"]
   repeated string value = 1 [(buf.validate.field).string.not_in = "orange", (buf.validate.field).string.not_in = "grape"];
 }
 ```


�


�

�

�

��

	�	 ��
`
 ��P `WellKnown` rules provide advanced constraints against common string
 patterns


 �
�
��� `email` specifies that the field value must be a valid email address
 (addr-spec only) as defined by [RFC 5322](https://tools.ietf.org/html/rfc5322#section-3.4.1).
 If the field value isn't a valid email address, an error message will be generated.

 ```proto
 message MyString {
   // value must be a valid email address
   string value = 1 [(buf.validate.field).string.email = true];
 }
 ```


�

�	

�

��

	�	 ��
�
��� `hostname` specifies that the field value must be a valid
 hostname as defined by [RFC 1034](https://tools.ietf.org/html/rfc1034#section-3.5). This constraint doesn't support
 internationalized domain names (IDNs). If the field value isn't a
 valid hostname, an error message will be generated.

 ```proto
 message MyString {
   // value must be a valid hostname
   string value = 1 [(buf.validate.field).string.hostname = true];
 }
 ```


�

�	

�

��

	�	 ��
�
��� `ip` specifies that the field value must be a valid IP
 (v4 or v6) address, without surrounding square brackets for IPv6 addresses.
 If the field value isn't a valid IP address, an error message will be
 generated.

 ```proto
 message MyString {
   // value must be a valid IP address
   string value = 1 [(buf.validate.field).string.ip = true];
 }
 ```


�

�	

�

��

	�	 ��
�
��� `ipv4` specifies that the field value must be a valid IPv4
 address. If the field value isn't a valid IPv4 address, an error message
 will be generated.

 ```proto
 message MyString {
   // value must be a valid IPv4 address
   string value = 1 [(buf.validate.field).string.ipv4 = true];
 }
 ```


�

�	

�

��

	�	 ��
�
��� `ipv6` specifies that the field value must be a valid
 IPv6 address, without surrounding square brackets. If the field value is
 not a valid IPv6 address, an error message will be generated.

 ```proto
 message MyString {
   // value must be a valid IPv6 address
   string value = 1 [(buf.validate.field).string.ipv6 = true];
 }
 ```


�

�	

�

��

	�	 ��
�
��� `uri` specifies that the field value must be a valid,
 absolute URI as defined by [RFC 3986](https://tools.ietf.org/html/rfc3986#section-3). If the field value isn't a valid,
 absolute URI, an error message will be generated.

 ```proto
 message MyString {
   // value must be a valid URI
   string value = 1 [(buf.validate.field).string.uri = true];
 }
 ```


�

�	

�

��

	�	 ��
�
��� `uri_ref` specifies that the field value must be a valid URI
 as defined by [RFC 3986](https://tools.ietf.org/html/rfc3986#section-3) and may be either relative or absolute. If the
 field value isn't a valid URI, an error message will be generated.

 ```proto
 message MyString {
   // value must be a valid URI
   string value = 1 [(buf.validate.field).string.uri_ref = true];
 }
 ```


�

�	

�

��

	�	 ��
�
��� `address` specifies that the field value must be either a valid hostname
 as defined by [RFC 1034](https://tools.ietf.org/html/rfc1034#section-3.5)
 (which doesn't support internationalized domain names or IDNs) or a valid
 IP (v4 or v6). If the field value isn't a valid hostname or IP, an error
 message will be generated.

 ```proto
 message MyString {
   // value must be a valid hostname, or ip address
   string value = 1 [(buf.validate.field).string.address = true];
 }
 ```


�

�	

�

��

	�	 ��
�
��� `uuid` specifies that the field value must be a valid UUID as defined by
 [RFC 4122](https://tools.ietf.org/html/rfc4122#section-4.1.2). If the
 field value isn't a valid UUID, an error message will be generated.

 ```proto
 message MyString {
   // value must be a valid UUID
   string value = 1 [(buf.validate.field).string.uuid = true];
 }
 ```


�

�	

�

��

	�	 ��
�
��� `ip_with_prefixlen` specifies that the field value must be a valid IP (v4 or v6)
 address with prefix length. If the field value isn't a valid IP with prefix
 length, an error message will be generated.


 ```proto
 message MyString {
   // value must be a valid IP with prefix length
    string value = 1 [(buf.validate.field).string.ip_with_prefixlen = true];
 }
 ```


�

�	

�

� �

	�	 �!�
�
��� `ipv4_with_prefixlen` specifies that the field value must be a valid
 IPv4 address with prefix.
 If the field value isn't a valid IPv4 address with prefix length,
 an error message will be generated.

 ```proto
 message MyString {
   // value must be a valid IPv4 address with prefix lentgh
    string value = 1 [(buf.validate.field).string.ipv4_with_prefixlen = true];
 }
 ```


�

�	

�!

�"�

	�	 �#�
�
��� `ipv6_with_prefixlen` specifies that the field value must be a valid
 IPv6 address with prefix length.
 If the field value is not a valid IPv6 address with prefix length,
 an error message will be generated.

 ```proto
 message MyString {
   // value must be a valid IPv6 address prefix length
    string value = 1 [(buf.validate.field).string.ipv6_with_prefixlen = true];
 }
 ```


�

�	

�!

�"�

	�	 �#�
�
��� `ip_prefix` specifies that the field value must be a valid IP (v4 or v6) prefix.
 If the field value isn't a valid IP prefix, an error message will be
 generated. The prefix must have all zeros for the masked bits of the prefix (e.g.,
 `127.0.0.0/16`, not `127.0.0.1/16`).

 ```proto
 message MyString {
   // value must be a valid IP prefix
    string value = 1 [(buf.validate.field).string.ip_prefix = true];
 }
 ```


�

�	

�

��

	�	 ��
�
��� `ipv4_prefix` specifies that the field value must be a valid IPv4
 prefix. If the field value isn't a valid IPv4 prefix, an error message
 will be generated. The prefix must have all zeros for the masked bits of
 the prefix (e.g., `127.0.0.0/16`, not `127.0.0.1/16`).

 ```proto
 message MyString {
   // value must be a valid IPv4 prefix
    string value = 1 [(buf.validate.field).string.ipv4_prefix = true];
 }
 ```


�

�	

�

��

	�	 ��
�
��� `ipv6_prefix` specifies that the field value must be a valid IPv6 prefix.
 If the field value is not a valid IPv6 prefix, an error message will be
 generated. The prefix must have all zeros for the masked bits of the prefix
 (e.g., `2001:db8::/48`, not `2001:db8::1/48`).

 ```proto
 message MyString {
   // value must be a valid IPv6 prefix
    string value = 1 [(buf.validate.field).string.ipv6_prefix = true];
 }
 ```


�

�	

�

��

	�	 ��
�
��� `well_known_regex` specifies a common well-known pattern
 defined as a regex. If the field value doesn't match the well-known
 regex, an error message will be generated.

 ```proto
 message MyString {
   // value must be a valid HTTP header value
   string value = 1 [(buf.validate.field).string.well_known_regex = 2];
 }
 ```

 #### KnownRegex

 `well_known_regex` contains some well-known patterns.

 | Name                          | Number | Description                               |
 |-------------------------------|--------|-------------------------------------------|
 | KNOWN_REGEX_UNSPECIFIED       | 0      |                                           |
 | KNOWN_REGEX_HTTP_HEADER_NAME  | 1      | HTTP header name as defined by [RFC 7230](https://tools.ietf.org/html/rfc7230#section-3.2)  |
 | KNOWN_REGEX_HTTP_HEADER_VALUE | 2      | HTTP header value as defined by [RFC 7230](https://tools.ietf.org/html/rfc7230#section-3.2.4) |


�

�

�"$

�%�

	�	 ��

	�	��
�
�� This applies to regexes `HTTP_HEADER_NAME` and `HTTP_HEADER_VALUE` to
 enable strict header validation. By default, this is true, and HTTP header
 validations are [RFC-compliant](https://tools.ietf.org/html/rfc7230#section-3). Setting to false will enable looser
 validations that only disallow `\r\n\0` characters, which can be used to
 bypass header matching rules.

 ```proto
 message MyString {
   // The field `value` must have be a valid HTTP headers, but not enforced with strict rules.
   string value = 1 [(buf.validate.field).string.strict = false];
 }
 ```


�


�

�

�
@
 � �2 WellKnownRegex contain some well-known patterns.


 �

  �

  �

  �
k
 �#] HTTP header name as defined by [RFC 7230](https://tools.ietf.org/html/rfc7230#section-3.2).


 �

 �!"
n
 �$` HTTP header value as defined by [RFC 7230](https://tools.ietf.org/html/rfc7230#section-3.2.4).


 �

 �"#
�
� �� BytesRules describe the constraints applied to `bytes` values. These rules
 may also be applied to the `google.protobuf.BytesValue` Well-Known-Type.


�
�
 ��� `const` requires the field value to exactly match the specified bytes
 value. If the field value doesn't match, an error message is generated.

 ```proto
 message MyBytes {
   // value must be "\x01\x02\x03\x04"
   bytes value = 1 [(buf.validate.field).bytes.const = "\x01\x02\x03\x04"];
 }
 ```


 �


 �

 �

 �

 ��

	 �	 ��
�
��� `len` requires the field value to have the specified length in bytes.
 If the field value doesn't match, an error message is generated.

 ```proto
 message MyBytes {
   // value length must be 4 bytes.
   optional bytes value = 1 [(buf.validate.field).bytes.len = 4];
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `min_len` requires the field value to have at least the specified minimum
 length in bytes.
 If the field value doesn't meet the requirement, an error message is generated.

 ```proto
 message MyBytes {
   // value length must be at least 2 bytes.
   optional bytes value = 1 [(buf.validate.field).bytes.min_len = 2];
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `max_len` requires the field value to have at most the specified maximum
 length in bytes.
 If the field value exceeds the requirement, an error message is generated.

 ```proto
 message MyBytes {
   // value must be at most 6 bytes.
   optional bytes value = 1 [(buf.validate.field).bytes.max_len = 6];
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `pattern` requires the field value to match the specified regular
 expression ([RE2 syntax](https://github.com/google/re2/wiki/Syntax)).
 The value of the field must be valid UTF-8 or validation will fail with a
 runtime error.
 If the field value doesn't match the pattern, an error message is generated.

 ```proto
 message MyBytes {
   // value must match regex pattern "^[a-zA-Z0-9]+$".
   optional bytes value = 1 [(buf.validate.field).bytes.pattern = "^[a-zA-Z0-9]+$"];
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `prefix` requires the field value to have the specified bytes at the
 beginning of the string.
 If the field value doesn't meet the requirement, an error message is generated.

 ```proto
 message MyBytes {
   // value does not have prefix \x01\x02
   optional bytes value = 1 [(buf.validate.field).bytes.prefix = "\x01\x02"];
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `suffix` requires the field value to have the specified bytes at the end
 of the string.
 If the field value doesn't meet the requirement, an error message is generated.

 ```proto
 message MyBytes {
   // value does not have suffix \x03\x04
   optional bytes value = 1 [(buf.validate.field).bytes.suffix = "\x03\x04"];
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `contains` requires the field value to have the specified bytes anywhere in
 the string.
 If the field value doesn't meet the requirement, an error message is generated.

 ```protobuf
 message MyBytes {
   // value does not contain \x02\x03
   optional bytes value = 1 [(buf.validate.field).bytes.contains = "\x02\x03"];
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `in` requires the field value to be equal to one of the specified
 values. If the field value doesn't match any of the specified values, an
 error message is generated.

 ```protobuf
 message MyBytes {
   // value must in ["\x01\x02", "\x02\x03", "\x03\x04"]
   optional bytes value = 1 [(buf.validate.field).bytes.in = {"\x01\x02", "\x02\x03", "\x03\x04"}];
 }
 ```


�


�

�

�

��

	�	 ��
�
	��� `not_in` requires the field value to be not equal to any of the specified
 values.
 If the field value matches any of the specified values, an error message is
 generated.

 ```proto
 message MyBytes {
   // value must not in ["\x01\x02", "\x02\x03", "\x03\x04"]
   optional bytes value = 1 [(buf.validate.field).bytes.not_in = {"\x01\x02", "\x02\x03", "\x03\x04"}];
 }
 ```


	�


	�

	�

	�

	��

		�	 ��
\
 ��L WellKnown rules provide advanced constraints against common byte
 patterns


 �
�

��� `ip` ensures that the field `value` is a valid IP address (v4 or v6) in byte format.
 If the field value doesn't meet this constraint, an error message is generated.

 ```proto
 message MyBytes {
   // value must be a valid IP address
   optional bytes value = 1 [(buf.validate.field).bytes.ip = true];
 }
 ```



�


�	


�


��

	
�	 ��
�
��� `ipv4` ensures that the field `value` is a valid IPv4 address in byte format.
 If the field value doesn't meet this constraint, an error message is generated.

 ```proto
 message MyBytes {
   // value must be a valid IPv4 address
   optional bytes value = 1 [(buf.validate.field).bytes.ipv4 = true];
 }
 ```


�

�	

�

��

	�	 ��
�
��� `ipv6` ensures that the field `value` is a valid IPv6 address in byte format.
 If the field value doesn't meet this constraint, an error message is generated.
 ```proto
 message MyBytes {
   // value must be a valid IPv6 address
   optional bytes value = 1 [(buf.validate.field).bytes.ipv6 = true];
 }
 ```


�

�	

�

��

	�	 ��
L
� �> EnumRules describe the constraints applied to `enum` values.


�
�
 ��� `const` requires the field value to exactly match the specified enum value.
 If the field value doesn't match, an error message is generated.

 ```proto
 enum MyEnum {
   MY_ENUM_UNSPECIFIED = 0;
   MY_ENUM_VALUE1 = 1;
   MY_ENUM_VALUE2 = 2;
 }

 message MyMessage {
   // The field `value` must be exactly MY_ENUM_VALUE1.
   MyEnum value = 1 [(buf.validate.field).enum.const = 1];
 }
 ```


 �


 �

 �

 �

 ��

	 �	 ��
�
�!� `defined_only` requires the field value to be one of the defined values for
 this enum, failing on any undefined value.

 ```proto
 enum MyEnum {
   MY_ENUM_UNSPECIFIED = 0;
   MY_ENUM_VALUE1 = 1;
   MY_ENUM_VALUE2 = 2;
 }

 message MyMessage {
   // The field `value` must be a defined value of MyEnum.
   MyEnum value = 1 [(buf.validate.field).enum.defined_only = true];
 }
 ```


�


�

�

� 
�
��� `in` requires the field value to be equal to one of the
specified enum values. If the field value doesn't match any of the
specified values, an error message is generated.

 ```proto
 enum MyEnum {
   MY_ENUM_UNSPECIFIED = 0;
   MY_ENUM_VALUE1 = 1;
   MY_ENUM_VALUE2 = 2;
 }

 message MyMessage {
   // The field `value` must be equal to one of the specified values.
   MyEnum value = 1 [(buf.validate.field).enum = { in: [1, 2]}];
 }
 ```


�


�

�

�

��

	�	 ��
�
��� `not_in` requires the field value to be not equal to any of the
specified enum values. If the field value matches one of the specified
 values, an error message is generated.

 ```proto
 enum MyEnum {
   MY_ENUM_UNSPECIFIED = 0;
   MY_ENUM_VALUE1 = 1;
   MY_ENUM_VALUE2 = 2;
 }

 message MyMessage {
   // The field `value` must not be equal to any of the specified values.
   MyEnum value = 1 [(buf.validate.field).enum = { not_in: [1, 2]}];
 }
 ```


�


�

�

�

��

	�	 ��
T
� �F RepeatedRules describe the constraints applied to `repeated` values.


�
�
 ��� `min_items` requires that this field must contain at least the specified
 minimum number of items.

 Note that `min_items = 1` is equivalent to setting a field as `required`.

 ```proto
 message MyRepeated {
   // value must contain at least  2 items
   repeated string value = 1 [(buf.validate.field).repeated.min_items = 2];
 }
 ```


 �


 �

 �

 �

 � �

	 �	 �!�
�
��� `max_items` denotes that this field must not exceed a
 certain number of items as the upper limit. If the field contains more
 items than specified, an error message will be generated, requiring the
 field to maintain no more than the specified number of items.

 ```proto
 message MyRepeated {
   // value must contain no more than 3 item(s)
   repeated string value = 1 [(buf.validate.field).repeated.max_items = 3];
 }
 ```


�


�

�

�

� �

	�	 �!�
�
��� `unique` indicates that all elements in this field must
 be unique. This constraint is strictly applicable to scalar and enum
 types, with message types not being supported.

 ```proto
 message MyRepeated {
   // repeated value must contain unique items
   repeated string value = 1 [(buf.validate.field).repeated.unique = true];
 }
 ```


�


�

�

�

��

	�	 ��
�
�&� `items` details the constraints to be applied to each item
 in the field. Even for repeated message fields, validation is executed
 against each item unless skip is explicitly specified.

 ```proto
 message MyRepeated {
   // The items in the field `value` must follow the specified constraints.
   repeated string value = 1 [(buf.validate.field).repeated.items = {
     string: {
       min_len: 3
       max_len: 10
     }
   }];
 }
 ```


�


�

�!

�$%
J
� �< MapRules describe the constraints applied to `map` values.


�
�
 ���Specifies the minimum number of key-value pairs allowed. If the field has
 fewer key-value pairs than specified, an error message is generated.

 ```proto
 message MyMap {
   // The field `value` must have at least 2 key-value pairs.
   map<string, string> value = 1 [(buf.validate.field).map.min_pairs = 2];
 }
 ```


 �


 �

 �

 �

 � �

	 �	 �!�
�
���Specifies the maximum number of key-value pairs allowed. If the field has
 more key-value pairs than specified, an error message is generated.

 ```proto
 message MyMap {
   // The field `value` must have at most 3 key-value pairs.
   map<string, string> value = 1 [(buf.validate.field).map.max_pairs = 3];
 }
 ```


�


�

�

�

� �

	�	 �!�
�
�%�Specifies the constraints to be applied to each key in the field.

 ```proto
 message MyMap {
   // The keys in the field `value` must follow the specified constraints.
   map<string, string> value = 1 [(buf.validate.field).map.keys = {
     string: {
       min_len: 3
       max_len: 10
     }
   }];
 }
 ```


�


�

� 

�#$
�
�'�Specifies the constraints to be applied to the value of each key in the
 field. Message values will still have their validations evaluated unless
skip is specified here.

 ```proto
 message MyMap {
   // The values in the field `value` must follow the specified constraints.
   map<string, string> value = 1 [(buf.validate.field).map.values = {
     string: {
       min_len: 5
       max_len: 20
     }
   }];
 }
 ```


�


�

�"

�%&
o
� �a AnyRules describe constraints applied exclusively to the `google.protobuf.Any` well-known type.


�
�
 �� `in` requires the field's `type_url` to be equal to one of the
specified values. If it doesn't match any of the specified values, an error
 message is generated.

 ```proto
 message MyAny {
   //  The `value` field must have a `type_url` equal to one of the specified values.
   google.protobuf.Any value = 1 [(buf.validate.field).any.in = ["type.googleapis.com/MyType1", "type.googleapis.com/MyType2"]];
 }
 ```


 �


 �

 �

 �
�
�� requires the field's type_url to be not equal to any of the specified values. If it matches any of the specified values, an error message is generated.

 ```proto
 message MyAny {
   // The field `value` must not have a `type_url` equal to any of the specified values.
   google.protobuf.Any value = 1 [(buf.validate.field).any.not_in = ["type.googleapis.com/ForbiddenType1", "type.googleapis.com/ForbiddenType2"]];
 }
 ```


�


�

�

�
}
� �o DurationRules describe the constraints applied exclusively to the `google.protobuf.Duration` well-known type.


�
�
 ��� `const` dictates that the field must match the specified value of the `google.protobuf.Duration` type exactly.
 If the field's value deviates from the specified value, an error message
 will be generated.

 ```proto
 message MyDuration {
   // value must equal 5s
   google.protobuf.Duration value = 1 [(buf.validate.field).duration.const = "5s"];
 }
 ```


 �


 �#

 �$)

 �,-

 �.�

	 �	 �/�

 ��

 �
�
��� `lt` stipulates that the field must be less than the specified value of the `google.protobuf.Duration` type,
 exclusive. If the field's value is greater than or equal to the specified
 value, an error message will be generated.

 ```proto
 message MyDuration {
   // value must be less than 5s
   google.protobuf.Duration value = 1 [(buf.validate.field).duration.lt = "5s"];
 }
 ```


�

�

�"#

�$�

	�	 �%�
�
��� `lte` indicates that the field must be less than or equal to the specified
 value of the `google.protobuf.Duration` type, inclusive. If the field's value is greater than the specified value,
 an error message will be generated.

 ```proto
 message MyDuration {
   // value must be less than or equal to 10s
   google.protobuf.Duration value = 1 [(buf.validate.field).duration.lte = "10s"];
 }
 ```


�

� 

�#$

�%�

	�	 �&�

��

�
�
��� `gt` requires the duration field value to be greater than the specified
 value (exclusive). If the value of `gt` is larger than a specified `lt`
 or `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MyDuration {
   // duration must be greater than 5s [duration.gt]
   google.protobuf.Duration value = 1 [(buf.validate.field).duration.gt = { seconds: 5 }];

   // duration must be greater than 5s and less than 10s [duration.gt_lt]
   google.protobuf.Duration another_value = 2 [(buf.validate.field).duration = { gt: { seconds: 5 }, lt: { seconds: 10 } }];

   // duration must be greater than 10s or less than 5s [duration.gt_lt_exclusive]
   google.protobuf.Duration other_value = 3 [(buf.validate.field).duration = { gt: { seconds: 10 }, lt: { seconds: 5 } }];
 }
 ```


�

�

�"#

�$�

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `gte` requires the duration field value to be greater than or equal to the
 specified value (exclusive). If the value of `gte` is larger than a
 specified `lt` or `lte`, the range is reversed, and the field value must
 be outside the specified range. If the field value doesn't meet the
 required conditions, an error message is generated.

 ```proto
 message MyDuration {
  // duration must be greater than or equal to 5s [duration.gte]
  google.protobuf.Duration value = 1 [(buf.validate.field).duration.gte = { seconds: 5 }];

  // duration must be greater than or equal to 5s and less than 10s [duration.gte_lt]
  google.protobuf.Duration another_value = 2 [(buf.validate.field).duration = { gte: { seconds: 5 }, lt: { seconds: 10 } }];

  // duration must be greater than or equal to 10s or less than 5s [duration.gte_lt_exclusive]
  google.protobuf.Duration other_value = 3 [(buf.validate.field).duration = { gte: { seconds: 10 }, lt: { seconds: 5 } }];
 }
 ```


�

� 

�#$

�%�

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `in` asserts that the field must be equal to one of the specified values of the `google.protobuf.Duration` type.
 If the field's value doesn't correspond to any of the specified values,
 an error message will be generated.

 ```proto
 message MyDuration {
   // value must be in list [1s, 2s, 3s]
   google.protobuf.Duration value = 1 [(buf.validate.field).duration.in = ["1s", "2s", "3s"]];
 }
 ```


�


�#

�$&

�)*

�+�

	�	 �,�
�
��� `not_in` denotes that the field must not be equal to
 any of the specified values of the `google.protobuf.Duration` type.
 If the field's value matches any of these values, an error message will be
 generated.

 ```proto
 message MyDuration {
   // value must not be in list [1s, 2s, 3s]
   google.protobuf.Duration value = 1 [(buf.validate.field).duration.not_in = ["1s", "2s", "3s"]];
 }
 ```


�


�#

�$*

�-.

�/�

	�	 �0�

� �q TimestampRules describe the constraints applied exclusively to the `google.protobuf.Timestamp` well-known type.


�
�
 ��� `const` dictates that this field, of the `google.protobuf.Timestamp` type, must exactly match the specified value. If the field value doesn't correspond to the specified timestamp, an error message will be generated.

 ```proto
 message MyTimestamp {
   // value must equal 2023-05-03T10:00:00Z
   google.protobuf.Timestamp created_at = 1 [(buf.validate.field).timestamp.const = {seconds: 1727998800}];
 }
 ```


 �


 �$

 �%*

 �-.

 �/�

	 �	 �0�

 ��

 �
�
��� requires the duration field value to be less than the specified value (field < value). If the field value doesn't meet the required conditions, an error message is generated.

 ```proto
 message MyDuration {
   // duration must be less than 'P3D' [duration.lt]
   google.protobuf.Duration value = 1 [(buf.validate.field).duration.lt = { seconds: 259200 }];
 }
 ```


�

� 

�#$

�%�

	�	 �&�
�
��� requires the timestamp field value to be less than or equal to the specified value (field <= value). If the field value doesn't meet the required conditions, an error message is generated.

 ```proto
 message MyTimestamp {
   // timestamp must be less than or equal to '2023-05-14T00:00:00Z' [timestamp.lte]
   google.protobuf.Timestamp value = 1 [(buf.validate.field).timestamp.lte = { seconds: 1678867200 }];
 }
 ```


�

�!

�$%

�&�

	�	 �'�
�
��� `lt_now` specifies that this field, of the `google.protobuf.Timestamp` type, must be less than the current time. `lt_now` can only be used with the `within` rule.

 ```proto
 message MyTimestamp {
  // value must be less than now
   google.protobuf.Timestamp created_at = 1 [(buf.validate.field).timestamp.lt_now = true];
 }
 ```


�

�	

�

��

	�	 ��

��

�
�
��� `gt` requires the timestamp field value to be greater than the specified
 value (exclusive). If the value of `gt` is larger than a specified `lt`
 or `lte`, the range is reversed, and the field value must be outside the
 specified range. If the field value doesn't meet the required conditions,
 an error message is generated.

 ```proto
 message MyTimestamp {
   // timestamp must be greater than '2023-01-01T00:00:00Z' [timestamp.gt]
   google.protobuf.Timestamp value = 1 [(buf.validate.field).timestamp.gt = { seconds: 1672444800 }];

   // timestamp must be greater than '2023-01-01T00:00:00Z' and less than '2023-01-02T00:00:00Z' [timestamp.gt_lt]
   google.protobuf.Timestamp another_value = 2 [(buf.validate.field).timestamp = { gt: { seconds: 1672444800 }, lt: { seconds: 1672531200 } }];

   // timestamp must be greater than '2023-01-02T00:00:00Z' or less than '2023-01-01T00:00:00Z' [timestamp.gt_lt_exclusive]
   google.protobuf.Timestamp other_value = 3 [(buf.validate.field).timestamp = { gt: { seconds: 1672531200 }, lt: { seconds: 1672444800 } }];
 }
 ```


�

� 

�#$

�%�

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `gte` requires the timestamp field value to be greater than or equal to the
 specified value (exclusive). If the value of `gte` is larger than a
 specified `lt` or `lte`, the range is reversed, and the field value
 must be outside the specified range. If the field value doesn't meet
 the required conditions, an error message is generated.

 ```proto
 message MyTimestamp {
   // timestamp must be greater than or equal to '2023-01-01T00:00:00Z' [timestamp.gte]
   google.protobuf.Timestamp value = 1 [(buf.validate.field).timestamp.gte = { seconds: 1672444800 }];

   // timestamp must be greater than or equal to '2023-01-01T00:00:00Z' and less than '2023-01-02T00:00:00Z' [timestamp.gte_lt]
   google.protobuf.Timestamp another_value = 2 [(buf.validate.field).timestamp = { gte: { seconds: 1672444800 }, lt: { seconds: 1672531200 } }];

   // timestamp must be greater than or equal to '2023-01-02T00:00:00Z' or less than '2023-01-01T00:00:00Z' [timestamp.gte_lt_exclusive]
   google.protobuf.Timestamp other_value = 3 [(buf.validate.field).timestamp = { gte: { seconds: 1672531200 }, lt: { seconds: 1672444800 } }];
 }
 ```


�

�!

�$%

�&�

	�	 ��

	�	��

	�	��

	�	��

	�	��
�
��� `gt_now` specifies that this field, of the `google.protobuf.Timestamp` type, must be greater than the current time. `gt_now` can only be used with the `within` rule.

 ```proto
 message MyTimestamp {
   // value must be greater than now
   google.protobuf.Timestamp created_at = 1 [(buf.validate.field).timestamp.gt_now = true];
 }
 ```


�

�	

�

��

	�	 ��
�
��� `within` specifies that this field, of the `google.protobuf.Timestamp` type, must be within the specified duration of the current time. If the field value isn't within the duration, an error message is generated.

 ```proto
 message MyTimestamp {
   // value must be within 1 hour of now
   google.protobuf.Timestamp created_at = 1 [(buf.validate.field).timestamp.within = {seconds: 3600}];
 }
 ```


�


�#

�$*

�-.

�/�

	�	 �0�bproto3��NH
$
	buf.buildbufbuildprotovalidate e097f827e65240ac9fd4b1158849a8fc 
�
common/common.protocommongoogle/protobuf/timestamp.proto"�
Metadata9

created_at (2.google.protobuf.TimestampR	createdAt9

updated_at (2.google.protobuf.TimestampR	updatedAt4
labels (2.common.Metadata.LabelsEntryRlabels9
LabelsEntry
key (	Rkey
value (	Rvalue:8"�
MetadataMutable;
labels (2#.common.MetadataMutable.LabelsEntryRlabels9
LabelsEntry
key (	Rkey
value (	Rvalue:8*}
MetadataUpdateEnum$
 METADATA_UPDATE_ENUM_UNSPECIFIED 
METADATA_UPDATE_ENUM_EXTEND 
METADATA_UPDATE_ENUM_REPLACE*�
ActiveStateEnum!
ACTIVE_STATE_ENUM_UNSPECIFIED 
ACTIVE_STATE_ENUM_ACTIVE
ACTIVE_STATE_ENUM_INACTIVE
ACTIVE_STATE_ENUM_ANYJ�	
  $

  

 
	
  )
V
  J Struct to uniquely identify a resource with optional additional metadata



 
\
  	+O created_at set by server (entity who created will recorded in an audit event)


  	

  	&

  	)*
\
 +O updated_at set by server (entity who updated will recorded in an audit event)


 

 &

 )*
)
 ! optional short description


 

 

  


 




 ! optional labels


 

 

  


  


 
&
  ' unspecified update type


  "

  %&
7
 "* only update the fields that are provided


 

  !
E
 #8 replace the entire metadata with the provided metadata


 

 !"
�
 $� buflint ENUM_VALUE_PREFIX: to make sure that C++ scoping rules aren't violated when users add new enum values to an enum in a given package





  $

  

  "#

!

!

!

"!

"

" 

#

#

#bproto3��  
�#
google/protobuf/wrappers.protogoogle.protobuf"#
DoubleValue
value (Rvalue""

FloatValue
value (Rvalue""

Int64Value
value (Rvalue"#
UInt64Value
value (Rvalue""

Int32Value
value (Rvalue"#
UInt32Value
value (Rvalue"!
	BoolValue
value (Rvalue"#
StringValue
value (	Rvalue""

BytesValue
value (RvalueB�
com.google.protobufBWrappersProtoPZ1google.golang.org/protobuf/types/known/wrapperspb��GPB�Google.Protobuf.WellKnownTypesJ�
( z
�
( 2� Protocol Buffers - Google's data interchange format
 Copyright 2008 Google Inc.  All rights reserved.
 https://developers.google.com/protocol-buffers/

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are
 met:

     * Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above
 copyright notice, this list of conditions and the following disclaimer
 in the documentation and/or other materials provided with the
 distribution.
     * Neither the name of Google Inc. nor the names of its
 contributors may be used to endorse or promote products derived from
 this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 Wrappers for primitive (non-message) types. These types are useful
 for embedding primitives in the `google.protobuf.Any` type and for places
 where we need to distinguish between the absence of a primitive
 typed field and its default value.

 These wrappers have no meaningful use within repeated fields as they lack
 the ability to detect presence on individual elements.
 These wrappers have no meaningful use within a map or a oneof since
 individual entries of a map or fields of a oneof can already detect presence.


* 

, 
	
, 

- H
	
- H

. ,
	
. ,

/ .
	
/ .

0 "
	

0 "

1 !
	
$1 !

2 ;
	
%2 ;
g
 7 :[ Wrapper message for `double`.

 The JSON representation for `DoubleValue` is JSON number.



 7
 
  9 The double value.


  9

  9	

  9
e
? BY Wrapper message for `float`.

 The JSON representation for `FloatValue` is JSON number.



?

 A The float value.


 A

 A

 A
e
G JY Wrapper message for `int64`.

 The JSON representation for `Int64Value` is JSON string.



G

 I The int64 value.


 I

 I

 I
g
O R[ Wrapper message for `uint64`.

 The JSON representation for `UInt64Value` is JSON string.



O
 
 Q The uint64 value.


 Q

 Q	

 Q
e
W ZY Wrapper message for `int32`.

 The JSON representation for `Int32Value` is JSON number.



W

 Y The int32 value.


 Y

 Y

 Y
g
_ b[ Wrapper message for `uint32`.

 The JSON representation for `UInt32Value` is JSON number.



_
 
 a The uint32 value.


 a

 a	

 a
o
g jc Wrapper message for `bool`.

 The JSON representation for `BoolValue` is JSON `true` and `false`.



g

 i The bool value.


 i

 i

 i
g
o r[ Wrapper message for `string`.

 The JSON representation for `StringValue` is JSON string.



o
 
 q The string value.


 q

 q	

 q
e
w zY Wrapper message for `bytes`.

 The JSON representation for `BytesValue` is JSON string.



w

 y The bytes value.


 y

 y

 ybproto3�� 
�'
,kasregistry/key_access_server_registry.protokasregistrybuf/validate/validate.protocommon/common.protogoogle/api/annotations.proto"�
KeyAccessServer
id (	Rid
uri (	Ruri5

public_key (2.kasregistry.PublicKeyR	publicKey,
metadatad (2.common.MetadataRmetadata"�
	PublicKey�
remote (	B��H���

uri_format�URI must be a valid URL (e.g., 'https://demo.com/') followed by additional segments. Each segment must start and end with an alphanumeric character, can contain hyphens, alphanumeric characters, and slashes.�this.matches('^https://[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*(/.*)?$')H Rremote
local (	H RlocalB

public_key"3
GetKeyAccessServerRequest
id (	B�H�Rid"f
GetKeyAccessServerResponseH
key_access_server (2.kasregistry.KeyAccessServerRkeyAccessServer"
ListKeyAccessServersRequest"j
ListKeyAccessServersResponseJ
key_access_servers (2.kasregistry.KeyAccessServerRkeyAccessServers"�
CreateKeyAccessServerRequest
uri (	B�H�Ruri=

public_key (2.kasregistry.PublicKeyB�H�R	publicKey3
metadatad (2.common.MetadataMutableRmetadata"i
CreateKeyAccessServerResponseH
key_access_server (2.kasregistry.KeyAccessServerRkeyAccessServer"�
UpdateKeyAccessServerRequest
id (	B�H�Rid
uri (	Ruri5

public_key (2.kasregistry.PublicKeyR	publicKey3
metadatad (2.common.MetadataMutableRmetadataT
metadata_update_behaviore (2.common.MetadataUpdateEnumRmetadataUpdateBehavior"i
UpdateKeyAccessServerResponseH
key_access_server (2.kasregistry.KeyAccessServerRkeyAccessServer"6
DeleteKeyAccessServerRequest
id (	B�H�Rid"i
DeleteKeyAccessServerResponseH
key_access_server (2.kasregistry.KeyAccessServerRkeyAccessServer2�
KeyAccessServerRegistryService�
ListKeyAccessServers(.kasregistry.ListKeyAccessServersRequest).kasregistry.ListKeyAccessServersResponse"���/key-access-servers�
GetKeyAccessServer&.kasregistry.GetKeyAccessServerRequest'.kasregistry.GetKeyAccessServerResponse" ���/key-access-servers/{id}�
CreateKeyAccessServer).kasregistry.CreateKeyAccessServerRequest*.kasregistry.CreateKeyAccessServerResponse"���:*"/key-access-servers�
UpdateKeyAccessServer).kasregistry.UpdateKeyAccessServerRequest*.kasregistry.UpdateKeyAccessServerResponse"#���:*2/key-access-servers/{id}�
DeleteKeyAccessServer).kasregistry.DeleteKeyAccessServerRequest*.kasregistry.DeleteKeyAccessServerResponse" ���*/key-access-servers/{id}J�
  j

  

 
	
  %
	
 
	
 &
"
  
Descriptor for a KAS



 

  

  

  	

  
(
  Address of a KAS instance


 

 	

 

 

 

 

 

 ! Common metadata


 

 

  


 !




  

 
X
 J kas public key url - optional since can also be retrieved via public key


 


 

 

 

	 �	 
H
; public key - optional since can also be retrieved via url










# %


#!

 $7

 $

 $	

 $

 $6

 �	$5


& (


&"

 '(

 '

 '#

 '&'
	
* &


*#


+ -


+$

 ,2

 ,


 ,

 ,-

 ,01


/ 6


/$

 18
 Required


 1

 1	

 1

 17

 �	16

2B

2

2

2

2A

�	2@

5( Common metadata


5

5!

5$'


7 9


7%

 8(

 8

 8#

 8&'


; D


;$

 =7
 Required


 =

 =	

 =

 =6

 �	=5

>

>

>	

>

?

?

?

?

B( Common metadata


B

B!

B$'

C;

C

C4

C7:


	E G


	E%

	 F(

	 F

	 F#

	 F&'



I K



I$


 J7


 J


 J	


 J


 J6


 �	J5


L N


L%

 M(

 M

 M#

 M&'


 P j


 P&

  QS

  Q

  Q6

  QA]

  R<

	  �ʼ"R<

 UW

 U

 U2

 U=W

 VA

	 �ʼ"VA

 Y^

 Y

 Y8

 YC`

 Z]

	 �ʼ"Z]

 `e

 `

 `8

 `C`

 ad

	 �ʼ"ad

 gi

 g

 g8

 gC`

 hD

	 �ʼ"hDbproto3��  
�X
policy/objects.protopolicybuf/validate/validate.protocommon/common.protogoogle/protobuf/wrappers.proto,kasregistry/key_access_server_registry.proto"�
	Namespace
id (	Rid
name (	Rname
fqn (	Rfqn2
active (2.google.protobuf.BoolValueRactive,
metadata (2.common.MetadataRmetadata"�
	Attribute
id (	Rid/
	namespace (2.policy.NamespaceR	namespace
name (	Rname>
rule (2.policy.AttributeRuleTypeEnumB�H��Rrule%
values (2.policy.ValueRvalues4
grants (2.kasregistry.KeyAccessServerRgrants
fqn (	Rfqn2
active (2.google.protobuf.BoolValueRactive,
metadatad (2.common.MetadataRmetadata"�
Value
id (	Rid/
	attribute (2.policy.AttributeR	attribute
value (	Rvalue'
members (2.policy.ValueRmembers4
grants (2.kasregistry.KeyAccessServerRgrants
fqn (	Rfqn2
active (2.google.protobuf.BoolValueRactiveA
subject_mappings (2.policy.SubjectMappingRsubjectMappings,
metadatad (2.common.MetadataRmetadata"�
Action;
standard (2.policy.Action.StandardActionH Rstandard
custom (	H Rcustom"l
StandardAction
STANDARD_ACTION_UNSPECIFIED 
STANDARD_ACTION_DECRYPT
STANDARD_ACTION_TRANSMITB
value"�
SubjectMapping
id (	Rid6
attribute_value (2.policy.ValueRattributeValueO
subject_condition_set (2.policy.SubjectConditionSetRsubjectConditionSet(
actions (2.policy.ActionRactions,
metadatad (2.common.MetadataRmetadata"�
	ConditionE
subject_external_selector_value (	RsubjectExternalSelectorValueK
operator (2".policy.SubjectMappingOperatorEnumB�H��Roperator6
subject_external_values (	RsubjectExternalValues"�
ConditionGroup;

conditions (2.policy.ConditionB�H�R
conditionsX
boolean_operator (2 .policy.ConditionBooleanTypeEnumB�H��RbooleanOperator"Y

SubjectSetK
condition_groups (2.policy.ConditionGroupB�H�RconditionGroups"�
SubjectConditionSet
id (	Rid?
subject_sets (2.policy.SubjectSetB�H�RsubjectSets,
metadatad (2.common.MetadataRmetadata"�
SubjectProperty>
external_selector_value (	B�H�RexternalSelectorValue-
external_value (	B�H�RexternalValue"�
ResourceMapping
id (	Rid,
metadata (2.common.MetadataRmetadata>
attribute_value (2.policy.ValueB�H�RattributeValue
terms (	Rterms*�
AttributeRuleTypeEnum(
$ATTRIBUTE_RULE_TYPE_ENUM_UNSPECIFIED #
ATTRIBUTE_RULE_TYPE_ENUM_ALL_OF#
ATTRIBUTE_RULE_TYPE_ENUM_ANY_OF&
"ATTRIBUTE_RULE_TYPE_ENUM_HIERARCHY*�
SubjectMappingOperatorEnum-
)SUBJECT_MAPPING_OPERATOR_ENUM_UNSPECIFIED $
 SUBJECT_MAPPING_OPERATOR_ENUM_IN(
$SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN*�
ConditionBooleanTypeEnum+
'CONDITION_BOOLEAN_TYPE_ENUM_UNSPECIFIED #
CONDITION_BOOLEAN_TYPE_ENUM_AND"
CONDITION_BOOLEAN_TYPE_ENUM_ORJ�A
  �

  

 
	
  %
	
 
	
 (
	
 6


 
 


 

)
   generated uuid in database


  

  	

  
h
 [ used to partition Attribute Definitions, support by namespace AuthN and enable federation


 

 	

 

 

 

 	

 
=
 '0 active by default until explicitly deactivated


 

 "

 %&

 

 

 

 


 2




 

 

 	

 
)
 namespace of the attribute








attribute name




	


#
"% attribute rule enum


"

"

" 

"!%

	�	#1

�	$(

'

'


'

'

'

)2

)


)&

)'-

)01

+

+

+	

+
=
.'0 active by default until explicitly deactivated


.

."

.%&

1! Common metadata


1

1

1 
�
 5 :� buflint ENUM_VALUE_PREFIX: to make sure that C++ scoping rules aren't violated when users add new enum values to an enum in a given package



 5

  6+

  6&

  6)*

 7&

 7!

 7$%

 8&

 8!

 8$%

 9)

 9$

 9'(


< T


<
)
 > generated uuid in database


 >

 >	

 >

@

@

@

@

B

B

B	

B
W
EJ list of attribute values that this value is related to (attribute group)


E


E

E

E
)
H2 list of key access servers


H


H&

H'-

H01

J

J

J	

J
=
M'0 active by default until explicitly deactivated


M

M"

M%&

P/ subject mapping


P


P

P*

P-.

S! Common metadata


S

S

S 
*
W b An action an entity can take



W
:
 Y], Standard actions supported by the platform


 Y

  Z$

  Z

  Z"#

 [ 

 [

 [

 \!

 \

 \ 

 ^a

 ^

 _ 

 _

 _

 _

`

`


`

`
�
i m� buflint ENUM_VALUE_PREFIX: to make sure that C++ scoping rules aren't violated when users add new enum values to an enum in a given package
2�
Subject Mapping (aka Access Control Subject Encoding aka ACSE):  Structures supporting the mapping of Subjects and Attributes (e.g. Entitlement)



i

 j0

 j+

 j./

k'

k"

k%&

l+

l&

l)*
�
p t� buflint ENUM_VALUE_PREFIX: to make sure that C++ scoping rules aren't violated when users add new enum values to an enum in a given package



p

 q.

 q)

 q,-

r&

r!

r$%

s%

s 

s#$
�
� ��
Subject Mapping: A Policy assigning Subject Set(s) to a permitted attribute value + action(s) combination

Example: Subjects in sets 1 and 2 are entitled attribute value http://wwww.example.org/attr/example/value/one
with permitted actions TRANSMIT and DECRYPT
{
"id": "someid",
"attribute_value": {example_one_attribute_value...},
"subject_condition_set": {"subject_sets":[{subject_set_1},{subject_set_2}]...},
"actions": [{"standard": "STANDARD_ACTION_DECRYPT"}", {"standard": "STANDARD_ACTION_TRANSMIT"}]
}


�

 �

 �

 �	

 �
V
�H the Attribute Value mapped to; aka: "The Entity Entitlement Attribute"


�

�

�
T
�0F the reusable SubjectConditionSet mapped to the given Attribute Value


�

�+

�./
A
�3 The actions permitted by subjects in this mapping


�


�

�

�

�!

�

�

� 
�
� ��*
A Condition defines a rule of <the value by a jq 'selector value' expression> <operator> <subject external values>

Example:  Subjects with a field selected by the jq syntax "'.division'" and a value of "Accounting" or "Marketing":
{
"subject_external_selector_value": "'.division'",
"operator": "SUBJECT_MAPPING_OPERATOR_ENUM_IN",
"subject_external_values" : ["Accounting", "Marketing"]
}

Example: Subjects that are not part of the Fantastic Four according to their alias field:
{
"subject_external_selector_value": "'.data[0].alias'",
"operator": "SUBJECT_MAPPING_OPERATOR_ENUM_NOT_IN",
"subject_external_values" : ["mister_fantastic", "the_thing", "human_torch", "invisible_woman"]
}


�
o
 �-a a jq syntax expression to select a value from an externally known field (such as from idP/LDAP)


 �

 �	(

 �+,
5
��% the evaluation operator of relation


�

�%

�()

�*�

	�	�1

�	�(
�
�.� list of comparison values for the result of applying the subject_external_selector_value with jq on a Subject, evaluated by the operator


�


�

�)

�,-
U
� �G A collection of Conditions evaluated by the boolean_operator provided


�

 �R

 �


 �

 �

 �"#

 �$Q

	 �	�%P
C
��3 the boolean evaluation type across the conditions


�

�+

�./

�0�

	�	�1

�	�(
0
� �" A collection of Condition Groups


�
F
 �]8 multiple Condition Groups are evaluated with AND logic


 �


 �

 �*

 �-.

 �/\

	 �	�0[
�
� ��
A container for multiple Subject Sets, each containing Condition Groups, each containing Conditions. Multiple Subject Sets in a SubjectConditionSet
are evaluated with AND logic. As each Subject Mapping has only one Attribute Value, the SubjectConditionSet is reusable across multiple
Subject Mappings / Attribute Values and is an independent unit.


�

 �

 �

 �	

 �

�U

�


�

�"

�%&

�'T

	�	�(S

�!

�

�

� 
�
	� ��

A property of a Subject/Entity as its selector expression -> value result pair. This would mirror external user attributes retrieved
from an authoritative source such as an IDP (Identity Provider) or User Store. Examples include such ADFS/LDAP, OKTA, etc.
For now, a valid property must contain both a selector expression & a resulting value. 

The external_selector_value is a jq syntax expression to select a value from an externally known field (such as from idP/LDAP),
and the external_value is the value selected by the external_selector_value on that Subject's Context. These mirror the Condition.


	�

	 �L

	 �

	 �	 

	 �#$

	 �%K

	 �	�&J

	�C

	�

	�	

	�

	�B

	�	�A
�

� ��
Resource Mappings (aka Access Control Resource Encodings aka ACRE) are structures supporting the mapping of Resources and Attribute Values



�


 �


 �


 �	


 �


�


�


�


�


�J


�


�


�!"


�#I


�	�$H


�


�



�


�


�bproto3��  
�<
!authorization/authorization.protoauthorizationgoogle/api/annotations.protogoogle/protobuf/any.protopolicy/objects.proto"�
Entity
id (	Rid%
email_address (	H RemailAddress
	user_name (	H RuserName,
remote_claims_url (	H RremoteClaimsUrl
jwt (	H Rjwt.
claims (2.google.protobuf.AnyH Rclaims5
custom (2.authorization.EntityCustomH Rcustom
	client_id (	H RclientIdB
entity_type"B
EntityCustom2
	extension (2.google.protobuf.AnyR	extension"P
EntityChain
id (	Rid1
entities (2.authorization.EntityRentities"�
DecisionRequest(
actions (2.policy.ActionRactions?
entity_chains (2.authorization.EntityChainRentityChainsQ
resource_attributes (2 .authorization.ResourceAttributeRresourceAttributes"�
DecisionResponse&
entity_chain_id (	RentityChainId4
resource_attributes_id (	RresourceAttributesId&
action (2.policy.ActionRactionD
decision (2(.authorization.DecisionResponse.DecisionRdecision 
obligations (	Robligations"L
Decision
DECISION_UNSPECIFIED 
DECISION_DENY
DECISION_PERMIT"b
GetDecisionsRequestK
decision_requests (2.authorization.DecisionRequestRdecisionRequests"f
GetDecisionsResponseN
decision_responses (2.authorization.DecisionResponseRdecisionResponses"�
GetEntitlementsRequest1
entities (2.authorization.EntityRentities;
scope (2 .authorization.ResourceAttributeH Rscope�B
_scope"c
EntityEntitlements
	entity_id (	RentityId0
attribute_value_fqns (	RattributeValueFqns"E
ResourceAttribute0
attribute_value_fqns (	RattributeValueFqns"`
GetEntitlementsResponseE
entitlements (2!.authorization.EntityEntitlementsRentitlements2�
AuthorizationServicer
GetDecisions".authorization.GetDecisionsRequest#.authorization.GetDecisionsResponse"���"/v1/authorizationz
GetEntitlements%.authorization.GetEntitlementsRequest&.authorization.GetEntitlementsResponse"���"/v1/entitlementsJ�,
  �

  

 
	
  &
	
 #
	
 
;
 
 / PE (Person Entity) or NPE (Non-Person Entity)



 

E
  "8 ephemeral id for tracking between request and response


  

  	

  
?
  1 Standard entity types supported by the platform


  

 

 


 

 

 

 


 

 

 !

 


 

  

 

 


 

 

 #

 

 

 !"

 

 

 

 

 

 


 

 
G
 ; Entity type for custom entities beyond the standard types





 $

 

 

 "#
)
 ! A set of related PE and NPE




E
 "8 ephemeral id for tracking between request and response


 

 	

 

 

 


 

 

 
�
P T�
Example Request Get Decisions to answer the question -  Do Bob (represented by entity chain ec1)
and Alice (represented by entity chain ec2) have TRANSMIT authorization for
2 resources; resource1 (attr-set-1) defined by attributes foo:bar  resource2 (attr-set-2) defined by attribute foo:bar, color:red ?

{
"actions": [
{
"standard": "STANDARD_ACTION_TRANSMIT"
}
],
"entityChains": [
{
"id": "ec1",
"entities": [
{
"emailAddress": "bob@example.org"
}
]
},
{
"id": "ec2",
"entities": [
{
"userName": "alice@example.org"
}
]
}
],
"resourceAttributes": [
{
"attributeFqns": [
"https://www.example.org/attr/foo/value/value1"
]
},
{
"attributeFqns": [
"https://example.net/attr/attr1/value/value1",
"https://example.net/attr/attr1/value/value2"
]
}
]
}




P

 Q%

 Q


 Q

 Q 

 Q#$

R)

R


R

R$

R'(

S5

S


S

S0

S34
�	
| ��	

Example response for a Decision Request -  Do Bob (represented by entity chain ec1)
and Alice (represented by entity chain ec2) have TRANSMIT authorization for
2 resources; resource1 (attr-set-1) defined by attributes foo:bar  resource2 (attr-set-2) defined by attribute foo:bar, color:red ?

Results:
- bob has permitted authorization to transmit for a resource defined by attr-set-1 attributes and has a watermark obligation
- bob has denied authorization to transmit a for a resource defined by attr-set-2 attributes
- alice has permitted authorization to transmit for a resource defined by attr-set-1 attributes
- alice has denied authorization to transmit a for a resource defined by attr-set-2 attributes

{
"entityChainId":  "ec1",
"resourceAttributesId":  "attr-set-1",
"decision":  "DECISION_PERMIT",
"obligations":  [
"http://www.example.org/obligation/watermark"
]
},
{
"entityChainId":  "ec1",
"resourceAttributesId":  "attr-set-2",
"decision":  "DECISION_PERMIT"
},
{
"entityChainId":  "ec2",
"resourceAttributesId":  "attr-set-1",
"decision":  "DECISION_PERMIT"
},
{
"entityChainId":  "ec2",
"resourceAttributesId":  "attr-set-2",
"decision":  "DECISION_DENY"
}





|

 }�

 }

  ~

  ~

  ~

 

 

 

 �

 �

 �
:
 �", ephemeral entity chain id from the request


 �

 �	

 �
A
�$"3 ephemeral resource attributes id from the request


�

�	

�"#
/
�"! Action of the decision response


�

�

�
%
�" The decision response


�


�

�
E
�""7optional list of obligations represented in URI format


�


�

�

� !

� �

�

 �1

 �


 �

 �,

 �/0

� �

�

 �3

 �


 �

 �.

 �12
�
� ��
Request to get entitlements for one or more entities for an optional attribute scope

Example: Get entitlements for bob and alice (both represented using an email address

{
"entities": [
{
"id": "e1",
"emailAddress": "bob@example.org"
},
{
"id": "e2",
"emailAddress": "alice@example.org"
}
]
}



�
*
 �" list of requested entities


 �


 �

 �

 �
0
�'""optional attribute fqn as a scope


�


�

�"

�%&

� �

�

 �

 �

 �	

 �

�+

�


�

�&

�)*
G
	� �9A logical bucket of attributes belonging to a "Resource"


	�

	 �+

	 �


	 �

	 �&

	 �)*
�

� ��

Example Response for a request of : Get entitlements for bob and alice (both represented using an email address

{
"entitlements":  [
{
"entityId":  "e1",
"attributeValueReferences":  [
{
"attributeFqn":  "http://www.example.org/attr/foo/value/bar"
}
]
},
{
"entityId":  "e2",
"attributeValueReferences":  [
{
"attributeFqn":  "http://www.example.org/attr/color/value/red"
}
]
}
]
}





�


 �/


 �



 �


 �*


 �-.

 � �

 �

  ��

  �

  �&

  �1E

  �;

	  �ʼ"�;

 ��

 �

 �,

 �7N

 �:

	 �ʼ"�:bproto3��  
�#
google/protobuf/struct.protogoogle.protobuf"�
Struct;
fields (2#.google.protobuf.Struct.FieldsEntryRfieldsQ
FieldsEntry
key (	Rkey,
value (2.google.protobuf.ValueRvalue:8"�
Value;

null_value (2.google.protobuf.NullValueH R	nullValue#
number_value (H RnumberValue#
string_value (	H RstringValue

bool_value (H R	boolValue<
struct_value (2.google.protobuf.StructH RstructValue;

list_value (2.google.protobuf.ListValueH R	listValueB
kind";
	ListValue.
values (2.google.protobuf.ValueRvalues*
	NullValue

NULL_VALUE B
com.google.protobufBStructProtoPZ/google.golang.org/protobuf/types/known/structpb��GPB�Google.Protobuf.WellKnownTypesJ�
 ^
�
 2� Protocol Buffers - Google's data interchange format
 Copyright 2008 Google Inc.  All rights reserved.
 https://developers.google.com/protocol-buffers/

 Redistribution and use in source and binary forms, with or without
 modification, are permitted provided that the following conditions are
 met:

     * Redistributions of source code must retain the above copyright
 notice, this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above
 copyright notice, this list of conditions and the following disclaimer
 in the documentation and/or other materials provided with the
 distribution.
     * Neither the name of Google Inc. nor the names of its
 contributors may be used to endorse or promote products derived from
 this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


  

" 
	
" 

# F
	
# F

$ ,
	
$ ,

% ,
	
% ,

& "
	

& "

' !
	
$' !

( ;
	
%( ;
�
 2 5� `Struct` represents a structured data value, consisting of fields
 which map to dynamically typed values. In some languages, `Struct`
 might be supported by a native representation. For example, in
 scripting languages like JS a struct is represented as an
 object. The details of that representation are described together
 with the proto support for the language.

 The JSON representation for `Struct` is JSON object.



 2
9
  4 , Unordered map of dynamically typed values.


  4

  4

  4
�
= M� `Value` represents a dynamically typed value which can be either
 null, a number, a string, a boolean, a recursive struct value, or a
 list of values. A producer of value is expected to set one of these
 variants. Absence of any variant indicates an error.

 The JSON representation for `Value` is JSON value.



=
"
 ?L The kind of value.


 ?
'
 A Represents a null value.


 A

 A

 A
)
C Represents a double value.


C


C

C
)
E Represents a string value.


E


E

E
*
G Represents a boolean value.


G

G	

G
-
I  Represents a structured value.


I


I

I
-
K  Represents a repeated `Value`.


K

K

K
�
 S V� `NullValue` is a singleton enumeration to represent the null value for the
 `Value` type union.

 The JSON representation for `NullValue` is JSON `null`.



 S

  U Null value.


  U

  U
�
[ ^v `ListValue` is a wrapper around a repeated field of values.

 The JSON representation for `ListValue` is JSON array.



[
:
 ]- Repeated field of dynamically typed values.


 ]


 ]

 ]

 ]bproto3�� 
�
authorization/idp_plugin.protoauthorization!authorization/authorization.protogoogle/protobuf/struct.protogoogle/protobuf/any.proto"<
	IdpConfig/
config (2.google.protobuf.StructRconfig"E
IdpPluginRequest1
entities (2.authorization.EntityRentities"~
IdpEntityRepresentationB
additional_props (2.google.protobuf.StructRadditionalProps
original_id (	R
originalId"r
IdpPluginResponse]
entity_representations (2&.authorization.IdpEntityRepresentationRentityRepresentations"�
EntityNotFoundError
code (Rcode
message (	Rmessage.
details (2.google.protobuf.AnyRdetails
entity (	RentityJ�	
  @

  

 
	
  +
	
 &
	
 #


  



 

  	$

  	

  	

  	"#
�
 �
Example: Get idp attributes for bob and alice (both represented using an email address
{
"entities": [
{
"id": "e1",
"emailAddress": "bob@example.org"
},
{
"id": "e2",
"emailAddress": "alice@example.org"
}
]
}






 /

 

 !

 "*

 -.


! $


!

 "7

 "


 "!

 ""2

 "56
3
#"& ephemeral entity id from the request


#

#	

#
�
7 9�
Example: Get idp attributes for bob and alice
{
"entity_representations": [
{
"idp_entity_id": "e1",
"additional_props": {"someAttr1":"someValue1"}
},
{
"idp_entity_id": "e2",
"additional_props": {"someAttr2":"someValue2"}
}
]
}




7

 8>

 8


 8"

 8#9

 8<=


; @


;

 <

 <

 <

 <

=

=

=	

=

>+

>


>

>&

>)*

?

?

?	

?bproto3��  
��
,protoc-gen-openapiv2/options/openapiv2.proto)grpc.gateway.protoc_gen_openapiv2.optionsgoogle/protobuf/struct.proto"�
Swagger
swagger (	RswaggerC
info (2/.grpc.gateway.protoc_gen_openapiv2.options.InfoRinfo
host (	Rhost
	base_path (	RbasePathK
schemes (21.grpc.gateway.protoc_gen_openapiv2.options.SchemeRschemes
consumes (	Rconsumes
produces (	Rproduces_
	responses
 (2A.grpc.gateway.protoc_gen_openapiv2.options.Swagger.ResponsesEntryR	responsesq
security_definitions (2>.grpc.gateway.protoc_gen_openapiv2.options.SecurityDefinitionsRsecurityDefinitionsZ
security (2>.grpc.gateway.protoc_gen_openapiv2.options.SecurityRequirementRsecurityB
tags (2..grpc.gateway.protoc_gen_openapiv2.options.TagRtagse
external_docs (2@.grpc.gateway.protoc_gen_openapiv2.options.ExternalDocumentationRexternalDocsb

extensions (2B.grpc.gateway.protoc_gen_openapiv2.options.Swagger.ExtensionsEntryR
extensionsq
ResponsesEntry
key (	RkeyI
value (23.grpc.gateway.protoc_gen_openapiv2.options.ResponseRvalue:8U
ExtensionsEntry
key (	Rkey,
value (2.google.protobuf.ValueRvalue:8J	J	
"�
	Operation
tags (	Rtags
summary (	Rsummary 
description (	Rdescriptione
external_docs (2@.grpc.gateway.protoc_gen_openapiv2.options.ExternalDocumentationRexternalDocs!
operation_id (	RoperationId
consumes (	Rconsumes
produces (	Rproducesa
	responses	 (2C.grpc.gateway.protoc_gen_openapiv2.options.Operation.ResponsesEntryR	responsesK
schemes
 (21.grpc.gateway.protoc_gen_openapiv2.options.SchemeRschemes

deprecated (R
deprecatedZ
security (2>.grpc.gateway.protoc_gen_openapiv2.options.SecurityRequirementRsecurityd

extensions (2D.grpc.gateway.protoc_gen_openapiv2.options.Operation.ExtensionsEntryR
extensionsU

parameters (25.grpc.gateway.protoc_gen_openapiv2.options.ParametersR
parametersq
ResponsesEntry
key (	RkeyI
value (23.grpc.gateway.protoc_gen_openapiv2.options.ResponseRvalue:8U
ExtensionsEntry
key (	Rkey,
value (2.google.protobuf.ValueRvalue:8J	"b

ParametersT
headers (2:.grpc.gateway.protoc_gen_openapiv2.options.HeaderParameterRheaders"�
HeaderParameter
name (	Rname 
description (	RdescriptionS
type (2?.grpc.gateway.protoc_gen_openapiv2.options.HeaderParameter.TypeRtype
format (	Rformat
required (Rrequired"E
Type
UNKNOWN 

STRING

NUMBER
INTEGER
BOOLEANJJ"�
Header 
description (	Rdescription
type (	Rtype
format (	Rformat
default (	Rdefault
pattern (	RpatternJJJJ	J	
J
JJJJJJJ"�
Response 
description (	RdescriptionI
schema (21.grpc.gateway.protoc_gen_openapiv2.options.SchemaRschemaZ
headers (2@.grpc.gateway.protoc_gen_openapiv2.options.Response.HeadersEntryRheaders]
examples (2A.grpc.gateway.protoc_gen_openapiv2.options.Response.ExamplesEntryRexamplesc

extensions (2C.grpc.gateway.protoc_gen_openapiv2.options.Response.ExtensionsEntryR
extensionsm
HeadersEntry
key (	RkeyG
value (21.grpc.gateway.protoc_gen_openapiv2.options.HeaderRvalue:8;
ExamplesEntry
key (	Rkey
value (	Rvalue:8U
ExtensionsEntry
key (	Rkey,
value (2.google.protobuf.ValueRvalue:8"�
Info
title (	Rtitle 
description (	Rdescription(
terms_of_service (	RtermsOfServiceL
contact (22.grpc.gateway.protoc_gen_openapiv2.options.ContactRcontactL
license (22.grpc.gateway.protoc_gen_openapiv2.options.LicenseRlicense
version (	Rversion_

extensions (2?.grpc.gateway.protoc_gen_openapiv2.options.Info.ExtensionsEntryR
extensionsU
ExtensionsEntry
key (	Rkey,
value (2.google.protobuf.ValueRvalue:8"E
Contact
name (	Rname
url (	Rurl
email (	Remail"/
License
name (	Rname
url (	Rurl"K
ExternalDocumentation 
description (	Rdescription
url (	Rurl"�
SchemaV
json_schema (25.grpc.gateway.protoc_gen_openapiv2.options.JSONSchemaR
jsonSchema$
discriminator (	Rdiscriminator
	read_only (RreadOnlye
external_docs (2@.grpc.gateway.protoc_gen_openapiv2.options.ExternalDocumentationRexternalDocs
example (	RexampleJ"�


JSONSchema
ref (	Rref
title (	Rtitle 
description (	Rdescription
default (	Rdefault
	read_only (RreadOnly
example	 (	Rexample
multiple_of
 (R
multipleOf
maximum (Rmaximum+
exclusive_maximum (RexclusiveMaximum
minimum (Rminimum+
exclusive_minimum (RexclusiveMinimum

max_length (R	maxLength

min_length (R	minLength
pattern (	Rpattern
	max_items (RmaxItems
	min_items (RminItems!
unique_items (RuniqueItems%
max_properties (RmaxProperties%
min_properties (RminProperties
required (	Rrequired
array" (	Rarray_
type# (2K.grpc.gateway.protoc_gen_openapiv2.options.JSONSchema.JSONSchemaSimpleTypesRtype
format$ (	Rformat
enum. (	Renumz
field_configuration� (2H.grpc.gateway.protoc_gen_openapiv2.options.JSONSchema.FieldConfigurationRfieldConfiguratione

extensions0 (2E.grpc.gateway.protoc_gen_openapiv2.options.JSONSchema.ExtensionsEntryR
extensions<
FieldConfiguration&
path_param_name/ (	RpathParamNameU
ExtensionsEntry
key (	Rkey,
value (2.google.protobuf.ValueRvalue:8"w
JSONSchemaSimpleTypes
UNKNOWN 	
ARRAY
BOOLEAN
INTEGER
NULL

NUMBER

OBJECT

STRINGJJJJJJJJJJ"J%*J*+J+."�
Tag
name (	Rname 
description (	Rdescriptione
external_docs (2@.grpc.gateway.protoc_gen_openapiv2.options.ExternalDocumentationRexternalDocs^

extensions (2>.grpc.gateway.protoc_gen_openapiv2.options.Tag.ExtensionsEntryR
extensionsU
ExtensionsEntry
key (	Rkey,
value (2.google.protobuf.ValueRvalue:8"�
SecurityDefinitionsh
security (2L.grpc.gateway.protoc_gen_openapiv2.options.SecurityDefinitions.SecurityEntryRsecurityv
SecurityEntry
key (	RkeyO
value (29.grpc.gateway.protoc_gen_openapiv2.options.SecuritySchemeRvalue:8"�
SecuritySchemeR
type (2>.grpc.gateway.protoc_gen_openapiv2.options.SecurityScheme.TypeRtype 
description (	Rdescription
name (	RnameL
in (2<.grpc.gateway.protoc_gen_openapiv2.options.SecurityScheme.InRinR
flow (2>.grpc.gateway.protoc_gen_openapiv2.options.SecurityScheme.FlowRflow+
authorization_url (	RauthorizationUrl
	token_url (	RtokenUrlI
scopes (21.grpc.gateway.protoc_gen_openapiv2.options.ScopesRscopesi

extensions	 (2I.grpc.gateway.protoc_gen_openapiv2.options.SecurityScheme.ExtensionsEntryR
extensionsU
ExtensionsEntry
key (	Rkey,
value (2.google.protobuf.ValueRvalue:8"K
Type
TYPE_INVALID 

TYPE_BASIC
TYPE_API_KEY
TYPE_OAUTH2"1
In

IN_INVALID 
IN_QUERY
	IN_HEADER"j
Flow
FLOW_INVALID 
FLOW_IMPLICIT
FLOW_PASSWORD
FLOW_APPLICATION
FLOW_ACCESS_CODE"�
SecurityRequirement�
security_requirement (2W.grpc.gateway.protoc_gen_openapiv2.options.SecurityRequirement.SecurityRequirementEntryRsecurityRequirement0
SecurityRequirementValue
scope (	Rscope�
SecurityRequirementEntry
key (	Rkeym
value (2W.grpc.gateway.protoc_gen_openapiv2.options.SecurityRequirement.SecurityRequirementValueRvalue:8"�
ScopesR
scope (2<.grpc.gateway.protoc_gen_openapiv2.options.Scopes.ScopeEntryRscope8

ScopeEntry
key (	Rkey
value (	Rvalue:8*;
Scheme
UNKNOWN 
HTTP	
HTTPS
WS
WSSBHZFgithub.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/optionsJ��
  �

  

 2
	
  &

 ]
	
 ]
c
 
 W Scheme describes the schemes supported by the OpenAPI Swagger
 and Operation objects.



 


  

  	

  

 

 

 	


 

 

 


 	

 

 

 


 

 	
�
 , g� `Swagger` is a representation of OpenAPI v2 specification's Swagger object.

 See: https://github.com/OAI/OpenAPI-Specification/blob/3.0.0/versions/2.0.md#swaggerObject

 Example:

  option (grpc.gateway.protoc_gen_openapiv2.options.openapiv2_swagger) = {
    info: {
      title: "Echo API";
      version: "1.0";
      description: "";
      contact: {
        name: "gRPC-Gateway project";
        url: "https://github.com/grpc-ecosystem/grpc-gateway";
        email: "none@example.com";
      };
      license: {
        name: "BSD 3-Clause License";
        url: "https://github.com/grpc-ecosystem/grpc-gateway/blob/main/LICENSE";
      };
    };
    schemes: HTTPS;
    consumes: "application/json";
    produces: "application/json";
  };




 ,
�
  0� Specifies the OpenAPI Specification version being used. It can be
 used by the OpenAPI UI and other clients to interpret the API listing. The
 value MUST be "2.0".


  0

  0	

  0
c
 3V Provides metadata about the API. The metadata can be used by the
 clients if needed.


 3

 3

 3
�
 8� The host (name or ip) serving the API. This MUST be the host only and does
 not include the scheme nor sub-paths. It MAY include a port. If the host is
 not included, the host serving the documentation is to be used (including
 the port). The host does not support path templating.


 8

 8	

 8
�
 B� The base path on which the API is served, which is relative to the host. If
 it is not included, the API is served directly under the host. The value
 MUST start with a leading slash (/). The basePath does not support path
 templating.
 Note that using `base_path` does not change the endpoint paths that are
 generated in the resulting OpenAPI file. If you wish to use `base_path`
 with relatively generated OpenAPI paths, the `base_path` prefix must be
 manually removed from your `google.api.http` paths and your code changed to
 serve the API from the `base_path`.


 B

 B	

 B
�
 F� The transfer protocol of the API. Values MUST be from the list: "http",
 "https", "ws", "wss". If the schemes is not included, the default scheme to
 be used is the one used to access the OpenAPI definition itself.


 F


 F

 F

 F
�
 J� A list of MIME types the APIs can consume. This is global to all APIs but
 can be overridden on specific API calls. Value MUST be as described under
 Mime Types.


 J


 J

 J

 J
�
 N� A list of MIME types the APIs can produce. This is global to all APIs but
 can be overridden on specific API calls. Value MUST be as described under
 Mime Types.


 N


 N

 N

 N
.
 	P" field 8 is reserved for 'paths'.


 	 P

 	 P

 	 P
�
 	Sw field 9 is reserved for 'definitions', which at this time are already
 exposed as and customizable as proto messages.


 	S

 	S

 	S
�
 V'� An object to hold responses that can be used across operations. This
 property does not define global responses for all operations.


 V

 V!

 V$&
U
 X0H Security scheme definitions that can be used across the specification.


 X

 X*

 X-/
�
 	]-� A declaration of which security schemes are applied for the API as a whole.
 The list of values describes alternative security schemes that can be used
 (that is, there is a logical OR between the security requirements).
 Individual operations can override this definition.


 	]


 	]

 	]'

 	]*,
�
 
`� A list of tags for API documentation control. Tags can be used for logical
 grouping of operations by resources or any other qualifier.


 
`


 
`

 
`

 
`
1
 b+$ Additional external documentation.


 b

 b%

 b(*
�
 f5� Custom properties that start with "x-" such as "x-foo" used to describe
 extra functionality that is not covered by the standard OpenAPI Specification.
 See: https://swagger.io/docs/specification/2-0/swagger-extensions/


 f$

 f%/

 f24
�
� �� `Operation` is a representation of OpenAPI v2 specification's Operation object.

 See: https://github.com/OAI/OpenAPI-Specification/blob/3.0.0/versions/2.0.md#operationObject

 Example:

  service EchoService {
    rpc Echo(SimpleMessage) returns (SimpleMessage) {
      option (google.api.http) = {
        get: "/v1/example/echo/{id}"
      };

      option (grpc.gateway.protoc_gen_openapiv2.options.openapiv2_operation) = {
        summary: "Get a message.";
        operation_id: "getMessage";
        tags: "echo";
        responses: {
          key: "200"
            value: {
            description: "OK";
          }
        }
      };
    }
  }


�
�
 �� A list of tags for API documentation control. Tags can be used for logical
 grouping of operations by resources or any other qualifier.


 �


 �

 �

 �
�
�� A short summary of what the operation does. For maximum readability in the
 swagger-ui, this field SHOULD be less than 120 characters.


�

�	

�
v
�h A verbose explanation of the operation behavior. GFM syntax can be used for
 rich text representation.


�

�	

�
E
�*7 Additional external documentation for this operation.


�

�%

�()
�
�� Unique string used to identify the operation. The id MUST be unique among
 all operations described in the API. Tools and libraries MAY use the
 operationId to uniquely identify an operation, therefore, it is recommended
 to follow common programming naming conventions.


�

�	

�
�
�� A list of MIME types the operation can consume. This overrides the consumes
 definition at the OpenAPI Object. An empty value MAY be used to clear the
 global definition. Value MUST be as described under Mime Types.


�


�

�

�
�
�� A list of MIME types the operation can produce. This overrides the produces
 definition at the OpenAPI Object. An empty value MAY be used to clear the
 global definition. Value MUST be as described under Mime Types.


�


�

�

�
4
	�' field 8 is reserved for 'parameters'.


	 �

	 �

	 �
c
�&U The list of possible responses as they are returned from executing this
 operation.


�

�!

�$%
�
�� The transfer protocol for the operation. Values MUST be from the list:
 "http", "https", "ws", "wss". The value overrides the OpenAPI Object
 schemes definition.


�


�

�

�
�
	�y Declares this operation to be deprecated. Usage of the declared operation
 should be refrained. Default value is false.


	�

	�

	�
�

�-� A declaration of which security schemes are applied for this operation. The
 list of values describes alternative security schemes that can be used
 (that is, there is a logical OR between the security requirements). This
 definition overrides any declared top-level security. To remove a top-level
 security declaration, an empty array can be used.



�



�


�'


�*,
�
�5� Custom properties that start with "x-" such as "x-foo" used to describe
 extra functionality that is not covered by the standard OpenAPI Specification.
 See: https://swagger.io/docs/specification/2-0/swagger-extensions/


�$

�%/

�24
�
�� Custom parameters such as HTTP request headers.
 See: https://swagger.io/docs/specification/2-0/describing-parameters/
 and https://swagger.io/specification/v2/#parameter-object.


�

�

�
�
� �� `Parameters` is a representation of OpenAPI v2 specification's parameters object.
 Note: This technically breaks compatibility with the OpenAPI 2 definition structure as we only
 allow header parameters to be set here since we do not want users specifying custom non-header
 parameters beyond those inferred from the Protobuf schema.
 See: https://swagger.io/specification/v2/#parameter-object


�
�
 �'� `Headers` is one or more HTTP header parameter.
 See: https://swagger.io/docs/specification/2-0/describing-parameters/#header-parameters


 �


 �

 �"

 �%&
v
� �h `HeaderParameter` a HTTP header parameter.
 See: https://swagger.io/specification/v2/#parameter-object


�
t
 ��d `Type` is a a supported HTTP header type.
 See https://swagger.io/specification/v2/#parameterType.


 �

  �

  �

  �

 �

 �


 �

 �

 �


 �

 �

 �

 �

 �

 �

 �
*
 � `Name` is the header name.


 �

 �	

 �
C
�5 `Description` is a short description of the header.


�

�	

�
�
�� `Type` is the type of the object. The value MUST be one of "string", "number", "integer", or "boolean". The "array" type is not supported.
 See: https://swagger.io/specification/v2/#parameterType.


�

�

�
P
�B `Format` The extending format for the previously mentioned type.


�

�	

�
>
�0 `Required` indicates if the header is optional


�

�

�
L
	�? field 6 is reserved for 'items', but in OpenAPI-specific way.


	 �

	 �

	 �
q
	�d field 7 is reserved `Collection Format`. Determines the format of the array if type array is used.


	�

	�

	�
�
� �� `Header` is a representation of OpenAPI v2 specification's Header object.

 See: https://github.com/OAI/OpenAPI-Specification/blob/3.0.0/versions/2.0.md#headerObject



�
C
 �5 `Description` is a short description of the header.


 �

 �	

 �
�
�� The type of the object. The value MUST be one of "string", "number", "integer", or "boolean". The "array" type is not supported.


�

�	

�
P
�B `Format` The extending format for the previously mentioned type.


�

�	

�
L
	�? field 4 is reserved for 'items', but in OpenAPI-specific way.


	 �

	 �

	 �
p
	�c field 5 is reserved `Collection Format` Determines the format of the array if type array is used.


	�

	�

	�
�
�� `Default` Declares the value of the header that the server will use if none is provided.
 See: https://tools.ietf.org/html/draft-fge-json-schema-validation-00#section-6.2.
 Unlike JSON Schema this value MUST conform to the defined type for the header.


�

�	

�
1
	�$ field 7 is reserved for 'maximum'.


	�

	�

	�
:
	�- field 8 is reserved for 'exclusiveMaximum'.


	�

	�

	�
1
	�$ field 9 is reserved for 'minimum'.


	�

	�

	�
;
	�. field 10 is reserved for 'exclusiveMinimum'.


	�

	�

	�
4
	�' field 11 is reserved for 'maxLength'.


	�

	�

	�
4
	�' field 12 is reserved for 'minLength'.


	�

	�

	�
l
�^ 'Pattern' See https://tools.ietf.org/html/draft-fge-json-schema-validation-00#section-5.2.3.


�

�	

�
3
	�& field 14 is reserved for 'maxItems'.


	�

	�

	�
3
	�& field 15 is reserved for 'minItems'.


		�

		�

		�
6
	�) field 16 is reserved for 'uniqueItems'.


	
�

	
�

	
�
/
	�" field 17 is reserved for 'enum'.


	�

	�

	�
5
	�( field 18 is reserved for 'multipleOf'.


	�

	�

	�
�
� �� `Response` is a representation of OpenAPI v2 specification's Response object.

 See: https://github.com/OAI/OpenAPI-Specification/blob/3.0.0/versions/2.0.md#responseObject



�
{
 �m `Description` is a short description of the response.
 GFM syntax can be used for rich text representation.


 �

 �	

 �
�
�� `Schema` optionally defines the structure of the response.
 If `Schema` is not provided, it means there is no content to the response.


�

�	

�
�
�"� `Headers` A list of headers that are sent with the response.
 `Header` name is expected to be a string in the canonical format of the MIME header key
 See: https://golang.org/pkg/net/textproto/#CanonicalMIMEHeaderKey


�

�

� !
�
�#� `Examples` gives per-mimetype response examples.
 See: https://github.com/OAI/OpenAPI-Specification/blob/3.0.0/versions/2.0.md#example-object


�

�

�!"
�
�4� Custom properties that start with "x-" such as "x-foo" used to describe
 extra functionality that is not covered by the standard OpenAPI Specification.
 See: https://swagger.io/docs/specification/2-0/swagger-extensions/


�$

�%/

�23
�
� �� `Info` is a representation of OpenAPI v2 specification's Info object.

 See: https://github.com/OAI/OpenAPI-Specification/blob/3.0.0/versions/2.0.md#infoObject

 Example:

  option (grpc.gateway.protoc_gen_openapiv2.options.openapiv2_swagger) = {
    info: {
      title: "Echo API";
      version: "1.0";
      description: "";
      contact: {
        name: "gRPC-Gateway project";
        url: "https://github.com/grpc-ecosystem/grpc-gateway";
        email: "none@example.com";
      };
      license: {
        name: "BSD 3-Clause License";
        url: "https://github.com/grpc-ecosystem/grpc-gateway/blob/main/LICENSE";
      };
    };
    ...
  };



�
-
 � The title of the application.


 �

 �	

 �
m
�_ A short description of the application. GFM syntax can be used for rich
 text representation.


�

�	

�
1
�# The Terms of Service for the API.


�

�	

�
<
�. The contact information for the exposed API.


�	

�


�
<
�. The license information for the exposed API.


�	

�


�
q
�c Provides the version of the application API (not to be confused
 with the specification version).


�

�	

�
�
�4� Custom properties that start with "x-" such as "x-foo" used to describe
 extra functionality that is not covered by the standard OpenAPI Specification.
 See: https://swagger.io/docs/specification/2-0/swagger-extensions/


�$

�%/

�23
�
� �� `Contact` is a representation of OpenAPI v2 specification's Contact object.

 See: https://github.com/OAI/OpenAPI-Specification/blob/3.0.0/versions/2.0.md#contactObject

 Example:

  option (grpc.gateway.protoc_gen_openapiv2.options.openapiv2_swagger) = {
    info: {
      ...
      contact: {
        name: "gRPC-Gateway project";
        url: "https://github.com/grpc-ecosystem/grpc-gateway";
        email: "none@example.com";
      };
      ...
    };
    ...
  };



�
H
 �: The identifying name of the contact person/organization.


 �

 �	

 �
]
�O The URL pointing to the contact information. MUST be in the format of a
 URL.


�

�	

�
q
�c The email address of the contact person/organization. MUST be in the format
 of an email address.


�

�	

�
�
� �� `License` is a representation of OpenAPI v2 specification's License object.

 See: https://github.com/OAI/OpenAPI-Specification/blob/3.0.0/versions/2.0.md#licenseObject

 Example:

  option (grpc.gateway.protoc_gen_openapiv2.options.openapiv2_swagger) = {
    info: {
      ...
      license: {
        name: "BSD 3-Clause License";
        url: "https://github.com/grpc-ecosystem/grpc-gateway/blob/main/LICENSE";
      };
      ...
    };
    ...
  };



�
2
 �$ The license name used for the API.


 �

 �	

 �
V
�H A URL to the license used for the API. MUST be in the format of a URL.


�

�	

�
�
	� �� `ExternalDocumentation` is a representation of OpenAPI v2 specification's
 ExternalDocumentation object.

 See: https://github.com/OAI/OpenAPI-Specification/blob/3.0.0/versions/2.0.md#externalDocumentationObject

 Example:

  option (grpc.gateway.protoc_gen_openapiv2.options.openapiv2_swagger) = {
    ...
    external_docs: {
      description: "More about gRPC-Gateway";
      url: "https://github.com/grpc-ecosystem/grpc-gateway";
    }
    ...
  };



	�
v
	 �h A short description of the target documentation. GFM syntax can be used for
 rich text representation.


	 �

	 �	

	 �
\
	�N The URL for the target documentation. Value MUST be in the format
 of a URL.


	�

	�	

	�
�

� �� `Schema` is a representation of OpenAPI v2 specification's Schema object.

 See: https://github.com/OAI/OpenAPI-Specification/blob/3.0.0/versions/2.0.md#schemaObject




�


 �


 �


 �


 �
�

�� Adds support for polymorphism. The discriminator is the schema property
 name that is used to differentiate between other schema that inherit this
 schema. The property name used MUST be defined at this schema and it MUST
 be in the required property list. When used, the value MUST be the name of
 this schema or any schema that inherits it.



�


�	


�
�

�� Relevant only for Schema "properties" definitions. Declares the property as
 "read only". This means that it MAY be sent as part of a response but MUST
 NOT be sent as part of the request. Properties marked as readOnly being
 true SHOULD NOT be in the required list of the defined schema. Default
 value is false.



�


�


�
-

	�  field 4 is reserved for 'xml'.



	 �


	 �


	 �
B

�*4 Additional external documentation for this schema.



�


�%


�()
�

�| A free-form property to include an example of an instance for this schema in JSON.
 This is copied verbatim to the output.



�


�	


�
�
� �� `JSONSchema` represents properties from JSON Schema taken, and as used, in
 the OpenAPI v2 spec.

 This includes changes made by OpenAPI v2.

 See: https://github.com/OAI/OpenAPI-Specification/blob/3.0.0/versions/2.0.md#schemaObject

 See also: https://cswr.github.io/JsonSchema/spec/basic_types/,
 https://github.com/json-schema-org/json-schema-spec/blob/master/schema.json

 Example:

  message SimpleMessage {
    option (grpc.gateway.protoc_gen_openapiv2.options.openapiv2_schema) = {
      json_schema: {
        title: "SimpleMessage"
        description: "A simple message."
        required: ["id"]
      }
    };

    // Id represents the message identifier.
    string id = 1; [
        (grpc.gateway.protoc_gen_openapiv2.options.openapiv2_field) = {
          description: "The unique identifier of the simple message."
        }];
  }



�
F
	�9 field 1 is reserved for '$id', omitted from OpenAPI v2.


	 �

	 �

	 �
J
	�= field 2 is reserved for '$schema', omitted from OpenAPI v2.


	�

	�

	�
�
 �� Ref is used to define an external reference to include in the message.
 This could be a fully qualified proto message reference, and that type must
 be imported into the protofile. If no message is identified, the Ref will
 be used verbatim in the output.
 For example:
  `ref: ".google.protobuf.Timestamp"`.


 �

 �	

 �
K
	�> field 4 is reserved for '$comment', omitted from OpenAPI v2.


	�

	�

	�
(
� The title of the schema.


�

�	

�
2
�$ A short description of the schema.


�

�	

�

�

�

�	

�

�

�

�

�
�
�� A free-form property to include a JSON example of this field. This is copied
 verbatim to the output swagger.json. Quotes must be escaped.
 This property is the same for 2.0 and 3.0.0 https://github.com/OAI/OpenAPI-Specification/blob/3.0.0/versions/3.0.0.md#schemaObject  https://github.com/OAI/OpenAPI-Specification/blob/3.0.0/versions/2.0.md#schemaObject


�

�	

�

�

�

�	

�
s
�e Maximum represents an inclusive upper limit for a numeric instance. The
 value of MUST be a number,


�

�	

�

�

�

�

�
s
	�e minimum represents an inclusive lower limit for a numeric instance. The
 value of MUST be a number,


	�

	�	

	�


�


�


�


�

�

�

�	

�

�

�

�	

�

�

�

�	

�
S
	�F field 18 is reserved for 'additionalItems', omitted from OpenAPI v2.


	�

	�

	�
j
	�] field 19 is reserved for 'items', but in OpenAPI-specific way.
 TODO(ivucica): add 'items'?


	�

	�

	�

�

�

�	

�

�

�

�	

�

�

�

�

�
L
	�? field 23 is reserved for 'contains', omitted from OpenAPI v2.


	�

	�

	�

�

�

�	

�

�

�

�	

�

� 

�


�

�

�
�
	�{ field 27 is reserved for 'additionalProperties', but in OpenAPI-specific
 way. TODO(ivucica): add 'additionalProperties'?


	�

	�

	�
O
	�B field 28 is reserved for 'definitions', omitted from OpenAPI v2.


	�

	�

	�
~
	�q field 29 is reserved for 'properties', but in OpenAPI-specific way.
 TODO(ivucica): add 'additionalProperties'?


	�

	�

	�
�
	�� following fields are reserved, as the properties have been omitted from
 OpenAPI v2:
 patternProperties, dependencies, propertyNames, const


		�

		�

		�
0
�" Items in 'array' must be unique.


�


�

�

�

 ��

 �

  �

  �

  �

 �

 �	

 �

 �

 �

 �

 �

 �

 �

 �

 �

 �

 �

 �


 �

 �

 �


 �

 �

 �


 �

�+

�


� 

�!%

�(*

�
 `Format`


�

�	

�
�
	�� following fields are reserved, as the properties have been omitted from
 OpenAPI v2: contentMediaType, contentEncoding, if, then, else


	
�

	
�

	
�
j
	�] field 42 is reserved for 'allOf', but in OpenAPI-specific way.
 TODO(ivucica): add 'allOf'?


	�

	�

	�
v
	�i following fields are reserved, as the properties have been omitted from
 OpenAPI v2:
 anyOf, oneOf, not


	�

	�

	�
|
�n Items in `enum` must be unique https://tools.ietf.org/html/draft-fge-json-schema-validation-00#section-5.5.1


�


�

�

�
[
�0M Additional field level properties used when generating the OpenAPI v2 file.


�

�(

�+/
�
 ��� 'FieldConfiguration' provides additional field level properties used when generating the OpenAPI v2 file.
 These properties are not defined by OpenAPIv2, but they are used to control the generation.


 �

�
  � � Alternative parameter name when used as path parameter. If set, this will
 be used as the complete parameter name when this field is used as a path
 parameter. Use this to avoid having auto generated path parameter names
 for overlapping paths.


  �


  �

  �
�
�5� Custom properties that start with "x-" such as "x-foo" used to describe
 extra functionality that is not covered by the standard OpenAPI Specification.
 See: https://swagger.io/docs/specification/2-0/swagger-extensions/


�$

�%/

�24
�
� �� `Tag` is a representation of OpenAPI v2 specification's Tag object.

 See: https://github.com/OAI/OpenAPI-Specification/blob/3.0.0/versions/2.0.md#tagObject



�
�
 �� The name of the tag. Use it to allow override of the name of a
 global Tag object, then use that name to reference the tag throughout the
 OpenAPI file.


 �

 �	

 �
f
�X A short description for the tag. GFM syntax can be used for rich text
 representation.


�

�	

�
?
�*1 Additional external documentation for this tag.


�

�%

�()
�
�4� Custom properties that start with "x-" such as "x-foo" used to describe
 extra functionality that is not covered by the standard OpenAPI Specification.
 See: https://swagger.io/docs/specification/2-0/swagger-extensions/


�$

�%/

�23
�
� �� `SecurityDefinitions` is a representation of OpenAPI v2 specification's
 Security Definitions object.

 See: https://github.com/OAI/OpenAPI-Specification/blob/3.0.0/versions/2.0.md#securityDefinitionsObject

 A declaration of the security schemes available to be used in the
 specification. This does not enforce the security schemes on the operations
 and only serves to provide the relevant details for each scheme.


�
`
 �+R A single security scheme definition, mapping a "name" to the scheme it
 defines.


 �

 �&

 �)*
�
� �� `SecurityScheme` is a representation of OpenAPI v2 specification's
 Security Scheme object.

 See: https://github.com/OAI/OpenAPI-Specification/blob/3.0.0/versions/2.0.md#securitySchemeObject

 Allows the definition of a security scheme that can be used by the
 operations. Supported schemes are basic authentication, an API key (either as
 a header or as a query parameter) and OAuth2's common flows (implicit,
 password, application and access code).


�
c
 ��S The type of the security scheme. Valid values are "basic",
 "apiKey" or "oauth2".


 �

  �

  �

  �

 �

 �

 �

 �

 �

 �

 �

 �

 �
T
��D The location of the API key. Valid values are "query" or "header".


�	

 �

 �

 �

�

�

�

�

�

�
�
��w The flow used by the OAuth2 security scheme. Valid values are
 "implicit", "password", "application" or "accessCode".


�

 �

 �

 �

�

�

�

�

�

�

�

�

�

�

�

�
a
 �S The type of the security scheme. Valid values are "basic",
 "apiKey" or "oauth2".


 �

 �

 �
8
�* A short description for security scheme.


�

�	

�
X
�J The name of the header or query parameter to be used.
 Valid for apiKey.


�

�	

�
f
�X The location of the API key. Valid values are "query" or
 "header".
 Valid for apiKey.


�

�

�

�
�� The flow used by the OAuth2 security scheme. Valid values are
 "implicit", "password", "application" or "accessCode".
 Valid for oauth2.


�

�

�
�
�� The authorization URL to be used for this flow. This SHOULD be in
 the form of a URL.
 Valid for oauth2/implicit and oauth2/accessCode.


�

�	

�
�
�� The token URL to be used for this flow. This SHOULD be in the
 form of a URL.
 Valid for oauth2/password, oauth2/application and oauth2/accessCode.


�

�	

�
W
�I The available scopes for the OAuth2 security scheme.
 Valid for oauth2.


�

�	

�
�
�4� Custom properties that start with "x-" such as "x-foo" used to describe
 extra functionality that is not covered by the standard OpenAPI Specification.
 See: https://swagger.io/docs/specification/2-0/swagger-extensions/


�$

�%/

�23
�
� �� `SecurityRequirement` is a representation of OpenAPI v2 specification's
 Security Requirement object.

 See: https://github.com/OAI/OpenAPI-Specification/blob/3.0.0/versions/2.0.md#securityRequirementObject

 Lists the required security schemes to execute this operation. The object can
 have multiple security schemes declared in it which are all required (that
 is, there is a logical AND between the schemes).

 The name used for each property MUST correspond to a security scheme
 declared in the Security Definitions.


�
�
 ��� If the security scheme is of type "oauth2", then the value is a list of
 scope names required for the execution. For other security scheme types,
 the array MUST be empty.


 �
"

  �

  �

  �

  �

  �
�
 �A� Each name must correspond to a security scheme which is declared in
 the Security Definitions. If the security scheme is of type "oauth2",
 then the value is a list of scope names required for the execution.
 For other security scheme types, the array MUST be empty.


 �'

 �(<

 �?@
�
� �� `Scopes` is a representation of OpenAPI v2 specification's Scopes object.

 See: https://github.com/OAI/OpenAPI-Specification/blob/3.0.0/versions/2.0.md#scopesObject

 Lists the available scopes for an OAuth2 security scheme.


�
l
 � ^ Maps between a name of a scope to a short description of it (as the value
 of the property).


 �

 �

 �bproto3��SM
)
	buf.buildgrpc-ecosystemgrpc-gateway 3f42134f4c564983838425bc43c7a65f 
�
.protoc-gen-openapiv2/options/annotations.proto)grpc.gateway.protoc_gen_openapiv2.options google/protobuf/descriptor.proto,protoc-gen-openapiv2/options/openapiv2.proto:~
openapiv2_swagger.google.protobuf.FileOptions� (22.grpc.gateway.protoc_gen_openapiv2.options.SwaggerRopenapiv2Swagger:�
openapiv2_operation.google.protobuf.MethodOptions� (24.grpc.gateway.protoc_gen_openapiv2.options.OperationRopenapiv2Operation:~
openapiv2_schema.google.protobuf.MessageOptions� (21.grpc.gateway.protoc_gen_openapiv2.options.SchemaRopenapiv2Schema:u
openapiv2_tag.google.protobuf.ServiceOptions� (2..grpc.gateway.protoc_gen_openapiv2.options.TagRopenapiv2Tag:~
openapiv2_field.google.protobuf.FieldOptions� (25.grpc.gateway.protoc_gen_openapiv2.options.JSONSchemaRopenapiv2FieldBHZFgithub.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2/optionsJ�
  +

  

 2
	
  *
	
 6

 ]
	
 ]
	
	 
�
 #� ID assigned by protobuf-global-extension-registry@google.com for gRPC-Gateway project.

 All IDs are the same, as assigned. It is okay that they are the same, as they extend
 different descriptor messages.



 	"


 	


 



 "
	
 
�
'� ID assigned by protobuf-global-extension-registry@google.com for gRPC-Gateway project.

 All IDs are the same, as assigned. It is okay that they are the same, as they extend
 different descriptor messages.



$








"&
	
 
�
!� ID assigned by protobuf-global-extension-registry@google.com for gRPC-Gateway project.

 All IDs are the same, as assigned. It is okay that they are the same, as they extend
 different descriptor messages.



%





	


 
	
 $
�
#� ID assigned by protobuf-global-extension-registry@google.com for gRPC-Gateway project.

 All IDs are the same, as assigned. It is okay that they are the same, as they extend
 different descriptor messages.



%


#


#


#
	
% +
�
*$� ID assigned by protobuf-global-extension-registry@google.com for gRPC-Gateway project.

 All IDs are the same, as assigned. It is okay that they are the same, as they extend
 different descriptor messages.



%#


*


*


*#bproto3��SM
)
	buf.buildgrpc-ecosystemgrpc-gateway 3f42134f4c564983838425bc43c7a65f 
�
kas/kas.protokasgoogle/api/annotations.protogoogle/protobuf/struct.protogoogle/protobuf/wrappers.proto.protoc-gen-openapiv2/options/annotations.proto"
InfoRequest"(
InfoResponse
version (	Rversion"6
LegacyPublicKeyRequest
	algorithm (	R	algorithm"l
PublicKeyRequest
	algorithm (	R	algorithm
fmt (	B�A	2versionRfmt
v (	B�A	2versionRv"2
PublicKeyResponse

public_key (	R	publicKey"A
RewrapRequest0
signed_request_token (	RsignedRequestToken"�
RewrapResponse=
metadata (2!.kas.RewrapResponse.MetadataEntryRmetadata,
entity_wrapped_key (RentityWrappedKey,
session_public_key (	RsessionPublicKey%
schema_version (	RschemaVersionS
MetadataEntry
key (	Rkey,
value (2.google.protobuf.ValueRvalue:82�
AccessServiceE
Info.kas.InfoRequest.kas.InfoResponse"�A	J
200 ���/kasf
	PublicKey.kas.PublicKeyRequest.kas.PublicKeyResponse"*�A	J
200 ���/kas/v2/kas_public_keyu
LegacyPublicKey.kas.LegacyPublicKeyRequest.google.protobuf.StringValue"'�A	J
200 ���/kas/kas_public_keyX
Rewrap.kas.RewrapRequest.kas.RewrapResponse"%�A	J
200 ���:*"/kas/v2/rewrapBv�Asq
OpenTDF Key Access Service*L
BSD 3-Clause Clear6https://github.com/opentdf/backend/blob/master/LICENSE21.5.0J�
  \

  

 
	
  &
	
 &
	
 (
	
 8
	
	 

�	 
>
  "2 Intentionally empty. May include features later.



 
0
 $ Service application level metadata





 

 

 	

 


 




 

 

 	

 


! %


!

 "

 "

 "	

 "

#j

#

#	

#

#i

�#h

$h

$

$	


$

$g

�$f


' )


'

 (

 (

 (	

 (


+ -


+

 ,"

 ,

 ,	

 , !


/ 4


/

 02

 0$

 0%-

 001

1

1

1

1

2 

2

2	

2

3

3

3	

3
-
 7 \! Get app info from the root path



 7
6
  9?( Get the current version of the service


  9


  9

  9!-

  :-

	  �ʼ":-

  <>

  �<>

 AG

 A

 A 

 A+<

 B?

	 �ʼ"B?

 DF

 �DF
:
 JP, buf:lint:ignore RPC_RESPONSE_STANDARD_NAME


 J

 J,

 J7R

 K<

	 �ʼ"K<

 MO

 �MO

 R[

 R

 R

 R%3

 SV

	 �ʼ"SV

 XZ

 �XZbproto3��  
�
policy/selectors.protopolicy"�
AttributeNamespaceSelector]
with_attributes
 (24.policy.AttributeNamespaceSelector.AttributeSelectorRwithAttributes�
AttributeSelector3
with_key_access_grants (RwithKeyAccessGrantsc
with_values
 (2B.policy.AttributeNamespaceSelector.AttributeSelector.ValueSelectorR
withValues�
ValueSelector3
with_key_access_grants (RwithKeyAccessGrants*
with_subject_maps (RwithSubjectMaps,
with_resource_maps (RwithResourceMaps"�
AttributeDefinitionSelector3
with_key_access_grants (RwithKeyAccessGrants\
with_namespace
 (25.policy.AttributeDefinitionSelector.NamespaceSelectorRwithNamespaceR
with_values (21.policy.AttributeDefinitionSelector.ValueSelectorR
withValues
NamespaceSelector�
ValueSelector3
with_key_access_grants (RwithKeyAccessGrants*
with_subject_maps (RwithSubjectMaps,
with_resource_maps (RwithResourceMaps"�
AttributeValueSelector3
with_key_access_grants (RwithKeyAccessGrants*
with_subject_maps (RwithSubjectMaps,
with_resource_maps (RwithResourceMapsW
with_attribute
 (20.policy.AttributeValueSelector.AttributeSelectorRwithAttribute�
AttributeSelector3
with_key_access_grants (RwithKeyAccessGrantsi
with_namespace
 (2B.policy.AttributeValueSelector.AttributeSelector.NamespaceSelectorRwithNamespace
NamespaceSelectorJ�

  ,

  

 


  


 "

  	

  !

   0

   

   +

   ./

   

   %

    	8

	    	

	    	3

	    	67

   
3

	   


	   
.

	   
12

   4

	   

	   /

	   23

  /

  

  )

  ,.

  /

  

  )

  ,.


 


#

 (

 

 #

 &'

 $

 !

.



(

+-





 0

 

 +

 ./

+



&

)*

,



'

*+

'



!

$&


  ,


 

 !(

 !

 !#

 !&'

"#

"

"

"!"

#$

#

#

#"#

 %*

 %!

  &0

  &

  &+

  &./

  (,

  ()

 )6

 )!

 )"0

 )35

+.

+

+(

++-bproto3��  
�o
"policy/attributes/attributes.protopolicy.attributesbuf/validate/validate.protocommon/common.protogoogle/api/annotations.protopolicy/objects.protopolicy/selectors.proto"n
AttributeKeyAccessServer!
attribute_id (	RattributeId/
key_access_server_id (	RkeyAccessServerId"b
ValueKeyAccessServer
value_id (	RvalueId/
key_access_server_id (	RkeyAccessServerId"d
ListAttributesRequest-
state (2.common.ActiveStateEnumRstate
	namespace (	R	namespace"K
ListAttributesResponse1

attributes (2.policy.AttributeR
attributes"-
GetAttributeRequest
id (	B�H�Rid"G
GetAttributeResponse/
	attribute (2.policy.AttributeR	attribute"�
CreateAttributeRequest)
namespace_id (	B�H�RnamespaceId�
name (	B��H���
attribute_name_format�Attribute name must be an alphanumeric string, allowing hyphens and underscores but not as the first or last character. The stored attribute name will be normalized to lower case.;this.matches('^[a-zA-Z0-9](?:[a-zA-Z0-9_-]*[a-zA-Z0-9])?$')�r�Rname>
rule (2.policy.AttributeRuleTypeEnumB�H��RruleV
values (	B>�H;�8 "2r0�2+^[a-zA-Z0-9](?:[a-zA-Z0-9_-]*[a-zA-Z0-9])?$Rvalues3
metadatad (2.common.MetadataMutableRmetadata"J
CreateAttributeResponse/
	attribute (2.policy.AttributeR	attribute"�
UpdateAttributeRequest
id (	B�H�Rid3
metadatad (2.common.MetadataMutableRmetadataT
metadata_update_behaviore (2.common.MetadataUpdateEnumRmetadataUpdateBehavior"J
UpdateAttributeResponse/
	attribute (2.policy.AttributeR	attribute"4
DeactivateAttributeRequest
id (	B�H�Rid"N
DeactivateAttributeResponse/
	attribute (2.policy.AttributeR	attribute"2
GetAttributeValueRequest
id (	B�H�Rid"@
GetAttributeValueResponse#
value (2.policy.ValueRvalue"v
ListAttributeValuesRequest)
attribute_id (	B�H�RattributeId-
state (2.common.ActiveStateEnumRstate"D
ListAttributeValuesResponse%
values (2.policy.ValueRvalues"�
CreateAttributeValueRequest)
attribute_id (	B�H�RattributeId�
value (	B��H���
attribute_value_format�Attribute value must be an alphanumeric string, allowing hyphens and underscores but not as the first or last character. The stored attribute value will be normalized to lower case.;this.matches('^[a-zA-Z0-9](?:[a-zA-Z0-9_-]*[a-zA-Z0-9])?$')�r�Rvalue
members (	Rmembers3
metadatad (2.common.MetadataMutableRmetadata"C
CreateAttributeValueResponse#
value (2.policy.ValueRvalue"�
UpdateAttributeValueRequest
id (	B�H�Rid
members (	Rmembers3
metadatad (2.common.MetadataMutableRmetadataT
metadata_update_behaviore (2.common.MetadataUpdateEnumRmetadataUpdateBehavior"C
UpdateAttributeValueResponse#
value (2.policy.ValueRvalue"9
DeactivateAttributeValueRequest
id (	B�H�Rid"G
 DeactivateAttributeValueResponse#
value (2.policy.ValueRvalue"�
GetAttributeValuesByFqnsRequest
fqns (	B�H�RfqnsE

with_value (2.policy.AttributeValueSelectorB�H�R	withValue"�
 GetAttributeValuesByFqnsResponse}
fqn_attribute_values (2K.policy.attributes.GetAttributeValuesByFqnsResponse.FqnAttributeValuesEntryRfqnAttributeValuesi
AttributeAndValue/
	attribute (2.policy.AttributeR	attribute#
value (2.policy.ValueRvalue�
FqnAttributeValuesEntry
key (	Rkey[
value (2E.policy.attributes.GetAttributeValuesByFqnsResponse.AttributeAndValueRvalue:8"�
'AssignKeyAccessServerToAttributeRequestj
attribute_key_access_server (2+.policy.attributes.AttributeKeyAccessServerRattributeKeyAccessServer"�
(AssignKeyAccessServerToAttributeResponsej
attribute_key_access_server (2+.policy.attributes.AttributeKeyAccessServerRattributeKeyAccessServer"�
)RemoveKeyAccessServerFromAttributeRequestj
attribute_key_access_server (2+.policy.attributes.AttributeKeyAccessServerRattributeKeyAccessServer"�
*RemoveKeyAccessServerFromAttributeResponsej
attribute_key_access_server (2+.policy.attributes.AttributeKeyAccessServerRattributeKeyAccessServer"�
#AssignKeyAccessServerToValueRequest^
value_key_access_server (2'.policy.attributes.ValueKeyAccessServerRvalueKeyAccessServer"�
$AssignKeyAccessServerToValueResponse^
value_key_access_server (2'.policy.attributes.ValueKeyAccessServerRvalueKeyAccessServer"�
%RemoveKeyAccessServerFromValueRequest^
value_key_access_server (2'.policy.attributes.ValueKeyAccessServerRvalueKeyAccessServer"�
&RemoveKeyAccessServerFromValueResponse^
value_key_access_server (2'.policy.attributes.ValueKeyAccessServerRvalueKeyAccessServer2�
AttributesServicez
ListAttributes(.policy.attributes.ListAttributesRequest).policy.attributes.ListAttributesResponse"���/attributes�
ListAttributeValues-.policy.attributes.ListAttributeValuesRequest..policy.attributes.ListAttributeValuesResponse"���/attributes/*/valuesy
GetAttribute&.policy.attributes.GetAttributeRequest'.policy.attributes.GetAttributeResponse"���/attributes/{id}�
GetAttributeValuesByFqns2.policy.attributes.GetAttributeValuesByFqnsRequest3.policy.attributes.GetAttributeValuesByFqnsResponse"���/attributes/*/fqn�
CreateAttribute).policy.attributes.CreateAttributeRequest*.policy.attributes.CreateAttributeResponse"���:*"/attributes�
UpdateAttribute).policy.attributes.UpdateAttributeRequest*.policy.attributes.UpdateAttributeResponse"���:*2/attributes/{id}�
DeactivateAttribute-.policy.attributes.DeactivateAttributeRequest..policy.attributes.DeactivateAttributeResponse"���*/attributes/{id}�
GetAttributeValue+.policy.attributes.GetAttributeValueRequest,.policy.attributes.GetAttributeValueResponse"!���/attributes/*/values/{id}�
CreateAttributeValue..policy.attributes.CreateAttributeValueRequest/.policy.attributes.CreateAttributeValueResponse",���&:*"!/attributes/{attribute_id}/values�
UpdateAttributeValue..policy.attributes.UpdateAttributeValueRequest/.policy.attributes.UpdateAttributeValueResponse"$���:*2/attributes/*/values/{id}�
DeactivateAttributeValue2.policy.attributes.DeactivateAttributeValueRequest3.policy.attributes.DeactivateAttributeValueResponse"!���*/attributes/*/values/{id}�
 AssignKeyAccessServerToAttribute:.policy.attributes.AssignKeyAccessServerToAttributeRequest;.policy.attributes.AssignKeyAccessServerToAttributeResponse"G���A:attribute_key_access_server""/attributes/keyaccessserver/assign�
"RemoveKeyAccessServerFromAttribute<.policy.attributes.RemoveKeyAccessServerFromAttributeRequest=.policy.attributes.RemoveKeyAccessServerFromAttributeResponse"G���A:attribute_key_access_server""/attributes/keyaccessserver/remove�
AssignKeyAccessServerToValue6.policy.attributes.AssignKeyAccessServerToValueRequest7.policy.attributes.AssignKeyAccessServerToValueResponse"J���D:value_key_access_server")/attributes/values/keyaccessserver/assign�
RemoveKeyAccessServerFromValue8.policy.attributes.RemoveKeyAccessServerFromValueRequest9.policy.attributes.RemoveKeyAccessServerFromValueResponse"J���D:value_key_access_server")/attributes/values/keyaccessserver/removeJ�6
  �

  

 
	
  %
	
 
	
 &
	
 
	
  
&
  2
Key Access Server Grants



  

  

  

  	

  

 "

 

 	

  !


 




 

 

 	

 

"



	

 !
+
 !2
Attribute Service Definitions




3
 #& ACTIVE by default when not specified


 

 

 !"
 
  can be id or name


 

 	

 


" $


"

 #+

 #


 #

 #&

 #)*


& (


&

 '7

 '

 '	

 '

 '6

 �	'5


) +


)

 *!

 *

 *

 * 


- O


-

 /A
 Required


 /

 /	

 /

 /@

 �	/?

08

0

0	

0

08

�	1(

	�	2-

	�	 37

9<

9

9

9 

9!<

	�	:1

�	;(
�
?K� Optional attribute values (when provided) must be alphanumeric strings, allowing hyphens and underscores but not as the first or last character.
 The stored attribute value will be normalized to lower case.


?


?

?

?

?K

�	@J

N(
 Optional


N

N!

N$'


P R


P

 Q!

 Q

 Q

 Q 


T [


T

 V7
 Required


 V

 V	

 V

 V6

 �	V5

Y(
 Optional


Y

Y!

Y$'

Z;

Z

Z4

Z7:


	\ ^


	\

	 ]!

	 ]

	 ]

	 ] 



` b



`"


 a7


 a


 a	


 a


 a6


 �	a5


c e


c#

 d!

 d

 d

 d 
%
j l/
/ Value RPC messages
/



j 

 k7

 k

 k	

 k

 k6

 �	k5


m o


m!

 n

 n

 n

 n


q u


q"

 rA

 r

 r	

 r

 r@

 �	r?
3
t#& ACTIVE by default when not specified


t

t

t!"


v x


v#

 w#

 w


 w

 w

 w!"

z �


z#

 |A
 Required


 |

 |	

 |

 |@

 �	|?

}�

}

}	

}

}�

�	~(

	�	-

	�	 ��

�
 Optional


�


�

�

�

�( Common metadata


�

�!

�$'

� �

�$

 �

 �

 �

 �

� �

�#

 �7

 �

 �	

 �

 �6

 �	�5

�
 Optional


�


�

�

�

�( Common metadata


�

�!

�$'

�;

�

�4

�7:

� �

�$

 �

 �

 �

 �

� �

�'

 �7

 �

 �	

 �

 �6

 �	�5

� �

�(

 �

 �

 �

 �

� �

�'

 �B
 Required


 �


 �

 �

 �

 �A

 �	�@

�V

�

� *

�-.

�/U

�	�0T

� �

�(

 ��

 �


  �#

  �

  �

  �!"

 �

 �

 �

 �
M
 �:? map of fqns to complete attributes and the one selected value


 � 

 �!5

 �89
?
� �21
Assign Key Access Server to Attribute and Value


�/

 �;

 �

 �6

 �9:

� �

�0

 �;

 �

 �6

 �9:

� �

�1

 �;

 �

 �6

 �9:

� �

�2

 �;

 �

 �6

 �9:

� �

�+

 �3

 �

 �.

 �12

� �

�,

 �3

 �

 �.

 �12

� �

�-

 �3

 �

 �.

 �12

� �

�.

 �3

 �

 �.

 �12
&
 � �/
/ Attribute Service
/


 �
o
  ��_--------------------------------------*
 Attribute RPCs
---------------------------------------

  �

  �*

  �5K

  �4

	  �ʼ"�4

 ��

 �

 �4

 �?Z

 �=

	 �ʼ"�=

 ��

 �

 �&

 �1E

 �9

	 �ʼ"�9

 ��

 �

 �>

 �Ii

 �:

	 �ʼ"�:

 ��

 �

 �,

 �7N

 ��

	 �ʼ"��

 ��

 �

 �,

 �7N

 ��

	 �ʼ"��

 ��

 �

 �4

 �?Z

 �<

	 �ʼ"�<
k
 ��[--------------------------------------*
 Value RPCs
---------------------------------------

 �

 �0

 �;T

 �B

	 �ʼ"�B

 ��

 �

 �6

 �A]

 ��

	 �ʼ"��

 	��

 	�

 	�6

 	�A]

 	��

	 	�ʼ"��

 
��

 
�

 
�>

 
�Ii

 
�E

	 
�ʼ"�E
�
 ��t--------------------------------------*
 Attribute <> Key Access Server RPCs
---------------------------------------

 �&

 �'N

 �Y�

 ��

	 �ʼ"��

 ��

 �(

 �)R

 �]�

 ��

	 �ʼ"��

 ��

 �"

 �#F

 �Qu

 ��

	 �ʼ"��

 ��

 �$

 �%J

 �U{

 ��

	 �ʼ"��bproto3��  
�
"policy/namespaces/namespaces.protopolicy.namespacesbuf/validate/validate.protogoogle/api/annotations.protocommon/common.protopolicy/objects.proto"-
GetNamespaceRequest
id (	B�H�Rid"G
GetNamespaceResponse/
	namespace (2.policy.NamespaceR	namespace"F
ListNamespacesRequest-
state (2.common.ActiveStateEnumRstate"K
ListNamespacesResponse1

namespaces (2.policy.NamespaceR
namespaces"�
CreateNamespaceRequest�
name (	B��H���
namespace_format�Namespace must be a valid hostname. It should include at least one dot, with each segment (label) starting and ending with an alphanumeric character. Each label must be 1 to 63 characters long, allowing hyphens but not as the first or last character. The top-level domain (the last segment after the final dot) must consist of at least two alphabetic characters. The stored namespace will be normalized to lower case.Qthis.matches('^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$')�r�Rname3
metadatad (2.common.MetadataMutableRmetadata"J
CreateNamespaceResponse/
	namespace (2.policy.NamespaceR	namespace"�
UpdateNamespaceRequest
id (	B�H�Rid3
metadatad (2.common.MetadataMutableRmetadataT
metadata_update_behaviore (2.common.MetadataUpdateEnumRmetadataUpdateBehavior"J
UpdateNamespaceResponse/
	namespace (2.policy.NamespaceR	namespace"4
DeactivateNamespaceRequest
id (	B�H�Rid"
DeactivateNamespaceResponse2�
NamespaceService�
GetNamespace&.policy.namespaces.GetNamespaceRequest'.policy.namespaces.GetNamespaceResponse"#���/attributes/namespaces/{id}�
ListNamespaces(.policy.namespaces.ListNamespacesRequest).policy.namespaces.ListNamespacesResponse"���/attributes/namespaces�
CreateNamespace).policy.namespaces.CreateNamespaceRequest*.policy.namespaces.CreateNamespaceResponse"!���:*"/attributes/namespaces�
UpdateNamespace).policy.namespaces.UpdateNamespaceRequest*.policy.namespaces.UpdateNamespaceResponse"&��� :*2/attributes/namespaces/{id}�
DeactivateNamespace-.policy.namespaces.DeactivateNamespaceRequest..policy.namespaces.DeactivateNamespaceResponse"#���*/attributes/namespaces/{id}J�
  [

  

 
	
  %
	
 &
	
 
	
 
-
  2!

Namespace Service Definitions




 

  7

  

  	

  

  6

  �	5


 




 !

 

 

  


 



3
 #& ACTIVE by default when not specified


 

 

 !"


 




 +

 


 

 &

 )*


 -




 !)
 Required


 !

 !	

 !

 !)

 �	"(

	 �	#-

	 �	 $(

,(
 Optional


,

,!

,$'


. 0


.

 /!

 /

 /

 / 


2 9


2

 47
 Required


 4

 4	

 4

 46

 �	45

7(
 Optional


7

7!

7$'

8;

8

84

87:


: <


:

 ;!

 ;

 ;

 ; 


> @


>"

 ?7

 ?

 ?	

 ?

 ?6

 �	?5
	
	A &


	A#


 C [


 C

  DF

  D

  D&

  D1E

  ED

	  �ʼ"ED

 HJ

 H

 H*

 H5K

 I?

	 �ʼ"I?

 LQ

 L

 L,

 L7N

 MP

	 �ʼ"MP

 RW

 R

 R,

 R7N

 SV

	 �ʼ"SV

 XZ

 X

 X4

 X?Z

 YG

	 �ʼ"YGbproto3��  
�:
-policy/resourcemapping/resource_mapping.protopolicy.resourcemappingbuf/validate/validate.protogoogle/api/annotations.protocommon/common.protopolicy/objects.proto"
ListResourceMappingsRequest"d
ListResourceMappingsResponseD
resource_mappings (2.policy.ResourceMappingRresourceMappings"3
GetResourceMappingRequest
id (	B�H�Rid"`
GetResourceMappingResponseB
resource_mapping (2.policy.ResourceMappingRresourceMapping"�
CreateResourceMappingRequest4
attribute_value_id (	B�H�RattributeValueId
terms (	B�H�Rterms3
metadatad (2.common.MetadataMutableRmetadata"c
CreateResourceMappingResponseB
resource_mapping (2.policy.ResourceMappingRresourceMapping"�
UpdateResourceMappingRequest
id (	B�H�Rid,
attribute_value_id (	RattributeValueId
terms (	Rterms3
metadatad (2.common.MetadataMutableRmetadataT
metadata_update_behaviore (2.common.MetadataUpdateEnumRmetadataUpdateBehavior"c
UpdateResourceMappingResponseB
resource_mapping (2.policy.ResourceMappingRresourceMapping"6
DeleteResourceMappingRequest
id (	B�H�Rid"c
DeleteResourceMappingResponseB
resource_mapping (2.policy.ResourceMappingRresourceMapping2�
ResourceMappingService�
ListResourceMappings3.policy.resourcemapping.ListResourceMappingsRequest4.policy.resourcemapping.ListResourceMappingsResponse"���/resource-mappings�
GetResourceMapping1.policy.resourcemapping.GetResourceMappingRequest2.policy.resourcemapping.GetResourceMappingResponse"���/resource-mappings/{id}�
CreateResourceMapping4.policy.resourcemapping.CreateResourceMappingRequest5.policy.resourcemapping.CreateResourceMappingResponse"���:*"/resource-mappings�
UpdateResourceMapping4.policy.resourcemapping.UpdateResourceMappingRequest5.policy.resourcemapping.UpdateResourceMappingResponse""���:*"/resource-mappings/{id}�
DeleteResourceMapping4.policy.resourcemapping.DeleteResourceMappingRequest5.policy.resourcemapping.DeleteResourceMappingResponse"���*/resource-mappings/{id}J�)
  �

  

 
	
  %
	
 &
	
 
	
 

  &2
Resource Mappings



 #


 


$

 8

 


 !

 "3

 67


 


!

 7

 

 	

 

 6

 �	5


 


"

 .

 

 )

 ,-
�
9 A�
### Request

grpcurl -plaintext -d @ localhost:8080 policy.resourcemapping.ResourceMappingService/CreateResourceMapping <<EOM
{
"mapping": {
"name": "Classification",
"attribute_value_id": "12345678-1234-1234-1234-123456789012",
"terms": ["CONFIDENTIAL", "CONTROLLED UNCLASSIFIED", "OFFICIAL-SENSITIVE", "CUI", "C"]
}
}
EOM

### Response

{
"mapping": {
"metadata": {
"id": "12345678-1234-1234-1234-123456789012",
"created_at": "2020-01-01T00:00:00Z",
"updated_at": "2020-01-01T00:00:00Z"
},
"name": "Classification",
"attribute_value_id": "12345678-1234-1234-1234-123456789012",
"terms": ["CONFIDENTIAL", "CONTROLLED UNCLASSIFIED", "OFFICIAL-SENSITIVE", "CUI", "C"]
}
}




9$

 ;G
 Required


 ;

 ;	

 ;

 ; F

 �	;!E

=C

=


=

=

=

=B

�	=A

@(
 Optional


@

@!

@$'


B D


B%

 C'

 C

 C"

 C%&


F R


F$

 H7
 Required


 H

 H	

 H

 H6

 �	H5

K 
 Optional


K

K	

K

M

M


M

M

M

P( Common Metadata


P

P!

P$'

Q;

Q

Q4

Q7:


S U


S%

 T'

 T

 T"

 T%&


W Y


W$

 X7

 X

 X	

 X

 X6

 �	X5


	Z \


	Z%

	 ['

	 [

	 ["

	 [%&
 
 ^ �"
Resource Mappings



 ^
�
  ���
Request Example:
- empty body

Response Example:
{
"resource_mappings": [
{
"terms": [
"TOPSECRET",
"TS",
],
"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
"metadata": {
"labels": [],
"created_at": {
"seconds": "1706103276",
"nanos": 510718000
},
"updated_at": {
"seconds": "1706107873",
"nanos": 399786000
},
"description": ""
},
"attribute_value": {
"members": [],
"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
"metadata": null,
"attribute_id": "",
"value": "value1"
}
}
]
}


  �

  �6

  �A]

  �;

	  �ʼ"�;
�
 ���
Request Example:
{
"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e"
}

Response Example:
{
"resource_mapping": {
"terms": [
"TOPSECRET",
"TS",
],
"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
"metadata": {
"labels": [],
"created_at": {
"seconds": "1706103276",
"nanos": 510718000
},
"updated_at": {
"seconds": "1706107873",
"nanos": 399786000
},
"description": ""
},
"attribute_value": {
"members": [],
"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
"metadata": null,
"attribute_id": "",
"value": "value1"
}
}
}


 �

 �2

 �=W

 �@

	 �ʼ"�@
�
 ���
Request Example:
{
"resource_mapping": {
"attribute_value_id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
"terms": [
"TOPSECRET",
"TS",
]
}
}

Response Example:
{
"resource_mapping": {
"terms": [
"TOPSECRET",
"TS",
],
"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
"metadata": {
"labels": [],
"created_at": {
"seconds": "1706103276",
"nanos": 510718000
},
"updated_at": {
"seconds": "1706107873",
"nanos": 399786000
},
"description": ""
},
"attribute_value": {
"members": [],
"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
"metadata": null,
"attribute_id": "",
"value": "value1"
}
}
}


 �

 �8

 �C`

 ��

	 �ʼ"��
�
 ���
Request Example:
{
"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
"resource_mapping": {
"attribute_value_id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
"terms": [
"TOPSECRET",
"TS",
"NEWTERM"
]
}
}

Response Example:
{
"resource_mapping": {
"terms": [
"TOPSECRET",
"TS",
],
"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
"metadata": {
"labels": [],
"created_at": {
"seconds": "1706103276",
"nanos": 510718000
},
"updated_at": {
"seconds": "1706107873",
"nanos": 399786000
},
"description": ""
},
"attribute_value": {
"members": [],
"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
"metadata": null,
"attribute_id": "",
"value": "value1"
}
}
}


 �

 �8

 �C`

 ��

	 �ʼ"��
�
 ���
Request Example:
{
"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e"
}

Response Example:
{
"resource_mapping": {
"terms": [
"TOPSECRET",
"TS",
],
"id": "3c649464-95b4-4fe0-a09c-ca4b1fecbb0e",
"metadata": {
"labels": [],
"created_at": {
"seconds": "1706103276",
"nanos": 510718000
},
"updated_at": {
"seconds": "1706107873",
"nanos": 399786000
},
"description": ""
},
"attribute_value": {
"members": [],
"id": "f0d1d4f6-bff9-45fd-8170-607b6b559349",
"metadata": null,
"attribute_id": "",
"value": "value1"
}
}
}


 �

 �8

 �C`

 �C

	 �ʼ"�Cbproto3��  
�V
+policy/subjectmapping/subject_mapping.protopolicy.subjectmappingbuf/validate/validate.protogoogle/api/annotations.protocommon/common.protopolicy/objects.proto"e
MatchSubjectMappingsRequestF
subject_properties (2.policy.SubjectPropertyRsubjectProperties"a
MatchSubjectMappingsResponseA
subject_mappings (2.policy.SubjectMappingRsubjectMappings"2
GetSubjectMappingRequest
id (	B�H�Rid"\
GetSubjectMappingResponse?
subject_mapping (2.policy.SubjectMappingRsubjectMapping"
ListSubjectMappingsRequest"`
ListSubjectMappingsResponseA
subject_mappings (2.policy.SubjectMappingRsubjectMappings"�
CreateSubjectMappingRequest4
attribute_value_id (	B�H�RattributeValueId2
actions (2.policy.ActionB�H�RactionsH
!existing_subject_condition_set_id (	RexistingSubjectConditionSetIdk
new_subject_condition_set (20.policy.subjectmapping.SubjectConditionSetCreateRnewSubjectConditionSet3
metadatad (2.common.MetadataMutableRmetadata"_
CreateSubjectMappingResponse?
subject_mapping (2.policy.SubjectMappingRsubjectMapping"�
UpdateSubjectMappingRequest
id (	B�H�Rid7
subject_condition_set_id (	RsubjectConditionSetId(
actions (2.policy.ActionRactions3
metadatad (2.common.MetadataMutableRmetadataT
metadata_update_behaviore (2.common.MetadataUpdateEnumRmetadataUpdateBehavior"_
UpdateSubjectMappingResponse?
subject_mapping (2.policy.SubjectMappingRsubjectMapping"5
DeleteSubjectMappingRequest
id (	B�H�Rid"_
DeleteSubjectMappingResponse?
subject_mapping (2.policy.SubjectMappingRsubjectMapping"7
GetSubjectConditionSetRequest
id (	B�H�Rid"�
GetSubjectConditionSetResponseO
subject_condition_set (2.policy.SubjectConditionSetRsubjectConditionSetV
associated_subject_mappings (2.policy.SubjectMappingRassociatedSubjectMappings"!
ListSubjectConditionSetsRequest"u
 ListSubjectConditionSetsResponseQ
subject_condition_sets (2.policy.SubjectConditionSetRsubjectConditionSets"�
SubjectConditionSetCreate?
subject_sets (2.policy.SubjectSetB�H�RsubjectSets3
metadatad (2.common.MetadataMutableRmetadata"�
 CreateSubjectConditionSetRequestd
subject_condition_set (20.policy.subjectmapping.SubjectConditionSetCreateRsubjectConditionSet"t
!CreateSubjectConditionSetResponseO
subject_condition_set (2.policy.SubjectConditionSetRsubjectConditionSet"�
 UpdateSubjectConditionSetRequest
id (	B�H�Rid5
subject_sets (2.policy.SubjectSetRsubjectSets3
metadatad (2.common.MetadataMutableRmetadataT
metadata_update_behaviore (2.common.MetadataUpdateEnumRmetadataUpdateBehavior"t
!UpdateSubjectConditionSetResponseO
subject_condition_set (2.policy.SubjectConditionSetRsubjectConditionSet":
 DeleteSubjectConditionSetRequest
id (	B�H�Rid"t
!DeleteSubjectConditionSetResponseO
subject_condition_set (2.policy.SubjectConditionSetRsubjectConditionSet2�
SubjectMappingService�
MatchSubjectMappings2.policy.subjectmapping.MatchSubjectMappingsRequest3.policy.subjectmapping.MatchSubjectMappingsResponse"3���-:subject_properties"/subject-mappings/match�
ListSubjectMappings1.policy.subjectmapping.ListSubjectMappingsRequest2.policy.subjectmapping.ListSubjectMappingsResponse"���/subject-mappings�
GetSubjectMapping/.policy.subjectmapping.GetSubjectMappingRequest0.policy.subjectmapping.GetSubjectMappingResponse"���/subject-mappings/{id}�
CreateSubjectMapping2.policy.subjectmapping.CreateSubjectMappingRequest3.policy.subjectmapping.CreateSubjectMappingResponse"���:*"/subject-mappings�
UpdateSubjectMapping2.policy.subjectmapping.UpdateSubjectMappingRequest3.policy.subjectmapping.UpdateSubjectMappingResponse"!���:*2/subject-mappings/{id}�
DeleteSubjectMapping2.policy.subjectmapping.DeleteSubjectMappingRequest3.policy.subjectmapping.DeleteSubjectMappingResponse"���*/subject-mappings/{id}�
ListSubjectConditionSets6.policy.subjectmapping.ListSubjectConditionSetsRequest7.policy.subjectmapping.ListSubjectConditionSetsResponse"���/subject-condition-sets�
GetSubjectConditionSet4.policy.subjectmapping.GetSubjectConditionSetRequest5.policy.subjectmapping.GetSubjectConditionSetResponse"$���/subject-condition-sets/{id}�
CreateSubjectConditionSet7.policy.subjectmapping.CreateSubjectConditionSetRequest8.policy.subjectmapping.CreateSubjectConditionSetResponse""���:*"/subject-condition-sets�
UpdateSubjectConditionSet7.policy.subjectmapping.UpdateSubjectConditionSetRequest8.policy.subjectmapping.UpdateSubjectConditionSetResponse"'���!:*2/subject-condition-sets/{id}�
DeleteSubjectConditionSet7.policy.subjectmapping.DeleteSubjectConditionSetRequest8.policy.subjectmapping.DeleteSubjectConditionSetResponse"$���*/subject-condition-sets/{id}J�/
  �

  

 
	
  %
	
 &
	
 
	
 
�
  � MatchSubjectMappingsRequest liberally returns a list of SubjectMappings based on the provided SubjectProperties. The SubjectMappings are returned
 if there is any single condition found among the structures that matches for one of the provided properties:
 1. The external selector value, external value, and an IN operator
 2. The external selector value, _no_ external value, and a NOT_IN operator

 Without this filtering, if a selector value was something like '.emailAddress' or '.username', every Subject is probably going to relate to that mapping
 in some way or another, potentially matching every single attribute in the DB if a policy admin has relied heavily on that field. There is no
 logic applied beyond a single condition within the query to avoid business logic interpreting the supplied conditions beyond the bare minimum
 initial filter.

 NOTE: if you have any issues, debug logs are available within the service to help identify why a mapping was or was not returned.



 #

  9

  


  !

  "4

  78


 


$

 6

 


  

 !1

 45
.
! #2"
Subject Mappings CRUD Operations



! 

 "7

 "

 "	

 "

 "6

 �	"5


$ &


$!

 %,

 %

 %'

 %*+
	
( %


("


) +


)#

 *6

 *


 * 

 *!1

 *45


- <


-#
8
 0G+ Required
 Attribute Value to be mapped to


 0

 0	

 0

 0 F

 �	0!E
@
2S3 The actions permitted by subjects in this mapping


2


2

2 

2#$

2%R

	�	2&Q
~
6/q Either of the following:
 Reuse existing SubjectConditionSet (NOTE: prioritized over new_subject_condition_set)


6

6	*

6-.
n
8:a Create new SubjectConditionSet (NOTE: ignored if existing_subject_condition_set_id is provided)


8

85

889

;(
 Optional


;

;!

;$'


= ?


=$

 >,

 >

 >'

 >*+


A N


A#

 C7
 Required


 C

 C	

 C

 C6

 �	C5
T
G&G Optional
 Replaces the existing SubjectConditionSet id with a new one


G

G	!

G$%
D
I%7 Replaces entire list of actions permitted by subjects


I


I

I 

I#$

L( Common metadata


L

L!

L$'

M;

M

M4

M7:


	O R


	O$
>
	 Q,1 Only ID of the updated Subject Mapping provided


	 Q

	 Q'

	 Q*+



T V



T#


 U7


 U


 U	


 U


 U6


 �	U5


W Z


W$
>
 Y,1 Only ID of the updated Subject Mapping provided


 Y

 Y'

 Y*+
2
` b2&*
SubjectConditionSet CRUD operations



`%

 a7

 a

 a	

 a

 a6

 �	a5


c g


c&

 d7

 d

 d2

 d56
W
fAJ contextualized Subject Mappings associated with this SubjectConditionSet


f


f 

f!<

f?@
	
i *


i'


j l


j(

 kA

 k


 k%

 k&<

 k?@


n u


n!

 p\
 Required


 p


 p

 p)

 p,-

 p.[

	 �	p/Z
(
t( Optional
 Common metadata


t

t!

t$'


v x


v(

 w6

 w

 w1

 w45


y {


y)

 z0

 z

 z+

 z./

} �


}(

 7
 Required


 

 	

 

 6

 �	5
y
�.k Optional
 If provided, replaces entire existing structure of Subject Sets, Condition Groups, & Conditions


�


�

�)

�,-

�( Common metadata


�

�!

�$'

�;

�

�4

�7:

� �

�)
A
 �73 Only ID of updated Subject Condition Set provided


 �

 �2

 �56

� �

�(

 �7

 �

 �	

 �

 �6

 �	�5

� �

�)
A
 �73 Only ID of deleted Subject Condition Set provided


 �

 �2

 �56

 � �

 �
D
  ��4 Find matching Subject Mappings for a given Subject


  �

  �6

  �A]

  ��

	  �ʼ"��

 ��

 �

 �4

 �?Z

 �:

	 �ʼ"�:

 ��

 �

 �0

 �;T

 �?

	 �ʼ"�?

 ��

 �

 �6

 �A]

 ��

	 �ʼ"��

 ��

 �

 �6

 �A]

 ��

	 �ʼ"��

 ��

 �

 �6

 �A]

 �B

	 �ʼ"�B

 ��

 �

 �>

 �Ii

 �@

	 �ʼ"�@

 ��

 �

 �:

 �Ec

 �E

	 �ʼ"�E

 ��

 �

 � @

 �Kl

 ��

	 �ʼ"��

 	��

 	�

 	� @

 	�Kl

 	��

	 	�ʼ"��

 
��

 
�

 
� @

 
�Kl

 
�H

	 
�ʼ"�Hbproto3��  
�
4wellknownconfiguration/wellknown_configuration.protowellknownconfigurationgoogle/api/annotations.protogoogle/protobuf/struct.proto"�
WellKnownConfig`
configuration (2:.wellknownconfiguration.WellKnownConfig.ConfigurationEntryRconfigurationY
ConfigurationEntry
key (	Rkey-
value (2.google.protobuf.StructRvalue:8""
 GetWellKnownConfigurationRequest"b
!GetWellKnownConfigurationResponse=
configuration (2.google.protobuf.StructRconfiguration2�
WellKnownService�
GetWellKnownConfiguration8.wellknownconfiguration.GetWellKnownConfigurationRequest9.wellknownconfiguration.GetWellKnownConfigurationResponse"*���$"/.well-known/opentdf-configurationJ�
  

  

 
	
  &
	
 &


  	


 

  8

  %

  &3

  67
	
 +


(


 


)

 +

 

 &

 )*


  


 

  

  

   @

  Kl

  K

	  �ʼ"Kbproto3��  