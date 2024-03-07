// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: protoc-gen-openapiv2/options/openapiv2.proto

// Protobuf Java Version: 3.25.3
package grpc.gateway.protoc_gen_openapiv2.options;

public interface ScopesOrBuilder extends
    // @@protoc_insertion_point(interface_extends:grpc.gateway.protoc_gen_openapiv2.options.Scopes)
    com.google.protobuf.MessageOrBuilder {

  /**
   * <pre>
   * Maps between a name of a scope to a short description of it (as the value
   * of the property).
   * </pre>
   *
   * <code>map&lt;string, string&gt; scope = 1 [json_name = "scope"];</code>
   */
  int getScopeCount();
  /**
   * <pre>
   * Maps between a name of a scope to a short description of it (as the value
   * of the property).
   * </pre>
   *
   * <code>map&lt;string, string&gt; scope = 1 [json_name = "scope"];</code>
   */
  boolean containsScope(
      java.lang.String key);
  /**
   * Use {@link #getScopeMap()} instead.
   */
  @java.lang.Deprecated
  java.util.Map<java.lang.String, java.lang.String>
  getScope();
  /**
   * <pre>
   * Maps between a name of a scope to a short description of it (as the value
   * of the property).
   * </pre>
   *
   * <code>map&lt;string, string&gt; scope = 1 [json_name = "scope"];</code>
   */
  java.util.Map<java.lang.String, java.lang.String>
  getScopeMap();
  /**
   * <pre>
   * Maps between a name of a scope to a short description of it (as the value
   * of the property).
   * </pre>
   *
   * <code>map&lt;string, string&gt; scope = 1 [json_name = "scope"];</code>
   */
  /* nullable */
java.lang.String getScopeOrDefault(
      java.lang.String key,
      /* nullable */
java.lang.String defaultValue);
  /**
   * <pre>
   * Maps between a name of a scope to a short description of it (as the value
   * of the property).
   * </pre>
   *
   * <code>map&lt;string, string&gt; scope = 1 [json_name = "scope"];</code>
   */
  java.lang.String getScopeOrThrow(
      java.lang.String key);
}
