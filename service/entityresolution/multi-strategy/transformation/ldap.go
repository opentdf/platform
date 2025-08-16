package transformation

import (
	"fmt"
	"strings"
)

// ApplyLDAPTransformation applies LDAP-specific transformations
func ApplyLDAPTransformation(value interface{}, transformation string) (interface{}, error) {
	switch transformation {
	case LDAPDNToCNArray:
		return ApplyLDAPDNToCNArray(value)
	case LDAPDNToCN:
		return ApplyLDAPDNToCN(value)
	case LDAPAttrValues:
		return ApplyLDAPAttributeValues(value)
	case LDAPADGroupName:
		return ApplyADGroupName(value)
	default:
		return nil, fmt.Errorf("unsupported LDAP transformation: %s", transformation)
	}
}

// ApplyLDAPDNToCNArray converts array of DNs to array of CNs
func ApplyLDAPDNToCNArray(value interface{}) (interface{}, error) {
	// Handle []interface{} arrays
	if arr, ok := value.([]interface{}); ok {
		result := make([]string, 0, len(arr))
		for _, item := range arr {
			if str, strOK := item.(string); strOK {
				cn := ExtractCNFromDN(str)
				if cn != "" {
					result = append(result, cn)
				}
			}
		}
		return result, nil
	}

	// Handle []string arrays
	if arr, ok := value.([]string); ok {
		result := make([]string, 0, len(arr))
		for _, dn := range arr {
			cn := ExtractCNFromDN(dn)
			if cn != "" {
				result = append(result, cn)
			}
		}
		return result, nil
	}

	return nil, fmt.Errorf("ldap_dn_to_cn_array transformation requires array input, got %T", value)
}

// ApplyLDAPDNToCN converts single DN to CN
func ApplyLDAPDNToCN(value interface{}) (interface{}, error) {
	str, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("ldap_dn_to_cn transformation requires string input, got %T", value)
	}
	return ExtractCNFromDN(str), nil
}

// ApplyLDAPAttributeValues extracts values from LDAP attribute (handle multi-valued attributes)
func ApplyLDAPAttributeValues(value interface{}) (interface{}, error) {
	// Handle []interface{} arrays
	if arr, ok := value.([]interface{}); ok {
		result := make([]string, len(arr))
		for i, v := range arr {
			result[i] = fmt.Sprintf("%v", v)
		}
		return result, nil
	}

	// Handle []string arrays
	if arr, ok := value.([]string); ok {
		return arr, nil
	}

	// Single value - wrap in array
	return []string{fmt.Sprintf("%v", value)}, nil
}

// ApplyADGroupName extracts group name from Active Directory group DN
func ApplyADGroupName(value interface{}) (interface{}, error) {
	str, ok := value.(string)
	if !ok {
		return nil, fmt.Errorf("ad_group_name transformation requires string input, got %T", value)
	}

	// Handle both DN format and simple group names
	if strings.Contains(str, "CN=") {
		return ExtractCNFromDN(str), nil
	}
	return str, nil
}

// ExtractCNFromDN extracts the Common Name (CN) from a Distinguished Name (DN)
// Example: "CN=Users,OU=Groups,DC=example,DC=com" -> "Users"
func ExtractCNFromDN(dn string) string {
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CN=") {
			return part[3:] // Remove "CN=" prefix
		}
	}
	return ""
}

// EscapeLDAPFilter escapes special characters in LDAP filter values
// This is a utility function for LDAP providers
func EscapeLDAPFilter(value string) string {
	// LDAP filter metacharacters that need escaping per RFC 4515
	replacer := strings.NewReplacer(
		"\\", "\\5c", // backslash must be first
		"*", "\\2a", // asterisk
		"(", "\\28", // left parenthesis
		")", "\\29", // right parenthesis
		"\x00", "\\00", // null character
	)
	return replacer.Replace(value)
}
