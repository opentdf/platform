package transformation

// Common transformation constants - usable by all providers
const (
	// Basic data type transformations
	CommonArray     = "array"
	CommonString    = "string"
	CommonLowercase = "lowercase"
	CommonUppercase = "uppercase"

	// Common parsing transformations
	CommonCSVToArray = "csv_to_array"
)

// SQL-specific transformation constants
const (
	SQLPostgresArray = "postgres_array"
)

// LDAP-specific transformation constants
const (
	LDAPDNToCNArray   = "ldap_dn_to_cn_array"
	LDAPDNToCN        = "ldap_dn_to_cn"
	LDAPAttrValues    = "ldap_attribute_values"
	LDAPADGroupName   = "ad_group_name"
)

// Claims-specific transformation constants
const (
	ClaimsExtractScope      = "jwt_extract_scope"
	ClaimsNormalizeGroups   = "jwt_normalize_groups"
)

// GetCommonTransformations returns all common transformations available to any provider
func GetCommonTransformations() []string {
	return []string{
		CommonCSVToArray,
		CommonArray,
		CommonString,
		CommonLowercase,
		CommonUppercase,
	}
}

// GetSQLTransformations returns SQL-specific transformations
func GetSQLTransformations() []string {
	return []string{
		SQLPostgresArray,
	}
}

// GetLDAPTransformations returns LDAP-specific transformations
func GetLDAPTransformations() []string {
	return []string{
		LDAPDNToCNArray,
		LDAPDNToCN,
		LDAPAttrValues,
		LDAPADGroupName,
	}
}

// GetClaimsTransformations returns Claims-specific transformations
func GetClaimsTransformations() []string {
	return []string{
		ClaimsExtractScope,
		ClaimsNormalizeGroups,
	}
}

// GetAllSQLTransformations returns common + SQL transformations
func GetAllSQLTransformations() []string {
	result := GetCommonTransformations()
	result = append(result, GetSQLTransformations()...)
	return result
}

// GetAllLDAPTransformations returns common + LDAP transformations
func GetAllLDAPTransformations() []string {
	result := GetCommonTransformations()
	result = append(result, GetLDAPTransformations()...)
	return result
}

// GetAllClaimsTransformations returns common + Claims transformations
func GetAllClaimsTransformations() []string {
	result := GetCommonTransformations()
	result = append(result, GetClaimsTransformations()...)
	return result
}

// IsCommonTransformation checks if a transformation is a common one
func IsCommonTransformation(transformation string) bool {
	common := GetCommonTransformations()
	for _, t := range common {
		if t == transformation {
			return true
		}
	}
	return false
}

// IsSupportedByProvider checks if a transformation is supported by a specific provider type
func IsSupportedByProvider(transformation, providerType string) bool {
	switch providerType {
	case "sql":
		supported := GetAllSQLTransformations()
		for _, t := range supported {
			if t == transformation {
				return true
			}
		}
	case "ldap":
		supported := GetAllLDAPTransformations()
		for _, t := range supported {
			if t == transformation {
				return true
			}
		}
	case "claims":
		supported := GetAllClaimsTransformations()
		for _, t := range supported {
			if t == transformation {
				return true
			}
		}
	}
	return false
}