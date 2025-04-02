```mermaid
erDiagram
    actions {
        timestamp_with_time_zone created_at 
        uuid id PK "Unique identifier for the action"
        boolean is_standard "Whether the action is standard (proto-enum) or custom (user-defined)."
        jsonb metadata "Metadata for the action (see protos for structure)"
        character_varying name UK "Unique name of the action, e.g. read, write, etc."
        timestamp_with_time_zone updated_at 
    }
    
    asym_key {
        timestamp_with_time_zone created_at "Timestamp when the key was created"
        timestamp_with_time_zone expiration 
        uuid id PK "Unique identifier for the key"
        integer key_algorithm "Algorithm used to generate the key"
        character_varying key_id UK "Unique identifier for the key"
        integer key_mode "Indicates whether the key is stored LOCAL or REMOTE"
        integer key_status "Indicates the status of the key Active, Inactive, Compromised, or Expired"
        jsonb metadata "Additional metadata for the key"
        jsonb private_key_ctx "Private Key Context is a json defined structure of the private key. Could include information like PEM encoded key, or external key id information"
        uuid provider_config_id FK "Reference the provider configuration for this key"
        jsonb public_key_ctx "Public Key Context is a json defined structure of the public key"
        timestamp_with_time_zone updated_at "Timestamp when the key was last updated"
    }

    attribute_definition_key_access_grants {
        uuid attribute_definition_id PK,FK "Foreign key to the attribute definition"
        uuid key_access_server_id PK,FK "Foreign key to the KAS registration"
    }

    attribute_definition_public_key_map {
        uuid definition_id PK,FK "Foreign key to the attribute definition"
        uuid key_access_server_key_id PK,FK "Foreign key to the key access server public key for wrapping symmetric keys"
    }

    attribute_definitions {
        boolean active "Active/Inactive state"
        timestamp_with_time_zone created_at 
        uuid id PK "Primary key for the table"
        jsonb metadata "Metadata for the attribute definition (see protos for structure)"
        character_varying name UK "Name of the attribute (i.e. organization or classification), unique within the namespace"
        uuid namespace_id FK,UK "Foreign key to the parent namespace of the attribute definition"
        attribute_definition_rule rule "<UNSPECIFIED,ALL_OF,ANY_OF,HIERARCHY> Rule for the attribute (see protos for options)"
        timestamp_with_time_zone updated_at 
        ARRAY values_order "Order of value ids for the attribute (important for hierarchy rule)"
    }

    attribute_fqns {
        uuid attribute_id FK,UK "Foreign key to the attribute definition"
        text fqn UK "Fully qualified name of the attribute (i.e. https://<namespace>/attr/<attribute name>/value/<value>)"
        uuid id PK "Primary key for the table"
        uuid namespace_id FK,UK "Foreign key to the namespace of the attribute"
        uuid value_id FK,UK "Foreign key to the attribute value"
    }

    attribute_namespace_key_access_grants {
        uuid key_access_server_id PK,FK "Foreign key to the KAS registration"
        uuid namespace_id PK,FK "Foreign key to the namespace of the KAS grant"
    }

    attribute_namespace_public_key_map {
        uuid key_access_server_key_id PK,FK "Foreign key to the key access server public key for wrapping symmetric keys"
        uuid namespace_id PK,FK "Foreign key to the attribute namespace"
    }

    attribute_namespaces {
        boolean active "Active/Inactive state"
        timestamp_with_time_zone created_at 
        uuid id PK "Primary key for the table"
        jsonb metadata "Metadata for the namespace (see protos for structure)"
        character_varying name UK "Name of the namespace (i.e. example.com)"
        timestamp_with_time_zone updated_at 
    }

    attribute_value_key_access_grants {
        uuid attribute_value_id PK,FK "Foreign key to the attribute value"
        uuid key_access_server_id PK,FK "Foreign key to the KAS registration"
    }

    attribute_value_public_key_map {
        uuid key_access_server_key_id PK,FK "Foreign key to the key access server public key for wrapping symmetric keys"
        uuid value_id PK,FK "Foreign key to the attribute value"
    }

    attribute_values {
        boolean active "Active/Inactive state"
        uuid attribute_definition_id FK,UK "Foreign key to the parent attribute definition"
        timestamp_with_time_zone created_at 
        uuid id PK "Primary key for the table"
        jsonb metadata "Metadata for the attribute value (see protos for structure)"
        timestamp_with_time_zone updated_at 
        character_varying value UK "Value of the attribute (i.e. #quot;manager#quot; or #quot;admin#quot; on an attribute for titles), unique within the definition"
    }

    goose_db_version {
        integer id PK 
        boolean is_applied 
        timestamp_without_time_zone tstamp 
        bigint version_id 
    }

    key_access_server_keys {
        timestamp_with_time_zone created_at 
        timestamp_with_time_zone expiration 
        uuid id PK 
        uuid key_access_server_id FK,UK 
        integer key_algorithm 
        character_varying key_id UK 
        integer key_mode 
        integer key_status 
        jsonb metadata 
        jsonb private_key_ctx 
        uuid provider_config_id 
        jsonb public_key_ctx 
        timestamp_with_time_zone updated_at 
    }

    key_access_servers {
        timestamp_with_time_zone created_at 
        uuid id PK "Primary key for the table"
        jsonb metadata "Metadata for the KAS (see protos for structure)"
        character_varying name UK "Optional common name of the KAS"
        jsonb public_key "Public key of the KAS (see protos for structure/options)"
        character_varying source_type 
        timestamp_with_time_zone updated_at 
        character_varying uri UK "URI of the KAS"
    }

    provider_config {
        jsonb config "Configuration details for the key provider"
        timestamp_with_time_zone created_at "Timestamp when the provider configuration was created"
        uuid id PK "Unique identifier for the provider configuration"
        jsonb metadata "Additional metadata for the provider configuration"
        character_varying provider_name "Name of the key provider"
        timestamp_with_time_zone updated_at "Timestamp when the provider configuration was last updated"
    }

    registered_resource_values {
        timestamp_with_time_zone created_at "Timestamp when the record was created"
        uuid id PK "Primary key for the table"
        jsonb metadata "Metadata for the registered resource value (see protos for structure)"
        uuid registered_resource_id FK,UK "Foreign key to the registered_resources table"
        timestamp_with_time_zone updated_at "Timestamp when the record was last updated"
        character_varying value UK "Value for the registered resource value"
    }

    registered_resources {
        timestamp_with_time_zone created_at "Timestamp when the record was created"
        uuid id PK "Primary key for the table"
        jsonb metadata "Metadata for the registered resource (see protos for structure)"
        character_varying name UK "Name for the registered resource"
        timestamp_with_time_zone updated_at "Timestamp when the record was last updated"
    }

    resource_mapping_groups {
        timestamp_with_time_zone created_at 
        uuid id PK "Primary key for the table"
        jsonb metadata 
        character_varying name UK "Name for the group of resource mappings"
        uuid namespace_id FK,UK "Foreign key to the namespace of the attribute"
        timestamp_with_time_zone updated_at 
    }

    resource_mappings {
        uuid attribute_value_id FK "Foreign key to the attribute value"
        timestamp_with_time_zone created_at 
        uuid group_id FK "Foreign key to the parent group of the resource mapping (optional, a resource mapping may not be in a group)"
        uuid id PK "Primary key for the table"
        jsonb metadata "Metadata for the resource mapping (see protos for structure)"
        ARRAY terms "Terms to match against resource data (i.e. translations #quot;roi#quot;, #quot;rey#quot;, or #quot;kung#quot; in a terms list could map to the value #quot;/attr/card/value/king#quot;)"
        timestamp_with_time_zone updated_at 
    }

    subject_condition_set {
        jsonb condition "Conditions that must be met for the subject entity to be entitled to the attribute value (see protos for JSON structure)"
        timestamp_with_time_zone created_at 
        uuid id PK "Primary key for the table"
        jsonb metadata "Metadata for the condition set (see protos for structure)"
        timestamp_with_time_zone updated_at 
    }

    subject_mapping_actions {
        uuid action_id PK,FK 
        timestamp_without_time_zone created_at 
        uuid subject_mapping_id PK,FK 
    }

    subject_mappings {
        uuid attribute_value_id FK "Foreign key to the attribute value"
        timestamp_with_time_zone created_at 
        uuid id PK "Primary key for the table"
        jsonb metadata "Metadata for the subject mapping (see protos for structure)"
        uuid subject_condition_set_id FK "Foreign key to the condition set that entitles the subject entity to the attribute value"
        timestamp_with_time_zone updated_at 
    }

    sym_key {
        timestamp_with_time_zone created_at "Timestamp when the key was created"
        timestamp_with_time_zone expiration 
        uuid id PK "Unique identifier for the key"
        character_varying key_id UK "Unique identifier for the key"
        integer key_mode "Indicates whether the key is stored LOCAL or REMOTE"
        integer key_status "Indicates the status of the key Active, Inactive, Compromised, or Expired"
        bytea key_value "Key value in binary format"
        jsonb metadata "Additional metadata for the key"
        uuid provider_config_id FK "Reference the provider configuration for this key"
        timestamp_with_time_zone updated_at "Timestamp when the key was last updated"
    }

    subject_mapping_actions }o--|| actions : "action_id"
    asym_key }o--|| provider_config : "provider_config_id"
    attribute_definition_key_access_grants }o--|| attribute_definitions : "attribute_definition_id"
    attribute_definition_key_access_grants }o--|| key_access_servers : "key_access_server_id"
    attribute_definition_public_key_map }o--|| attribute_definitions : "definition_id"
    attribute_definition_public_key_map }o--|| key_access_server_keys : "key_access_server_key_id"
    attribute_definitions }o--|| attribute_namespaces : "namespace_id"
    attribute_fqns }o--|| attribute_definitions : "attribute_id"
    attribute_values }o--|| attribute_definitions : "attribute_definition_id"
    attribute_fqns }o--|| attribute_namespaces : "namespace_id"
    attribute_fqns }o--|| attribute_values : "value_id"
    attribute_namespace_key_access_grants }o--|| attribute_namespaces : "namespace_id"
    attribute_namespace_key_access_grants }o--|| key_access_servers : "key_access_server_id"
    attribute_namespace_public_key_map }o--|| attribute_namespaces : "namespace_id"
    attribute_namespace_public_key_map }o--|| key_access_server_keys : "key_access_server_key_id"
    resource_mapping_groups }o--|| attribute_namespaces : "namespace_id"
    attribute_value_key_access_grants }o--|| attribute_values : "attribute_value_id"
    attribute_value_key_access_grants }o--|| key_access_servers : "key_access_server_id"
    attribute_value_public_key_map }o--|| attribute_values : "value_id"
    attribute_value_public_key_map }o--|| key_access_server_keys : "key_access_server_key_id"
    resource_mappings }o--|| attribute_values : "attribute_value_id"
    subject_mappings }o--|| attribute_values : "attribute_value_id"
    registered_resource_values }o--|| registered_resources : "registered_resource_id"
    key_access_server_keys }o--|| key_access_servers : "key_access_server_id"
    sym_key }o--|| provider_config : "provider_config_id"
    resource_mappings }o--|| resource_mapping_groups : "group_id"
    subject_mappings }o--|| subject_condition_set : "subject_condition_set_id"
    subject_mapping_actions }o--|| subject_mappings : "subject_mapping_id"
```
<style>div.mermaid{overflow-x:scroll;}div.mermaid>svg{width:250rem;}</style>
