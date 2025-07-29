package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/creasty/defaults"
	"github.com/go-ldap/ldap/v3"
	"github.com/go-viper/mapstructure/v2"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/opentdf/platform/protocol/go/entity"
	entityresolutionV2 "github.com/opentdf/platform/protocol/go/entityresolution/v2"
	ent "github.com/opentdf/platform/service/entity"
	"github.com/opentdf/platform/service/logger"
	"github.com/opentdf/platform/service/pkg/config"
	"github.com/opentdf/platform/service/pkg/serviceregistry"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

var (
	ErrCreationFailed     = errors.New("resource creation failed")
	ErrGetRetrievalFailed = errors.New("resource retrieval failed")
	ErrNotFound           = errors.New("resource not found")
	ErrConnectionFailed   = errors.New("LDAP connection failed")
)

const (
	DefaultLDAPPort    = 389
	DefaultLDAPSPort   = 636
	DefaultConnTimeout = 10 * time.Second
	DefaultReadTimeout = 30 * time.Second
)

// LDAPEntityResolutionServiceV2 implements the v2 Entity Resolution Service for LDAP
type LDAPEntityResolutionServiceV2 struct {
	entityresolutionV2.UnimplementedEntityResolutionServiceServer
	config LDAPConfig
	logger *logger.Logger
	trace.Tracer
}

// LDAPConfig holds the configuration for LDAP connection and attribute mapping
type LDAPConfig struct {
	// Connection settings
	Servers     []string `mapstructure:"servers" json:"servers"`
	Port        int      `mapstructure:"port" json:"port" default:"636"`
	UseTLS      bool     `mapstructure:"use_tls" json:"use_tls" default:"true"`
	InsecureTLS bool     `mapstructure:"insecure_tls" json:"insecure_tls" default:"false"`
	StartTLS    bool     `mapstructure:"start_tls" json:"start_tls" default:"false"`

	// Authentication
	BindDN       string `mapstructure:"bind_dn" json:"bind_dn"`
	BindPassword string `mapstructure:"bind_password" json:"bind_password"`

	// Search settings
	BaseDN           string `mapstructure:"base_dn" json:"base_dn"`
	UserFilter       string `mapstructure:"user_filter" json:"user_filter" default:"(uid={username})"`
	EmailFilter      string `mapstructure:"email_filter" json:"email_filter" default:"(mail={email})"`
	ClientIDFilter   string `mapstructure:"client_id_filter" json:"client_id_filter" default:"(cn={client_id})"`
	GroupSearchBase  string `mapstructure:"group_search_base" json:"group_search_base"`
	GroupFilter      string `mapstructure:"group_filter" json:"group_filter" default:"(member={dn})"`

	// Attribute mapping
	AttributeMapping AttributeMapping `mapstructure:"attribute_mapping" json:"attribute_mapping"`

	// Timeouts
	ConnectTimeout time.Duration `mapstructure:"connect_timeout" json:"connect_timeout"`
	ReadTimeout    time.Duration `mapstructure:"read_timeout" json:"read_timeout"`

	// Feature flags
	IncludeGroups bool `mapstructure:"include_groups" json:"include_groups" default:"true"`
	InferID       InferredIdentityConfig `mapstructure:"inferid,omitempty" json:"inferid,omitempty"`
}

// AttributeMapping defines how LDAP attributes map to entity properties
type AttributeMapping struct {
	Username    string   `mapstructure:"username" json:"username" default:"uid"`
	Email       string   `mapstructure:"email" json:"email" default:"mail"`
	DisplayName string   `mapstructure:"display_name" json:"display_name" default:"displayName"`
	Groups      string   `mapstructure:"groups" json:"groups" default:"memberOf"`
	ClientID    string   `mapstructure:"client_id" json:"client_id" default:"cn"`
	Additional  []string `mapstructure:"additional" json:"additional"`
}

// InferredIdentityConfig matches the pattern from Keycloak ERS
type InferredIdentityConfig struct {
	From EntityImpliedFrom `mapstructure:"from,omitempty" json:"from,omitempty"`
}

type EntityImpliedFrom struct {
	ClientID bool `mapstructure:"clientid,omitempty" json:"clientid,omitempty"`
	Email    bool `mapstructure:"email,omitempty" json:"email,omitempty"`
	Username bool `mapstructure:"username,omitempty" json:"username,omitempty"`
}

// LDAPConnector manages LDAP connections with failover support
type LDAPConnector struct {
	conn   *ldap.Conn
	config LDAPConfig
	logger *logger.Logger
}

// RegisterLDAPERS creates and registers the LDAP Entity Resolution Service for v2
func RegisterLDAPERS(config config.ServiceConfig, logger *logger.Logger) (*LDAPEntityResolutionServiceV2, serviceregistry.HandlerServer) {
	var ldapConfig LDAPConfig
	if err := mapstructure.Decode(config, &ldapConfig); err != nil {
		panic(fmt.Errorf("failed to decode LDAP configuration: %w", err))
	}

	// Set defaults using creasty/defaults
	defaults.Set(&ldapConfig)
	
	// Set defaults that can't be handled by the defaults tag
	if ldapConfig.Port == 0 {
		if ldapConfig.UseTLS {
			ldapConfig.Port = DefaultLDAPSPort
		} else {
			ldapConfig.Port = DefaultLDAPPort
		}
	}
	if ldapConfig.ConnectTimeout == 0 {
		ldapConfig.ConnectTimeout = DefaultConnTimeout
	}
	if ldapConfig.ReadTimeout == 0 {
		ldapConfig.ReadTimeout = DefaultReadTimeout
	}
	if ldapConfig.UserFilter == "" {
		ldapConfig.UserFilter = "(uid={username})"
	}
	if ldapConfig.EmailFilter == "" {
		ldapConfig.EmailFilter = "(mail={email})"
	}
	if ldapConfig.ClientIDFilter == "" {
		ldapConfig.ClientIDFilter = "(cn={client_id})"
	}
	if ldapConfig.AttributeMapping.Username == "" {
		ldapConfig.AttributeMapping.Username = "uid"
	}
	if ldapConfig.AttributeMapping.Email == "" {
		ldapConfig.AttributeMapping.Email = "mail"
	}
	if ldapConfig.AttributeMapping.DisplayName == "" {
		ldapConfig.AttributeMapping.DisplayName = "displayName"
	}
	if ldapConfig.AttributeMapping.Groups == "" {
		ldapConfig.AttributeMapping.Groups = "memberOf"
	}
	if ldapConfig.AttributeMapping.ClientID == "" {
		ldapConfig.AttributeMapping.ClientID = "cn"
	}

	logger.Debug("LDAP entity resolution v2 configuration", "config", ldapConfig)
	
	ldapSVC := &LDAPEntityResolutionServiceV2{
		config: ldapConfig,
		logger: logger,
	}
	
	return ldapSVC, nil
}

// LogValue implements slog.LogValuer for secure logging
func (c LDAPConfig) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("servers", c.Servers),
		slog.Int("port", c.Port),
		slog.Bool("use_tls", c.UseTLS),
		slog.Bool("insecure_tls", c.InsecureTLS),
		slog.Bool("start_tls", c.StartTLS),
		slog.String("bind_dn", c.BindDN),
		slog.String("bind_password", "[REDACTED]"),
		slog.String("base_dn", c.BaseDN),
		slog.String("user_filter", c.UserFilter),
		slog.String("email_filter", c.EmailFilter),
		slog.String("client_id_filter", c.ClientIDFilter),
		slog.Any("attribute_mapping", c.AttributeMapping),
		slog.Bool("include_groups", c.IncludeGroups),
		slog.Any("inferid", c.InferID),
	)
}

// ResolveEntities implements the v2 ResolveEntities method
func (s *LDAPEntityResolutionServiceV2) ResolveEntities(ctx context.Context, req *connect.Request[entityresolutionV2.ResolveEntitiesRequest]) (*connect.Response[entityresolutionV2.ResolveEntitiesResponse], error) {
	ctx, span := s.Tracer.Start(ctx, "LDAP.ResolveEntities")
	defer span.End()

	resp, err := EntityResolution(ctx, req.Msg, s.config, s.logger)
	return connect.NewResponse(&resp), err
}

// CreateEntityChainsFromTokens implements the v2 CreateEntityChainsFromTokens method
func (s *LDAPEntityResolutionServiceV2) CreateEntityChainsFromTokens(ctx context.Context, req *connect.Request[entityresolutionV2.CreateEntityChainsFromTokensRequest]) (*connect.Response[entityresolutionV2.CreateEntityChainsFromTokensResponse], error) {
	ctx, span := s.Tracer.Start(ctx, "LDAP.CreateEntityChainsFromTokens")
	defer span.End()

	resp, err := CreateEntityChainsFromTokens(ctx, req.Msg, s.config, s.logger)
	return connect.NewResponse(&resp), err
}

// EntityResolution handles the core entity resolution logic for v2 protocol
func EntityResolution(ctx context.Context, req *entityresolutionV2.ResolveEntitiesRequest, ldapConfig LDAPConfig, logger *logger.Logger) (entityresolutionV2.ResolveEntitiesResponse, error) {
	connector, err := createConnector(ctx, ldapConfig, logger)
	if err != nil {
		return entityresolutionV2.ResolveEntitiesResponse{}, 
			connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create LDAP connection: %w", err))
	}
	defer connector.close()

	var resolvedEntities []*entityresolutionV2.EntityRepresentation
	
	for idx, ident := range req.GetEntities() {
		logger.Debug("resolving entity", "type", fmt.Sprintf("%T", ident.GetEntityType()), "ephemeral_id", ident.GetEphemeralId())
		
		var entries []*ldap.Entry
		var searchErr error

		switch entityType := ident.GetEntityType().(type) {
		case *entity.Entity_ClientId:
			entries, searchErr = connector.searchByClientID(ctx, entityType.ClientId)
		case *entity.Entity_EmailAddress:
			entries, searchErr = connector.searchByEmail(ctx, entityType.EmailAddress)
		case *entity.Entity_UserName:
			entries, searchErr = connector.searchByUsername(ctx, entityType.UserName)
		default:
			logger.Warn("unsupported entity type", "type", fmt.Sprintf("%T", entityType))
			continue
		}

		if searchErr != nil {
			logger.Error("LDAP search failed", "error", searchErr.Error())
			return entityresolutionV2.ResolveEntitiesResponse{}, 
				connect.NewError(connect.CodeInternal, ErrGetRetrievalFailed)
		}

		var jsonEntities []*structpb.Struct
		
		if len(entries) == 0 {
			// Handle entity not found - check if we should infer the identity
			if shouldInferEntity(ident, ldapConfig) {
				entityStruct, err := entityToStructPb(ident)
				if err != nil {
					logger.Error("failed to create inferred entity struct", "error", err.Error())
					return entityresolutionV2.ResolveEntitiesResponse{}, 
						connect.NewError(connect.CodeInternal, ErrCreationFailed)
				}
				jsonEntities = append(jsonEntities, entityStruct)
			} else {
				entityNotFoundErr := entityresolutionV2.EntityNotFoundError{
					Code:    int32(codes.NotFound),
					Message: ErrNotFound.Error(),
					Entity:  ident.String(),
				}
				logger.Error("entity not found", "entity", ident.String())
				return entityresolutionV2.ResolveEntitiesResponse{}, 
					connect.NewError(connect.Code(entityNotFoundErr.GetCode()), ErrNotFound)
			}
		} else {
			// Convert LDAP entries to JSON structures
			for _, entry := range entries {
				jsonEntity, err := ldapEntryToJSON(entry, ldapConfig)
				if err != nil {
					logger.Error("failed to convert LDAP entry to JSON", "error", err.Error())
					return entityresolutionV2.ResolveEntitiesResponse{}, 
						connect.NewError(connect.CodeInternal, ErrCreationFailed)
				}
				
				entityStruct, err := structpb.NewStruct(jsonEntity)
				if err != nil {
					logger.Error("failed to create struct from JSON", "error", err.Error())
					return entityresolutionV2.ResolveEntitiesResponse{}, 
						connect.NewError(connect.CodeInternal, ErrCreationFailed)
				}
				
				jsonEntities = append(jsonEntities, entityStruct)
			}
		}

		// Ensure the original ID field is populated following v2 patterns
		originalID := ident.GetEphemeralId()
		if originalID == "" {
			originalID = ent.EntityIDPrefix + strconv.Itoa(idx)
		}

		resolvedEntities = append(resolvedEntities, &entityresolutionV2.EntityRepresentation{
			OriginalId:      originalID,
			AdditionalProps: jsonEntities,
		})
	}

	return entityresolutionV2.ResolveEntitiesResponse{
		EntityRepresentations: resolvedEntities,
	}, nil
}

// CreateEntityChainsFromTokens handles JWT-based entity chain creation for v2 protocol
func CreateEntityChainsFromTokens(ctx context.Context, req *entityresolutionV2.CreateEntityChainsFromTokensRequest, ldapConfig LDAPConfig, logger *logger.Logger) (entityresolutionV2.CreateEntityChainsFromTokensResponse, error) {
	var entityChains []*entity.EntityChain
	
	// For each token in the tokens form an entity chain
	for _, tok := range req.GetTokens() {
		entities, err := getEntitiesFromToken(ctx, ldapConfig, tok.GetJwt(), logger)
		if err != nil {
			return entityresolutionV2.CreateEntityChainsFromTokensResponse{}, err
		}
		entityChains = append(entityChains, &entity.EntityChain{
			EphemeralId: tok.GetEphemeralId(),
			Entities:    entities,
		})
	}

	return entityresolutionV2.CreateEntityChainsFromTokensResponse{
		EntityChains: entityChains,
	}, nil
}

// createConnector establishes an LDAP connection with failover support
func createConnector(ctx context.Context, config LDAPConfig, logger *logger.Logger) (*LDAPConnector, error) {
	var conn *ldap.Conn
	var lastErr error

	// Try connecting to each server in order
	for _, server := range config.Servers {
		address := fmt.Sprintf("%s:%d", server, config.Port)
		logger.Debug("attempting LDAP connection", "address", address)

		var dialErr error
		if config.UseTLS {
			tlsConfig := &tls.Config{
				ServerName:         server,
				InsecureSkipVerify: config.InsecureTLS,
			}
			conn, dialErr = ldap.DialTLS("tcp", address, tlsConfig)
		} else {
			conn, dialErr = ldap.Dial("tcp", address)
			if dialErr == nil && config.StartTLS {
				tlsConfig := &tls.Config{
					ServerName:         server,
					InsecureSkipVerify: config.InsecureTLS,
				}
				dialErr = conn.StartTLS(tlsConfig)
			}
		}

		if dialErr != nil {
			logger.Warn("failed to connect to LDAP server", "address", address, "error", dialErr.Error())
			lastErr = dialErr
			continue
		}

		// Set timeouts
		conn.SetTimeout(config.ReadTimeout)

		// Bind to the directory
		if config.BindDN != "" {
			if err := conn.Bind(config.BindDN, config.BindPassword); err != nil {
				logger.Warn("LDAP bind failed", "address", address, "bind_dn", config.BindDN, "error", err.Error())
				conn.Close()
				lastErr = err
				continue
			}
		}

		logger.Debug("successfully connected to LDAP server", "address", address)
		return &LDAPConnector{
			conn:   conn,
			config: config,
			logger: logger,
		}, nil
	}

	return nil, fmt.Errorf("failed to connect to any LDAP server: %w", lastErr)
}

// close closes the LDAP connection
func (c *LDAPConnector) close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// searchByUsername searches for a user by username
func (c *LDAPConnector) searchByUsername(ctx context.Context, username string) ([]*ldap.Entry, error) {
	filter := strings.ReplaceAll(c.config.UserFilter, "{username}", ldap.EscapeFilter(username))
	return c.search(ctx, filter)
}

// searchByEmail searches for a user by email address
func (c *LDAPConnector) searchByEmail(ctx context.Context, email string) ([]*ldap.Entry, error) {
	filter := strings.ReplaceAll(c.config.EmailFilter, "{email}", ldap.EscapeFilter(email))
	return c.search(ctx, filter)
}

// searchByClientID searches for a client by client ID
func (c *LDAPConnector) searchByClientID(ctx context.Context, clientID string) ([]*ldap.Entry, error) {
	filter := strings.ReplaceAll(c.config.ClientIDFilter, "{client_id}", ldap.EscapeFilter(clientID))
	return c.search(ctx, filter)
}

// search performs an LDAP search with the given filter
func (c *LDAPConnector) search(ctx context.Context, filter string) ([]*ldap.Entry, error) {
	// Build list of attributes to retrieve
	attributes := []string{
		c.config.AttributeMapping.Username,
		c.config.AttributeMapping.Email,
		c.config.AttributeMapping.DisplayName,
		c.config.AttributeMapping.ClientID,
	}
	
	if c.config.IncludeGroups && c.config.AttributeMapping.Groups != "" {
		attributes = append(attributes, c.config.AttributeMapping.Groups)
	}
	
	// Add any additional attributes
	attributes = append(attributes, c.config.AttributeMapping.Additional...)

	searchRequest := ldap.NewSearchRequest(
		c.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, // No size limit
		0, // No time limit
		false,
		filter,
		attributes,
		nil,
	)

	c.logger.Debug("performing LDAP search", "base_dn", c.config.BaseDN, "filter", filter, "attributes", attributes)

	result, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %w", err)
	}

	c.logger.Debug("LDAP search completed", "entries_found", len(result.Entries))
	return result.Entries, nil
}

// ldapEntryToJSON converts an LDAP entry to a JSON-compatible map with attribute mapping
func ldapEntryToJSON(entry *ldap.Entry, config LDAPConfig) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	
	// Add the distinguished name
	result["dn"] = entry.DN
	
	// Create a mapping from LDAP attribute names to expected field names
	attributeMapping := map[string]string{
		config.AttributeMapping.Username:    "username",
		config.AttributeMapping.Email:       "email", 
		config.AttributeMapping.DisplayName: "display_name",
		config.AttributeMapping.ClientID:    "client_id",
		config.AttributeMapping.Groups:      "groups",
	}
	
	// Add all attributes with proper field name mapping
	for _, attr := range entry.Attributes {
		// Use mapped field name if available, otherwise use original attribute name
		fieldName := attr.Name
		if mappedName, exists := attributeMapping[attr.Name]; exists {
			fieldName = mappedName
		}
		
		if len(attr.Values) == 1 {
			result[fieldName] = attr.Values[0]
		} else if len(attr.Values) > 1 {
			result[fieldName] = attr.Values
		}
	}

	return result, nil
}

// shouldInferEntity determines if an entity should be inferred when not found in LDAP
func shouldInferEntity(ident *entity.Entity, config LDAPConfig) bool {
	switch ident.GetEntityType().(type) {
	case *entity.Entity_ClientId:
		return config.InferID.From.ClientID
	case *entity.Entity_EmailAddress:
		return config.InferID.From.Email
	case *entity.Entity_UserName:
		return config.InferID.From.Username
	default:
		return false
	}
}

// entityToStructPb converts an entity to a protobuf Struct
func entityToStructPb(ident *entity.Entity) (*structpb.Struct, error) {
	entityBytes, err := protojson.Marshal(ident)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal entity: %w", err)
	}
	
	var entityStruct structpb.Struct
	if err := entityStruct.UnmarshalJSON(entityBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal JSON to struct: %w", err)
	}
	
	return &entityStruct, nil
}

// getEntitiesFromToken extracts entities from a JWT token
func getEntitiesFromToken(ctx context.Context, config LDAPConfig, jwtString string, logger *logger.Logger) ([]*entity.Entity, error) {
	token, err := jwt.ParseString(jwtString, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	claims, err := token.AsMap(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to extract claims from JWT: %w", err)
	}

	var entities []*entity.Entity
	entityID := 0

	// Extract client ID (azp claim)
	if clientID, ok := claims["azp"].(string); ok && clientID != "" {
		entities = append(entities, &entity.Entity{
			EntityType:  &entity.Entity_ClientId{ClientId: clientID},
			EphemeralId: fmt.Sprintf("jwtentity-%d-clientid-%s", entityID, clientID),
			Category:    entity.Entity_CATEGORY_ENVIRONMENT,
		})
		entityID++
	}

	// Extract username (preferred_username claim)
	if username, ok := claims["preferred_username"].(string); ok && username != "" {
		entities = append(entities, &entity.Entity{
			EntityType:  &entity.Entity_UserName{UserName: username},
			EphemeralId: fmt.Sprintf("jwtentity-%d-username-%s", entityID, username),
			Category:    entity.Entity_CATEGORY_SUBJECT,
		})
		entityID++
	}

	// Extract email if available
	if email, ok := claims["email"].(string); ok && email != "" {
		entities = append(entities, &entity.Entity{
			EntityType:  &entity.Entity_EmailAddress{EmailAddress: email},
			EphemeralId: fmt.Sprintf("jwtentity-%d-email-%s", entityID, email),
			Category:    entity.Entity_CATEGORY_SUBJECT,
		})
		entityID++
	}

	return entities, nil
}