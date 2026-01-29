package fixtures

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v13"
)

const (
	kcErrNone    = 0
	kcErrUnknown = -1

	// Token refresh constants
	defaultTokenBufferSeconds    = 120 // 2 minutes before expiration
	defaultFallbackExpiryMinutes = 5   // Fallback when token doesn't provide ExpiresIn
	adaptiveBufferDivisor        = 2   // Use 50% of token lifetime when buffer > lifetime
)

type KeycloakData struct {
	Realms []RealmToCreate `yaml:"realms" json:"realms"`
}
type RealmToCreate struct {
	RealmRepresentation gocloak.RealmRepresentation `yaml:"realm_repepresentation" json:"realm_repepresentation"`
	Clients             []Client                    `yaml:"clients,omitempty" json:"clients,omitempty"`
	Users               []User                      `yaml:"users,omitempty" json:"users,omitempty"`
	CustomRealmRoles    []gocloak.Role              `yaml:"custom_realm_roles,omitempty" json:"custom_realm_roles,omitempty"`
	CustomClientRoles   map[string][]gocloak.Role   `yaml:"custom_client_roles,omitempty" json:"custom_client_roles,omitempty"`
	CustomGroups        []gocloak.Group             `yaml:"custom_groups,omitempty" json:"custom_groups,omitempty"`
	TokenExchanges      []TokenExchange             `yaml:"token_exchanges,omitempty" json:"token_exchanges,omitempty"`
}

type User struct {
	gocloak.User
	Copies int `yaml:"copies,omitempty" json:"copies,omitempty"`
}

type Client struct {
	Client        gocloak.Client      `yaml:"client" json:"client"`
	SaRealmRoles  []string            `yaml:"sa_realm_roles,omitempty" json:"sa_realm_roles,omitempty"`
	SaClientRoles map[string][]string `yaml:"sa_client_roles,omitempty" json:"sa_client_roles,omitempty"`
	Copies        int                 `yaml:"copies,omitempty" json:"copies,omitempty"`
}

type TokenExchange struct {
	StartClientID  string `yaml:"start_client" json:"start_client"`
	TargetClientID string `yaml:"target_client" json:"target_client"`
}

// Extracts the HTTP status code from err if it is available
// as an http status code. Returns 0 for no error and -1 for
// invalid error; use const values kcErrNone and kcErrUnknown.
func kcErrCode(err error) int {
	if err == nil {
		return kcErrNone
	}
	var kcErr *gocloak.APIError
	if errors.As(err, &kcErr) {
		return kcErr.Code
	}
	return kcErrUnknown
}

type KeycloakConnectParams struct {
	BasePath         string
	Username         string
	Password         string
	Realm            string
	Audience         string
	AllowInsecureTLS bool
}

// TokenManagerConfig allows configuring token refresh behavior
type TokenManagerConfig struct {
	// TokenBuffer is duration before expiration to trigger preemptive refresh
	// Default: 120s (2 minutes)
	TokenBuffer time.Duration
}

// TokenManager manages automatic token refresh for Keycloak operations
type TokenManager struct {
	connectParams KeycloakConnectParams
	client        *gocloak.GoCloak
	token         *gocloak.JWT
	expiresAt     time.Time
	tokenBuffer   time.Duration
	mu            sync.Mutex
}

func SetupKeycloak(ctx context.Context, kcConnectParams KeycloakConnectParams) error {
	return SetupKeycloakWithConfig(ctx, kcConnectParams, nil)
}

func SetupKeycloakWithConfig(ctx context.Context, kcConnectParams KeycloakConnectParams, tmConfig *TokenManagerConfig) error {
	// Create TokenManager
	tm, err := NewTokenManager(ctx, &kcConnectParams, tmConfig)
	if err != nil {
		return fmt.Errorf("failed to create token manager: %w", err)
	}

	// Get token and client
	token, err := tm.GetToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}
	client := tm.GetClient()

	// Create realm
	realm, err := client.GetRealm(ctx, token.AccessToken, kcConnectParams.Realm)
	if err != nil {
		switch kcErrCode(err) {
		case http.StatusConflict:
			slog.Info("realm already exists, skipping create", slog.String("realm", kcConnectParams.Realm))
		case http.StatusNotFound:
			// yay!
		default:
			return err
		}
	}

	//nolint:nestif // only create realm if it does not exist
	if realm == nil {
		realm := gocloak.RealmRepresentation{
			Realm:   gocloak.StringP(kcConnectParams.Realm),
			Enabled: gocloak.BoolP(true),
		}

		if _, err := client.CreateRealm(ctx, token.AccessToken, realm); err != nil {
			return err
		}
		//nolint:sloglint // allow existing emojis
		slog.Info("✅ realm created", slog.String("realm", kcConnectParams.Realm))

		// update realm users profile via upconfig
		realmProfileURL := fmt.Sprintf("%s/admin/realms/%s/users/profile", kcConnectParams.BasePath, kcConnectParams.Realm)
		realmUserProfileResp, err := client.GetRequestWithBearerAuth(ctx, token.AccessToken).Get(realmProfileURL)
		if err != nil {
			return err
		}
		var upConfig map[string]interface{}
		err = json.Unmarshal([]byte(realmUserProfileResp.String()), &upConfig)
		if err != nil {
			return err
		}
		upConfig["unmanagedAttributePolicy"] = "ENABLED"
		_, err = client.GetRequestWithBearerAuth(ctx, token.AccessToken).SetBody(upConfig).Put(realmProfileURL)
		if err != nil {
			return err
		}
		//nolint:sloglint // allow existing emojis
		slog.Info("✅ realm users profile updated", slog.String("realm", kcConnectParams.Realm))
	} else {
		//nolint:sloglint // allow existing emojis
		slog.Info("⏭️ realm already exists", slog.String("realm", kcConnectParams.Realm))
	}

	opentdfClientID := "opentdf"
	opentdfSdkClientID := "opentdf-sdk"
	opentdfAdminRoleName := "opentdf-admin"
	opentdfStandardRoleName := "opentdf-standard"
	testingOnlyRoleName := "opentdf-testing-role"
	opentdfERSClientID := "tdf-entity-resolution"
	opentdfAuthorizationClientID := "tdf-authorization-svc"
	realmMangementClientName := "realm-management"

	protocolMappers := []gocloak.ProtocolMapperRepresentation{
		{
			Name:           gocloak.StringP("audience-mapper"),
			Protocol:       gocloak.StringP("openid-connect"),
			ProtocolMapper: gocloak.StringP("oidc-audience-mapper"),
			Config: &map[string]string{
				"included.client.audience": kcConnectParams.Audience,
				"included.custom.audience": "custom_audience",
				"access.token.claim":       "true",
				"id.token.claim":           "true",
			},
		},
		{
			Name:           gocloak.StringP("dpop-mapper"),
			Protocol:       gocloak.StringP("openid-connect"),
			ProtocolMapper: gocloak.StringP("virtru-oidc-protocolmapper"),
			Config: &map[string]string{
				"claim.name":         "tdf_claims",
				"client.dpop":        "true",
				"tdf_claims.enabled": "true",
				"access.token.claim": "true",
				"client.publickey":   "X-VirtruPubKey",
			},
		},
	}

	// Create Roles
	roles := []string{opentdfAdminRoleName, opentdfStandardRoleName, testingOnlyRoleName}
	for _, role := range roles {
		_, err := client.CreateRealmRole(ctx, token.AccessToken, kcConnectParams.Realm, gocloak.Role{
			Name: gocloak.StringP(role),
		})
		if err != nil {
			switch kcErrCode(err) {
			case http.StatusConflict:
				//nolint:sloglint // allow existing emojis
				slog.Warn("⏭️ role already exists", slog.String("role", role))
			default:
				return err
			}
		} else {
			//nolint:sloglint // allow existing emojis
			slog.Info("✅ role created", slog.String("role", role))
		}
	}

	// Get the roles
	var opentdfAdminRole *gocloak.Role
	var opentdfStandardRole *gocloak.Role
	var testingOnlyRole *gocloak.Role
	realmRoles, err := client.GetRealmRoles(ctx, token.AccessToken, kcConnectParams.Realm, gocloak.GetRoleParams{
		Search: gocloak.StringP("opentdf"),
	})
	if err != nil {
		return err
	}

	//nolint:sloglint // allow existing emojis
	slog.Info("✅ roles found", slog.Int("count", len(realmRoles)))
	for _, role := range realmRoles {
		switch *role.Name {
		case opentdfAdminRoleName:
			opentdfAdminRole = role
		case opentdfStandardRoleName:
			opentdfStandardRole = role
		case testingOnlyRoleName:
			testingOnlyRole = role
		}
	}

	// Create OpenTDF Client
	_, err = createClient(ctx, tm, &kcConnectParams, gocloak.Client{
		ClientID:                gocloak.StringP(opentdfClientID),
		Enabled:                 gocloak.BoolP(true),
		Name:                    gocloak.StringP(opentdfClientID),
		ServiceAccountsEnabled:  gocloak.BoolP(true),
		ClientAuthenticatorType: gocloak.StringP("client-secret"),
		Secret:                  gocloak.StringP("secret"),
		ProtocolMappers:         &protocolMappers,
	}, []gocloak.Role{*opentdfAdminRole}, nil)
	if err != nil {
		return err
	}

	var (
		testScopeID = "5787804c-cdd1-44db-ac74-c46fbda91ccc"
		testScope   *gocloak.ClientScope
	)

	// Try an get the test scope
	switch _, err = client.GetClientScope(ctx, token.AccessToken, kcConnectParams.Realm, testScopeID); kcErrCode(err) {
	case http.StatusNotFound:
		testScope = &gocloak.ClientScope{
			ID:                    gocloak.StringP(testScopeID),
			Name:                  gocloak.StringP("testscope"),
			Description:           gocloak.StringP("a scope for testing"),
			Protocol:              gocloak.StringP("openid-connect"),
			ClientScopeAttributes: &gocloak.ClientScopeAttributes{IncludeInTokenScope: gocloak.StringP("true")},
		}

		testScopeID, err = client.CreateClientScope(ctx, token.AccessToken, kcConnectParams.Realm, *testScope)
		if err != nil {
			return err
		}
	case kcErrNone:
		break
	case kcErrUnknown:
		return err
	default:
		// This should never happen
	}

	// Create TDF SDK Client
	sdkNumericID, err := createClient(ctx, tm, &kcConnectParams, gocloak.Client{
		ClientID: gocloak.StringP(opentdfSdkClientID),
		Enabled:  gocloak.BoolP(true),
		// OptionalClientScopes:    &[]string{"testscope"},
		Name:                      gocloak.StringP(opentdfSdkClientID),
		ServiceAccountsEnabled:    gocloak.BoolP(true),
		ClientAuthenticatorType:   gocloak.StringP("client-secret"),
		Secret:                    gocloak.StringP("secret"),
		DirectAccessGrantsEnabled: gocloak.BoolP(true),
		ProtocolMappers:           &protocolMappers,
	}, []gocloak.Role{*opentdfStandardRole, *testingOnlyRole}, nil)
	if err != nil {
		return err
	}

	err = client.AddOptionalScopeToClient(ctx, token.AccessToken, kcConnectParams.Realm, sdkNumericID, testScopeID)
	if err != nil {
		slog.Error("error adding scope to client", slog.Any("error", err))
		return err
	}

	err = client.CreateClientScopesScopeMappingsRealmRoles(ctx, token.AccessToken, kcConnectParams.Realm, testScopeID, []gocloak.Role{*testingOnlyRole})
	if err != nil {
		slog.Error("error creating a client scope mapping", slog.Any("error", err))
		return err
	}

	// Create TDF Entity Resolution Client
	realmManagementClientID, err := getIDOfClient(ctx, tm, &kcConnectParams, &realmMangementClientName)
	if err != nil {
		return err
	}
	clientRolesToAdd, addErr := getClientRolesByList(ctx, &kcConnectParams, tm, *realmManagementClientID, []string{"view-clients", "query-clients", "view-users", "query-users"})
	if addErr != nil {
		slog.Error("error getting client roles", slog.Any("error", err))
		return err
	}
	_, err = createClient(ctx, tm, &kcConnectParams, gocloak.Client{
		ClientID:                gocloak.StringP(opentdfERSClientID),
		Enabled:                 gocloak.BoolP(true),
		Name:                    gocloak.StringP(opentdfERSClientID),
		ServiceAccountsEnabled:  gocloak.BoolP(true),
		ClientAuthenticatorType: gocloak.StringP("client-secret"),
		Secret:                  gocloak.StringP("secret"),
		ProtocolMappers:         &protocolMappers,
	}, nil, map[string][]gocloak.Role{*realmManagementClientID: clientRolesToAdd})
	if err != nil {
		return err
	}

	// Create TDF Authorization Svc Client
	_, err = createClient(ctx, tm, &kcConnectParams, gocloak.Client{
		ClientID:                gocloak.StringP(opentdfAuthorizationClientID),
		Enabled:                 gocloak.BoolP(true),
		Name:                    gocloak.StringP(opentdfAuthorizationClientID),
		ServiceAccountsEnabled:  gocloak.BoolP(true),
		ClientAuthenticatorType: gocloak.StringP("client-secret"),
		Secret:                  gocloak.StringP("secret"),
		ProtocolMappers:         &protocolMappers,
	}, nil, nil)
	if err != nil {
		return err
	}

	// opentdfSdkClientNumericId, err := getIDOfClient(ctx, client, token, &kcConnectParams, &opentdfClientId)
	// if err != nil {
	// 	slog.Error("error getting the sdk id", slog.Any("error", err))
	// 	return err
	// }

	user := gocloak.User{
		FirstName:  gocloak.StringP("sample"),
		LastName:   gocloak.StringP("user"),
		Email:      gocloak.StringP("sampleuser@sample.com"),
		Enabled:    gocloak.BoolP(true),
		Username:   gocloak.StringP("sampleuser"),
		Attributes: &map[string][]string{"superhero_name": {"thor"}, "superhero_group": {"avengers"}},
	}
	_, err = createUser(ctx, tm, &kcConnectParams, user)
	if err != nil {
		panic("Oh no!, failed to create user :(")
	}

	// Create token exchange opentdf->opentdf sdk
	if err := createTokenExchange(ctx, &kcConnectParams, opentdfClientID, opentdfSdkClientID); err != nil {
		return err
	}
	if err := createCertExchange(ctx, &kcConnectParams, "x509-auth-flow", opentdfSdkClientID); err != nil {
		return err
	}

	return nil
}

func SetupCustomKeycloak(ctx context.Context, kcParams KeycloakConnectParams, keycloakData KeycloakData) error {
	return SetupCustomKeycloakWithConfig(ctx, kcParams, keycloakData, nil)
}

func SetupCustomKeycloakWithConfig(ctx context.Context, kcParams KeycloakConnectParams, keycloakData KeycloakData, tmConfig *TokenManagerConfig) error {
	// for each realm to create
	for _, realmToCreate := range keycloakData.Realms {
		// login and try to create the realm
		if realmToCreate.RealmRepresentation.Realm == nil {
			return errors.New("realm does not have name")
		}

		kcConnectParams := KeycloakConnectParams{
			BasePath:         kcParams.BasePath,
			Username:         kcParams.Username,
			Password:         kcParams.Password,
			Realm:            *realmToCreate.RealmRepresentation.Realm,
			AllowInsecureTLS: true,
		}

		// Create TokenManager for this realm
		tm, err := NewTokenManager(ctx, &kcConnectParams, tmConfig)
		if err != nil {
			return fmt.Errorf("failed to create token manager: %w", err)
		}

		err = createRealmWithTokenManager(ctx, kcConnectParams, realmToCreate.RealmRepresentation, tm)
		if err != nil {
			return err
		}

		// create the custom realm roles
		if realmToCreate.CustomRealmRoles != nil {
			for _, customRole := range realmToCreate.CustomRealmRoles {
				err = createRealmRole(ctx, tm, *realmToCreate.RealmRepresentation.Realm, customRole)
				if err != nil {
					return err
				}
			}
		}

		// create the custom groups
		if realmToCreate.CustomGroups != nil {
			for _, customGroup := range realmToCreate.CustomGroups {
				err = createGroup(ctx, tm, *realmToCreate.RealmRepresentation.Realm, customGroup)
				if err != nil {
					return err
				}
			}
		}

		// create the clients
		if realmToCreate.Clients != nil { //nolint:nestif // need to create clients in order
			for _, customClient := range realmToCreate.Clients {
				realmRoles, err := getRealmRolesByList(ctx, kcConnectParams.Realm, tm, customClient.SaRealmRoles)
				if err != nil {
					return err
				}
				clientRoleMap := make(map[string][]gocloak.Role)
				for clientID, roleString := range customClient.SaClientRoles {
					longClientID, err := getIDOfClient(ctx, tm, &kcConnectParams, &clientID)
					if err != nil {
						return err
					}
					roleList, err := getClientRolesByList(ctx, &kcConnectParams, tm, *longClientID, roleString)
					if err != nil {
						return err
					}
					clientRoleMap[*longClientID] = roleList
				}
				_, err = createClient(ctx, tm, &kcConnectParams, customClient.Client, realmRoles, clientRoleMap)
				if err != nil {
					return err
				}
				if customClient.Copies < 1 {
					continue
				}
				baseClientID := *customClient.Client.ClientID
				baseClientName := *customClient.Client.Name
				numDigits := int(math.Log10(float64(customClient.Copies-1))) + 1
				padFormat := fmt.Sprintf("%%s-%%%dd", numDigits)
				for i := 0; i < customClient.Copies; i++ {
					customClient.Client.ClientID = gocloak.StringP(fmt.Sprintf(padFormat, baseClientID, i))
					customClient.Client.Name = gocloak.StringP(fmt.Sprintf(padFormat, baseClientName, i))
					_, err = createClient(ctx, tm, &kcConnectParams, customClient.Client, realmRoles, clientRoleMap)
					if err != nil {
						return err
					}
				}
			}
		}

		// create the custom client roles
		if realmToCreate.CustomClientRoles != nil {
			for clientID, customRoles := range realmToCreate.CustomClientRoles {
				for _, customRole := range customRoles {
					err = createClientRole(ctx, tm, *realmToCreate.RealmRepresentation.Realm, clientID, customRole)
					if err != nil {
						return err
					}
				}
			}
		}

		// create the users
		if realmToCreate.Users != nil {
			for _, customUser := range realmToCreate.Users {
				_, err = createUser(ctx, tm, &kcConnectParams, customUser.User)
				if err != nil {
					return err
				}
				if customUser.Copies < 1 {
					continue
				}
				baseUserName := *customUser.Username
				baseEmail := *customUser.Email
				numDigits := int(math.Log10(float64(customUser.Copies-1))) + 1
				padFormat := fmt.Sprintf("%%s-%%%dd", numDigits)
				for i := 0; i < customUser.Copies; i++ {
					customUser.Username = gocloak.StringP(fmt.Sprintf(padFormat, baseUserName, i))
					customUser.Email = gocloak.StringP(fmt.Sprintf("%d-%s", i, baseEmail))
					_, err = createUser(ctx, tm, &kcConnectParams, customUser.User)
					if err != nil {
						return err
					}
				}
			}
		}

		// create token exchanges
		if realmToCreate.TokenExchanges != nil {
			for _, tokenExchange := range realmToCreate.TokenExchanges {
				err := createTokenExchangeWithTokenManager(ctx, &kcConnectParams, tm, tokenExchange.StartClientID, tokenExchange.TargetClientID)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// NewTokenManager creates a new TokenManager with initial login
func NewTokenManager(ctx context.Context, connectParams *KeycloakConnectParams, config *TokenManagerConfig) (*TokenManager, error) {
	if connectParams == nil {
		return nil, errors.New("connectParams cannot be nil")
	}

	// Set default token buffer if not provided
	tokenBuffer := defaultTokenBufferSeconds * time.Second
	if config != nil && config.TokenBuffer > 0 {
		tokenBuffer = config.TokenBuffer
	}

	tm := &TokenManager{
		connectParams: *connectParams,
		tokenBuffer:   tokenBuffer,
	}

	// Perform initial login
	if err := tm.refreshToken(ctx); err != nil {
		return nil, fmt.Errorf("initial login failed: %w", err)
	}

	return tm, nil
}

// GetToken returns a valid token, refreshing if necessary
func (tm *TokenManager) GetToken(ctx context.Context) (*gocloak.JWT, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Check if token needs refresh
	if tm.needsRefresh() {
		slog.InfoContext(ctx, "keycloak token expired or expiring soon - refreshing")
		if err := tm.refreshToken(ctx); err != nil {
			return nil, fmt.Errorf("failed to refresh token: %w", err)
		}
		slog.InfoContext(ctx, "successfully refreshed keycloak token",
			slog.Int("expires_in_seconds", tm.token.ExpiresIn))
	}

	return tm.token, nil
}

// GetClient returns the GoCloak client
func (tm *TokenManager) GetClient() *gocloak.GoCloak {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	return tm.client
}

// needsRefresh checks if the token needs to be refreshed
// Must be called with mutex locked
func (tm *TokenManager) needsRefresh() bool {
	if tm.token == nil || tm.client == nil {
		return true
	}
	return time.Now().After(tm.expiresAt.Add(-tm.tokenBuffer))
}

// refreshToken performs the actual token refresh
// Must be called with mutex locked
func (tm *TokenManager) refreshToken(ctx context.Context) error {
	// Create client if needed
	if tm.client == nil {
		client := gocloak.NewClient(tm.connectParams.BasePath)
		restyClient := client.RestyClient()
		restyClient.SetTLSClientConfig(&tls.Config{
			InsecureSkipVerify: tm.connectParams.AllowInsecureTLS, //nolint:gosec // need insecure TLS option for testing and development
		})
		tm.client = client
	}

	// Get new token from master realm
	// Note: Admin tokens are ALWAYS obtained from the "master" realm in Keycloak,
	// regardless of which realm is being managed. The token has admin permissions
	// across all realms. This is standard Keycloak authentication behavior.
	token, err := tm.client.LoginAdmin(ctx, tm.connectParams.Username, tm.connectParams.Password, "master")
	if err != nil {
		return fmt.Errorf("keycloak login failed: %w", err)
	}

	tm.token = token
	// Use the token's expiration time if available, otherwise calculate from ExpiresIn
	if token.ExpiresIn > 0 {
		tm.expiresAt = time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)

		// Adaptive buffer: if token lifetime is shorter than buffer, use 50% of lifetime instead
		tokenLifetime := time.Duration(token.ExpiresIn) * time.Second
		if tm.tokenBuffer >= tokenLifetime {
			tm.tokenBuffer = tokenLifetime / adaptiveBufferDivisor
			slog.InfoContext(ctx, "adjusted token buffer for short token lifetime",
				slog.Duration("token_lifetime", tokenLifetime),
				slog.Duration("adjusted_buffer", tm.tokenBuffer))
		}
	} else {
		// Fallback to a reasonable default if ExpiresIn is not set
		tm.expiresAt = time.Now().Add(defaultFallbackExpiryMinutes * time.Minute)
	}

	return nil
}

func keycloakLogin(ctx context.Context, connectParams *KeycloakConnectParams) (*gocloak.GoCloak, *gocloak.JWT, error) {
	client := gocloak.NewClient(connectParams.BasePath)
	restyClient := client.RestyClient()
	// TODO allow insecure TLS....
	restyClient.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: connectParams.AllowInsecureTLS}) //nolint:gosec // need insecure TLS option for testing and development

	// Get Token from master
	token, err := client.LoginAdmin(ctx, connectParams.Username, connectParams.Password, "master")
	if err != nil {
		slog.Error("error logging into keycloak", slog.Any("error", err))
	}
	return client, token, err
}

func createRealm(ctx context.Context, kcConnectParams KeycloakConnectParams, realm gocloak.RealmRepresentation) error {
	// Create TokenManager and delegate to TokenManager version
	tm, err := NewTokenManager(ctx, &kcConnectParams, nil)
	if err != nil {
		return fmt.Errorf("failed to create token manager: %w", err)
	}
	return createRealmWithTokenManager(ctx, kcConnectParams, realm, tm)
}

func createRealmWithTokenManager(ctx context.Context, kcConnectParams KeycloakConnectParams, realm gocloak.RealmRepresentation, tm *TokenManager) error {
	// Get fresh token
	token, err := tm.GetToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}
	client := tm.GetClient()

	// Create realm
	r, err := client.GetRealm(ctx, token.AccessToken, *realm.Realm)
	if err != nil {
		var kcErr *gocloak.APIError
		if errors.As(err, &kcErr) {
			switch kcErr.Code {
			case http.StatusNotFound:
				// Realm doesn't exist, we'll create it below
			case http.StatusConflict:
				slog.Info("realm already exists, skipping create", slog.String("realm", *realm.Realm))
			default:
				return err
			}
		} else {
			// Non-Keycloak error
			return err
		}
	}

	if r == nil {
		if _, err := client.CreateRealm(ctx, token.AccessToken, realm); err != nil {
			return err
		}
		//nolint:sloglint // allow existing emojis
		slog.Info("✅ realm created", slog.String("realm", *realm.Realm))
	} else {
		//nolint:sloglint // allow existing emojis
		slog.Info("⏭️ realm already exists", slog.String("realm", *realm.Realm))
	}

	// update realm users profile via upconfig
	realmProfileURL := fmt.Sprintf("%s/admin/realms/%s/users/profile", kcConnectParams.BasePath, *realm.Realm)
	realmUserProfileResp, err := client.GetRequestWithBearerAuth(ctx, token.AccessToken).Get(realmProfileURL)
	if err != nil {
		slog.Error("error retrieving realm users profile", slog.String("realm", *realm.Realm))
		return err
	}
	var upConfig map[string]interface{}
	err = json.Unmarshal([]byte(realmUserProfileResp.String()), &upConfig)
	if err != nil {
		return err
	}
	upConfig["unmanagedAttributePolicy"] = "ENABLED"
	_, err = client.GetRequestWithBearerAuth(ctx, token.AccessToken).SetBody(upConfig).Put(realmProfileURL)
	if err != nil {
		return err
	}
	//nolint:sloglint // allow existing emojis
	slog.Info("✅ realm users profile updated", slog.String("realm", *realm.Realm))

	return nil
}

func createGroup(ctx context.Context, tm *TokenManager, realmName string, group gocloak.Group) error {
	if group.Name == nil {
		return errors.New("group does not have name")
	}

	// Get fresh token
	token, err := tm.GetToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}
	client := tm.GetClient()

	_, err = client.CreateGroup(ctx, token.AccessToken, realmName, group)
	if err != nil {
		kcErr := err.(*gocloak.APIError) //nolint:errcheck,errorlint,forcetypeassert // kc error checked below
		if kcErr.Code == http.StatusConflict {
			//nolint:sloglint // allow existing emojis
			slog.Warn("⏭️ group already exists", slog.String("group", *group.Name))
		} else {
			return err
		}
	} else {
		//nolint:sloglint // allow existing emojis
		slog.Info("✅ group created", slog.String("group", *group.Name))
	}
	return nil
}

func createRealmRole(ctx context.Context, tm *TokenManager, realmName string, role gocloak.Role) error {
	if role.Name == nil {
		return errors.New("realm role does not have name")
	}

	// Get fresh token
	token, err := tm.GetToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}
	client := tm.GetClient()

	_, err = client.CreateRealmRole(ctx, token.AccessToken, realmName, role)
	if err != nil {
		kcErr := err.(*gocloak.APIError) //nolint:errcheck,errorlint,forcetypeassert // kc error checked below
		if kcErr.Code == http.StatusConflict {
			//nolint:sloglint // allow existing emojis
			slog.Warn("⏭️ role already exists", slog.String("role", *role.Name))
		} else {
			return err
		}
	} else {
		//nolint:sloglint // allow existing emojis
		slog.Info("✅ role created", slog.String("role", *role.Name))
	}
	return nil
}

func createClientRole(ctx context.Context, tm *TokenManager, realmName string, clientID string, role gocloak.Role) error {
	if role.Name == nil {
		return errors.New("client role does not have name")
	}

	// Get fresh token
	token, err := tm.GetToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}
	client := tm.GetClient()

	results, err := client.GetClients(ctx, token.AccessToken, realmName, gocloak.GetClientsParams{ClientID: &clientID})
	if err != nil || len(results) == 0 {
		slog.Error("error getting client",
			slog.String("client_id", clientID),
			slog.Any("error", err))
		return err
	}
	idOfClient := results[0].ID

	_, err = client.CreateClientRole(ctx, token.AccessToken, realmName, *idOfClient, role)
	if err != nil {
		kcErr := err.(*gocloak.APIError) //nolint:errcheck,errorlint,forcetypeassert // kc error checked below
		if kcErr.Code == http.StatusConflict {
			//nolint:sloglint // allow existing emojis
			slog.Warn("⏭️ role already exists for client",
				slog.String("role", *role.Name),
				slog.String("client_id", clientID))
		} else {
			return err
		}
	} else {
		//nolint:sloglint // allow existing emojis
		slog.Info("✅ client role created",
			slog.String("client_id", clientID),
			slog.String("role", *role.Name))
	}
	return nil
}

func createClient(ctx context.Context, tm *TokenManager, connectParams *KeycloakConnectParams, newClient gocloak.Client, realmRoles []gocloak.Role, clientRoles map[string][]gocloak.Role) (string, error) {
	// Get fresh token
	token, err := tm.GetToken(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get token: %w", err)
	}
	client := tm.GetClient()

	var longClientID string

	clientID := *newClient.ClientID
	longClientID, err = client.CreateClient(ctx, token.AccessToken, connectParams.Realm, newClient)
	if err != nil {
		switch kcErrCode(err) {
		case http.StatusConflict:
			//nolint:sloglint // allow existing emojis
			slog.Warn("⏭️ client already exists", slog.String("client_id", clientID))
			clients, err := client.GetClients(ctx, token.AccessToken, connectParams.Realm, gocloak.GetClientsParams{ClientID: newClient.ClientID})
			if err != nil {
				return "", err
			}
			if len(clients) == 1 {
				longClientID = *clients[0].ID
			} else {
				err = fmt.Errorf("❗️ error, %s client not found", clientID)
				return "", err
			}
		default:
			slog.Error("error creating client",
				slog.String("client_id", clientID),
				slog.Any("error", err))
			return "", err
		}
	} else {
		//nolint:sloglint // allow existing emojis
		slog.Info("✅ client created",
			slog.String("client_id", clientID),
			slog.String("client_identifier", longClientID))
	}

	// if the client is not public
	if newClient.ServiceAccountsEnabled != nil && *newClient.ServiceAccountsEnabled { //nolint:nestif // have to handle the different cases
		// Get service account user
		user, err := client.GetClientServiceAccount(ctx, token.AccessToken, connectParams.Realm, longClientID)
		if err != nil {
			slog.Error("error getting service account user for client",
				slog.String("client_id", clientID),
				slog.Any("error", err))
			return "", err
		}
		slog.Info("ℹ️ service account user for client",
			slog.String("client_id", clientID),
			slog.String("username", *user.Username))

		if realmRoles != nil {
			//nolint:sloglint // allow existing emojis
			slog.Info("⏭️ adding realm roles to client via service account",
				slog.String("client_id", longClientID),
				slog.String("username", *user.Username))
			if err := client.AddRealmRoleToUser(ctx, token.AccessToken, connectParams.Realm, *user.ID, realmRoles); err != nil {
				for _, role := range realmRoles {
					slog.Warn("error adding role", slog.String("role", *role.Name))
				}
				return "", err
			}
			for _, role := range realmRoles {
				//nolint:sloglint // allow existing emojis
				slog.Info("✅ realm role added to client",
					slog.String("role", *role.Name),
					slog.String("client_id", longClientID))
			}
		}
		if clientRoles != nil {
			//nolint:sloglint // allow existing emojis
			slog.Info("⏭️ adding client roles to client via service account",
				slog.String("client_id", longClientID),
				slog.String("username", *user.Username))
			for clientIDRole, roles := range clientRoles {
				if err := client.AddClientRolesToUser(ctx, token.AccessToken, connectParams.Realm, clientIDRole, *user.ID, roles); err != nil {
					for _, role := range roles {
						slog.Warn("error adding role", slog.String("role", *role.Name))
					}
					return "", err
				}
				for _, role := range roles {
					//nolint:sloglint // allow existing emojis
					slog.Info("✅ client role added to client",
						slog.String("role", *role.Name),
						slog.String("client_id", longClientID))
				}
			}
		}
	}
	return longClientID, nil
}

func createUser(ctx context.Context, tm *TokenManager, connectParams *KeycloakConnectParams, newUser gocloak.User) (*string, error) { //nolint:unparam // return var to be used in future
	// Get fresh token
	token, err := tm.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	client := tm.GetClient()

	username := *newUser.Username
	longUserID, err := client.CreateUser(ctx, token.AccessToken, connectParams.Realm, newUser)
	if err != nil {
		switch kcErrCode(err) {
		case http.StatusConflict:
			slog.Warn("user already exists", slog.String("username", username))
			users, err := client.GetUsers(ctx, token.AccessToken, connectParams.Realm, gocloak.GetUsersParams{
				Username: newUser.Username,
				Exact:    gocloak.BoolP(true),
			})
			if err != nil {
				return nil, err
			}
			if len(users) == 1 {
				longUserID = *users[0].ID
			} else if len(users) > 1 {
				err = fmt.Errorf("error, multiple users found with username %s", username)
				return nil, err
			} else {
				err = fmt.Errorf("error, %s user not found", username)
				return nil, err
			}
		default:
			slog.Error("error creating user",
				slog.String("username", username),
				slog.Any("error", err))
			return nil, err
		}
	} else {
		//nolint:sloglint // allow existing emojis
		slog.Info("✅ user created",
			slog.String("username", username),
			slog.String("user_identifier", longUserID))
	}
	// assign realm roles to user
	// retrieve the roles by name
	if newUser.RealmRoles != nil {
		roles, err := getRealmRolesByList(ctx, connectParams.Realm, tm, *newUser.RealmRoles)
		if err != nil {
			return nil, err
		}
		err = client.AddRealmRoleToUser(ctx, token.AccessToken, connectParams.Realm, longUserID, roles)
		if err != nil {
			slog.Error("error adding realm roles to user",
				slog.Any("roles", *newUser.RealmRoles),
				slog.String("realm", connectParams.Realm))
			return nil, err
		}
	}
	// assign client roles to user
	if newUser.ClientRoles != nil {
		for clientID, roles := range *newUser.ClientRoles {
			results, err := client.GetClients(ctx, token.AccessToken, connectParams.Realm, gocloak.GetClientsParams{ClientID: &clientID})
			if err != nil || len(results) == 0 {
				slog.Error("error getting client",
					slog.String("client_id", clientID),
					slog.Any("error", err))
				return nil, err
			}
			idOfClient := results[0].ID

			clientRoles, err := getClientRolesByList(ctx, connectParams, tm, *idOfClient, roles)
			if err != nil {
				slog.Error("error getting client roles", slog.Any("error", err))
				return nil, err
			}

			if err := client.AddClientRolesToUser(ctx, token.AccessToken, connectParams.Realm, *idOfClient, longUserID, clientRoles); err != nil {
				for _, role := range clientRoles {
					slog.Warn("error adding role", slog.String("role", *role.Name))
				}
				return nil, err
			}
			for _, role := range clientRoles {
				//nolint:sloglint // allow existing emojis
				slog.Info("✅ client role added to user",
					slog.String("role", *role.Name),
					slog.String("user_id", longUserID))
			}
		}
	}

	return &longUserID, nil
}

func getRealmRolesByList(ctx context.Context, realmName string, tm *TokenManager, rolesToAdd []string) ([]gocloak.Role, error) {
	// Get fresh token
	token, err := tm.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	client := tm.GetClient()

	var roles []gocloak.Role
	for _, roleName := range rolesToAdd {
		role, err := client.GetRealmRole(
			ctx,
			token.AccessToken,
			realmName,
			roleName)
		if err != nil {
			slog.Error("error getting realm role for realm",
				slog.String("role", roleName),
				slog.String("realm", realmName))
			return nil, err
		}
		roles = append(roles, *role)
	}
	return roles, nil
}

func getClientRolesByList(ctx context.Context, connectParams *KeycloakConnectParams, tm *TokenManager, idClient string, roles []string) ([]gocloak.Role, error) {
	// Get fresh token
	token, err := tm.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	client := tm.GetClient()

	var notFoundRoles []string
	var clientRoles []gocloak.Role

	roleObjects, err := client.GetClientRoles(ctx, token.AccessToken, connectParams.Realm, idClient, gocloak.GetRoleParams{})
	if err != nil {
		return nil, fmt.Errorf("failed to get roles for client (error: %s)", err.Error())
	}

searchRole:
	for _, r := range roles {
		for _, rb := range roleObjects {
			if r == *rb.Name {
				clientRoles = append(clientRoles, *rb)
				continue searchRole
			}
		}
		notFoundRoles = append(notFoundRoles, r)
	}

	if len(notFoundRoles) > 0 {
		return nil, fmt.Errorf("failed to found role(s) '%s' for client", strings.Join(notFoundRoles, ", "))
	}

	return clientRoles, nil
}

func getIDOfClient(ctx context.Context, tm *TokenManager, connectParams *KeycloakConnectParams, clientName *string) (*string, error) {
	// Get fresh token
	token, err := tm.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	client := tm.GetClient()

	results, err := client.GetClients(ctx, token.AccessToken, connectParams.Realm, gocloak.GetClientsParams{ClientID: clientName})
	if err != nil || len(results) == 0 {
		slog.Error("error getting realm management client", slog.Any("error", err))
		return nil, err
	}
	clientID := results[0].ID
	return clientID, nil
}

func createTokenExchange(ctx context.Context, connectParams *KeycloakConnectParams, startClientID string, targetClientID string) error {
	// Create TokenManager and delegate to TokenManager version
	tm, err := NewTokenManager(ctx, connectParams, nil)
	if err != nil {
		return fmt.Errorf("failed to create token manager: %w", err)
	}
	return createTokenExchangeWithTokenManager(ctx, connectParams, tm, startClientID, targetClientID)
}

func createTokenExchangeWithTokenManager(ctx context.Context, connectParams *KeycloakConnectParams, tm *TokenManager, startClientID string, targetClientID string) error {
	// Get fresh token
	token, err := tm.GetToken(ctx)
	if err != nil {
		return fmt.Errorf("failed to get token: %w", err)
	}
	client := tm.GetClient()

	// Step 1- enable permissions for target client
	idForTargetClientID, err := getIDOfClient(ctx, tm, connectParams, &targetClientID)
	if err != nil {
		return err
	}
	enabled := true
	mgmtPermissionsRepr, err := client.UpdateClientManagementPermissions(ctx, token.AccessToken,
		connectParams.Realm, *idForTargetClientID,
		gocloak.ManagementPermissionRepresentation{Enabled: &enabled})
	if err != nil {
		slog.Error("error creating management permissions", slog.Any("error", err))
		return err
	}
	tokenExchangePolicyPermissionResourceID := mgmtPermissionsRepr.Resource
	scopePermissions := *mgmtPermissionsRepr.ScopePermissions
	tokenExchangePolicyScopePermissionID := scopePermissions["token-exchange"]
	slog.Debug("creating management permission",
		slog.String("resource", *tokenExchangePolicyPermissionResourceID),
		slog.String("scope_permission_id", tokenExchangePolicyScopePermissionID))

	slog.Debug("step 2 - get realm mgmt client id")
	realmMangementClientName := "realm-management"
	realmManagementClientID, err := getIDOfClient(ctx, tm, connectParams, &realmMangementClientName)
	if err != nil {
		return err
	}
	slog.Debug("client information",
		slog.String("client_name", realmMangementClientName),
		slog.String("client_id", *realmManagementClientID))

	slog.Debug("step 3 - add policy for token exchange")
	policyType := "client"
	policyName := fmt.Sprintf("%s-%s-exchange-policy", targetClientID, startClientID)
	realmMgmtExchangePolicyRepresentation := gocloak.PolicyRepresentation{
		Logic: gocloak.POSITIVE,
		Name:  &policyName,
		Type:  &policyType,
	}
	policyClients := []string{startClientID}
	realmMgmtExchangePolicyRepresentation.Clients = &policyClients

	realmMgmtPolicy, err := client.CreatePolicy(ctx, token.AccessToken, connectParams.Realm,
		*realmManagementClientID, realmMgmtExchangePolicyRepresentation)
	if err != nil {
		switch kcErrCode(err) {
		case http.StatusConflict:
			//nolint:sloglint // allow existing emojis
			slog.Warn("⏭️ policy already exists; skipping remainder of token exchange creation", slog.String("policy", *realmMgmtExchangePolicyRepresentation.Name))
			return nil
		default:
			slog.Error("error creating realm management policy", slog.Any("error", err))
			return err
		}
	}
	tokenExchangePolicyID := realmMgmtPolicy.ID
	//nolint:sloglint // allow existing emojis
	slog.Info("✅ created token exchange policy", slog.String("policy_id", *tokenExchangePolicyID))

	slog.Debug("step 4 - get token exchange scope identifier")
	resourceRep, err := client.GetResource(ctx, token.AccessToken, connectParams.Realm, *realmManagementClientID, *tokenExchangePolicyPermissionResourceID)
	if err != nil {
		slog.Error("error getting resource", slog.Any("error", err))
		return err
	}
	var tokenExchangeScopeID *string
	tokenExchangeScopeID = nil
	for _, scope := range *resourceRep.Scopes {
		if *scope.Name == "token-exchange" {
			tokenExchangeScopeID = scope.ID
		}
	}
	if tokenExchangeScopeID == nil {
		return errors.New("no token exchange scope found")
	}
	slog.Debug("token exchange scope information",
		slog.String("scope_id", *tokenExchangeScopeID))

	clientPermissionName := "token-exchange.permission.client." + *idForTargetClientID
	clientType := "Scope"
	clientPermissionResources := []string{*tokenExchangePolicyPermissionResourceID}
	clientPermissionPolicies := []string{*tokenExchangePolicyID}
	clientPermissionScopes := []string{*tokenExchangeScopeID}
	permissionScopePolicyRepresentation := gocloak.PolicyRepresentation{
		ID:               &tokenExchangePolicyScopePermissionID,
		Name:             &clientPermissionName,
		Type:             &clientType,
		Logic:            gocloak.POSITIVE,
		DecisionStrategy: gocloak.UNANIMOUS,
		Resources:        &clientPermissionResources,
		Policies:         &clientPermissionPolicies,
		Scopes:           &clientPermissionScopes,
	}
	if err := client.UpdatePermissionScope(ctx, token.AccessToken, connectParams.Realm,
		*realmManagementClientID, tokenExchangePolicyScopePermissionID, permissionScopePolicyRepresentation); err != nil {
		slog.Error("error creating permission scope", slog.Any("error", err))
		return err
	}
	return nil
}

func createCertExchange(ctx context.Context, connectParams *KeycloakConnectParams, topLevelFlowName, clientID string) error {
	client, token, err := keycloakLogin(ctx, connectParams)
	if err != nil {
		return err
	}

	providerID := "basic-flow"
	builtIn := false
	topLevel := true
	desc := "X509 Direct Grant Flow"

	if err := client.CreateAuthenticationFlow(ctx, token.AccessToken, connectParams.Realm,
		gocloak.AuthenticationFlowRepresentation{
			Alias:       &topLevelFlowName,
			ProviderID:  &providerID,
			BuiltIn:     &builtIn,
			Description: &desc,
			TopLevel:    &topLevel,
		}); err != nil {
		switch kcErrCode(err) {
		case http.StatusConflict:
			//nolint:sloglint // allow existing emojis
			slog.Warn("⏭️ authentication flow already exists; skipping remainder of cert exchange creation", slog.String("flow_name", topLevelFlowName))
			return nil
		default:
			slog.Error("error creating realm certificate authentication flow", slog.Any("error", err))
			return err
		}
	}

	provider := "direct-grant-auth-x509-username"
	if err := client.CreateAuthenticationExecution(ctx, token.AccessToken, connectParams.Realm,
		topLevelFlowName, gocloak.CreateAuthenticationExecutionRepresentation{
			Provider: &provider,
		}); err != nil {
		slog.Error("error creating realm management policy", slog.Any("error", err))
		return err
	}

	authExecutions, err := client.GetAuthenticationExecutions(ctx, token.AccessToken, connectParams.Realm, topLevelFlowName)
	if err != nil {
		slog.Error("error gettings executions", slog.Any("error", err))
		return err
	}
	if len(authExecutions) != 1 {
		err = fmt.Errorf("expected a single flow execution for %s", topLevelFlowName)
		slog.Error("error setting up authentication flow", slog.Any("error", err))
		return err
	}

	requiredRequirement := "REQUIRED"
	execution := authExecutions[0]
	executionConfig := make(map[string]any)
	executionConfig["alias"] = topLevelFlowName + " X509 Validate Username"
	config := make(map[string]any)
	config["x509-cert-auth.mapping-source-selection"] = "Subject's Common Name"
	config["x509-cert-auth.canonical-dn-enabled"] = false
	config["x509-cert-auth.serialnumber-hex-enabled"] = false
	config["x509-cert-auth.regular-expression"] = "CN=(.*?)(?:,|$)"
	config["x509-cert-auth.mapper-selection"] = "Username or Email"
	config["x509-cert-auth.timestamp-validation-enabled"] = true
	config["x509-cert-auth.crl-checking-enabled"] = false
	config["x509-cert-auth.crldp-checking-enabled"] = false
	config["x509-cert-auth.ocsp-checking-enabled"] = false
	config["x509-cert-auth.ocsp-fail-open"] = false
	config["x509-cert-auth.ocsp-responder-uri"] = ""
	config["x509-cert-auth.ocsp-responder-certificate"] = ""
	config["x509-cert-auth.keyusage"] = ""
	config["x509-cert-auth.extendedkeyusage"] = ""
	config["x509-cert-auth.confirmation-page-disallowed"] = false
	config["x509-cert-auth.revalidate-certificate-enabled"] = false
	config["x509-cert-auth.certificate-policy"] = ""
	config["x509-cert-auth.certificate-policy-mode"] = "All"
	executionConfig["config"] = config
	if err := updateExecutionConfig(ctx, client, execution, connectParams, token.AccessToken, executionConfig); err != nil {
		slog.Error("error updating x509 auth flow configs",
			slog.String("client_id", clientID),
			slog.Any("error", err),
		)
		return err
	}

	execution.Requirement = &requiredRequirement
	if err := client.UpdateAuthenticationExecution(ctx, token.AccessToken, connectParams.Realm, topLevelFlowName, *execution); err != nil {
		slog.Error("error updating x509 auth flow requjirement",
			slog.String("client_id", clientID),
			slog.Any("error", err),
		)
		return err
	}

	authFlows, err := client.GetAuthenticationFlows(ctx, token.AccessToken, connectParams.Realm)
	if err != nil {
		return err
	}
	var flowID *string
	for _, flow := range authFlows {
		if flow.Alias != nil && *flow.Alias == topLevelFlowName {
			flowID = flow.ID
			break
		}
	}
	if flowID == nil {
		return fmt.Errorf("could not find flow %s despite making it", topLevelFlowName)
	}

	clients, err := client.GetClients(ctx, token.AccessToken, connectParams.Realm, gocloak.GetClientsParams{ClientID: gocloak.StringP(clientID)})
	if err != nil {
		return err
	}
	if len(clients) != 1 {
		return errors.New("could not find client")
	}
	updatedClient := clients[0]

	flowBindings := make(map[string]string)
	flowBindings["direct_grant"] = *flowID
	updatedClient.AuthenticationFlowBindingOverrides = &flowBindings
	if err := client.UpdateClient(ctx, token.AccessToken, connectParams.Realm, *updatedClient); err != nil {
		slog.Error("error updating client auth flow binding overrides",
			slog.String("client_id", clientID),
			slog.Any("error", err),
		)
		return err
	}

	//nolint:sloglint // allow existing emojis
	slog.Info("✅ created Cert Exchange Authentication",
		slog.String("flow_id", *flowID),
	)

	return nil
}

// updateExecutionConfig Posts an authentication execution config (body) to keycloak for a given execution
func updateExecutionConfig(ctx context.Context, client *gocloak.GoCloak, execution *gocloak.ModifyAuthenticationExecutionRepresentation,
	connectParams *KeycloakConnectParams, accessToken string, body interface{},
) error {
	updateURL := fmt.Sprintf("%s/admin/realms/%s/authentication/executions/%s/config", connectParams.BasePath,
		connectParams.Realm, *execution.ID)
	resp, respErr := client.GetRequestWithBearerAuth(ctx, accessToken).SetBody(body).
		Post(updateURL)
	if respErr != nil {
		return respErr
	}
	statusCode := resp.RawResponse.StatusCode
	if statusCode != http.StatusCreated {
		return fmt.Errorf("received %d response to configuration request", statusCode)
	}

	return nil
}
