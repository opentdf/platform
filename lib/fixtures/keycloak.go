package fixtures

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Nerzal/gocloak/v13"
)

const (
	kcErrNone    = 0
	kcErrUnknown = -1
)

type KeycloakData struct {
	Realms []RealmToCreate `yaml:"realms" json:"realms"`
}
type RealmToCreate struct {
	RealmRepresentation gocloak.RealmRepresentation `yaml:"realm_repepresentation" json:"realm_repepresentation"`
	Clients             []Client                    `yaml:"clients,omitempty" json:"clients,omitempty"`
	Users               []gocloak.User              `yaml:"users,omitempty" json:"users,omitempty"`
	CustomRealmRoles    []gocloak.Role              `yaml:"custom_realm_roles,omitempty" json:"custom_realm_roles,omitempty"`
	CustomClientRoles   map[string][]gocloak.Role   `yaml:"custom_client_roles,omitempty" json:"custom_client_roles,omitempty"`
	CustomGroups        []gocloak.Group             `yaml:"custom_groups,omitempty" json:"custom_groups,omitempty"`
	TokenExchanges      []TokenExchange             `yaml:"token_exchanges,omitempty" json:"token_exchanges,omitempty"`
}

type Client struct {
	Client        gocloak.Client      `yaml:"client" json:"client"`
	SaRealmRoles  []string            `yaml:"sa_realm_roles,omitempty" json:"sa_realm_roles,omitempty"`
	SaClientRoles map[string][]string `yaml:"sa_client_roles,omitempty" json:"sa_client_roles,omitempty"`
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

func SetupKeycloak(ctx context.Context, kcConnectParams KeycloakConnectParams) error {
	// Create realm, if it does not exist.
	client, token, err := keycloakLogin(ctx, &kcConnectParams)
	if err != nil {
		return err
	}

	// Create realm
	realm, err := client.GetRealm(ctx, token.AccessToken, kcConnectParams.Realm)
	if err != nil {
		switch kcErrCode(err) {
		case http.StatusConflict:
			slog.Info(fmt.Sprintf("⏭️ %s realm already exists, skipping create", kcConnectParams.Realm))
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
		slog.Info("✅ Realm created", slog.String("realm", kcConnectParams.Realm))

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
		slog.Info("✅ Realm Users Profile Updated", slog.String("realm", kcConnectParams.Realm))
	} else {
		slog.Info("⏭️  Realm already exists", slog.String("realm", kcConnectParams.Realm))
	}

	opentdfClientID := "opentdf"
	opentdfSdkClientID := "opentdf-sdk"
	opentdfOrgAdminRoleName := "opentdf-org-admin"
	opentdfAdminRoleName := "opentdf-admin"
	opentdfReadonlyRoleName := "opentdf-readonly"
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
	roles := []string{opentdfOrgAdminRoleName, opentdfAdminRoleName, opentdfReadonlyRoleName, testingOnlyRoleName}
	for _, role := range roles {
		_, err := client.CreateRealmRole(ctx, token.AccessToken, kcConnectParams.Realm, gocloak.Role{
			Name: gocloak.StringP(role),
		})
		if err != nil {
			switch kcErrCode(err) {
			case http.StatusConflict:
				slog.Warn(fmt.Sprintf("⏭️  role %s already exists", role))
			default:
				return err
			}
		} else {
			slog.Info(fmt.Sprintf("✅ Role created: role = %s", role))
		}
	}

	// Get the roles
	var opentdfOrgAdminRole *gocloak.Role
	// var opentdfAdminRole *gocloak.Role
	var opentdfReadonlyRole *gocloak.Role
	var testingOnlyRole *gocloak.Role
	realmRoles, err := client.GetRealmRoles(ctx, token.AccessToken, kcConnectParams.Realm, gocloak.GetRoleParams{
		Search: gocloak.StringP("opentdf"),
	})
	if err != nil {
		return err
	}

	slog.Info(fmt.Sprintf("✅ Roles found: %d", len(realmRoles))) // , slog.String("roles", fmt.Sprintf("%v", realmRoles))
	for _, role := range realmRoles {
		switch *role.Name {
		case opentdfOrgAdminRoleName:
			opentdfOrgAdminRole = role
		// case opentdfAdminRoleName:
		// 	opentdfAdminRole = role
		case opentdfReadonlyRoleName:
			opentdfReadonlyRole = role
		case testingOnlyRoleName:
			testingOnlyRole = role
		}
	}

	// Create OpenTDF Client
	_, err = createClient(ctx, client, token, &kcConnectParams, gocloak.Client{
		ClientID:                gocloak.StringP(opentdfClientID),
		Enabled:                 gocloak.BoolP(true),
		Name:                    gocloak.StringP(opentdfClientID),
		ServiceAccountsEnabled:  gocloak.BoolP(true),
		ClientAuthenticatorType: gocloak.StringP("client-secret"),
		Secret:                  gocloak.StringP("secret"),
		ProtocolMappers:         &protocolMappers,
	}, []gocloak.Role{*opentdfOrgAdminRole}, nil)
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
	sdkNumericID, err := createClient(ctx, client, token, &kcConnectParams, gocloak.Client{
		ClientID: gocloak.StringP(opentdfSdkClientID),
		Enabled:  gocloak.BoolP(true),
		// OptionalClientScopes:    &[]string{"testscope"},
		Name:                      gocloak.StringP(opentdfSdkClientID),
		ServiceAccountsEnabled:    gocloak.BoolP(true),
		ClientAuthenticatorType:   gocloak.StringP("client-secret"),
		Secret:                    gocloak.StringP("secret"),
		DirectAccessGrantsEnabled: gocloak.BoolP(true),
		ProtocolMappers:           &protocolMappers,
	}, []gocloak.Role{*opentdfReadonlyRole, *testingOnlyRole}, nil)
	if err != nil {
		return err
	}

	err = client.AddOptionalScopeToClient(ctx, token.AccessToken, kcConnectParams.Realm, sdkNumericID, testScopeID)
	if err != nil {
		slog.Error(fmt.Sprintf("Error adding scope to client: %s", err))
		return err
	}

	err = client.CreateClientScopesScopeMappingsRealmRoles(ctx, token.AccessToken, kcConnectParams.Realm, testScopeID, []gocloak.Role{*testingOnlyRole})
	if err != nil {
		slog.Error(fmt.Sprintf("Error creating a client scope mapping: %s", err))
		return err
	}

	// Create TDF Entity Resolution Client
	realmManagementClientID, err := getIDOfClient(ctx, client, token, &kcConnectParams, &realmMangementClientName)
	if err != nil {
		return err
	}
	clientRolesToAdd, addErr := getClientRolesByList(ctx, &kcConnectParams, client, token, *realmManagementClientID, []string{"view-clients", "query-clients", "view-users", "query-users"})
	if addErr != nil {
		slog.Error(fmt.Sprintf("Error getting client roles : %s", err))
		return err
	}
	_, err = createClient(ctx, client, token, &kcConnectParams, gocloak.Client{
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
	_, err = createClient(ctx, client, token, &kcConnectParams, gocloak.Client{
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
	// 	slog.Error(fmt.Sprintf("Error getting the SDK id: %s", err))
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
	_, err = createUser(ctx, client, token, &kcConnectParams, user)
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

		err := createRealm(ctx, kcConnectParams, realmToCreate.RealmRepresentation)
		if err != nil {
			return err
		}

		// login to new realm
		client, token, err := keycloakLogin(ctx, &kcConnectParams)
		if err != nil {
			return err
		}

		// create the custom realm roles
		if realmToCreate.CustomRealmRoles != nil {
			for _, customRole := range realmToCreate.CustomRealmRoles {
				err = createRealmRole(ctx, client, token, *realmToCreate.RealmRepresentation.Realm, customRole)
				if err != nil {
					return err
				}
			}
		}

		// create the custom groups
		if realmToCreate.CustomGroups != nil {
			for _, customGroup := range realmToCreate.CustomGroups {
				err = createGroup(ctx, client, token, *realmToCreate.RealmRepresentation.Realm, customGroup)
				if err != nil {
					return err
				}
			}
		}

		// create the clients
		if realmToCreate.Clients != nil {
			for _, customClient := range realmToCreate.Clients {
				realmRoles, err := getRealmRolesByList(ctx, kcConnectParams.Realm, client, token, customClient.SaRealmRoles)
				if err != nil {
					return err
				}
				clientRoleMap := make(map[string][]gocloak.Role)
				for clientID, roleString := range customClient.SaClientRoles {
					longClientID, err := getIDOfClient(ctx, client, token, &kcConnectParams, &clientID)
					if err != nil {
						return err
					}
					roleList, err := getClientRolesByList(ctx, &kcConnectParams, client, token, *longClientID, roleString)
					if err != nil {
						return err
					}
					clientRoleMap[*longClientID] = roleList
				}
				_, err = createClient(ctx, client, token, &kcConnectParams, customClient.Client, realmRoles, clientRoleMap)
				if err != nil {
					return err
				}
			}
		}

		// create the custom client roles
		if realmToCreate.CustomClientRoles != nil {
			for clientID, customRoles := range realmToCreate.CustomClientRoles {
				for _, customRole := range customRoles {
					err = createClientRole(ctx, client, token, *realmToCreate.RealmRepresentation.Realm, clientID, customRole)
					if err != nil {
						return err
					}
				}
			}
		}

		// create the users
		if realmToCreate.Users != nil {
			for _, customUser := range realmToCreate.Users {
				_, err = createUser(ctx, client, token, &kcConnectParams, customUser)
				if err != nil {
					return err
				}
			}
		}

		// create token exchanges
		if realmToCreate.TokenExchanges != nil {
			for _, tokenExchange := range realmToCreate.TokenExchanges {
				err := createTokenExchange(ctx, &kcConnectParams, tokenExchange.StartClientID, tokenExchange.TargetClientID)
				if err != nil {
					return err
				}
			}
		}
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
		slog.Error(fmt.Sprintf("Error logging into keycloak: %s", err))
	}
	return client, token, err
}

func createRealm(ctx context.Context, kcConnectParams KeycloakConnectParams, realm gocloak.RealmRepresentation) error {
	// Create realm, if it does not exist.
	client, token, err := keycloakLogin(ctx, &kcConnectParams)
	if err != nil {
		return err
	}

	// Create realm
	r, err := client.GetRealm(ctx, token.AccessToken, *realm.Realm)
	if err != nil {
		kcErr := err.(*gocloak.APIError) //nolint:errcheck,errorlint,forcetypeassert // kc error checked below
		if kcErr.Code == http.StatusConflict {
			slog.Info(fmt.Sprintf("⏭️ %s realm already exists, skipping create", *realm.Realm))
		} else if kcErr.Code != http.StatusNotFound {
			return err
		}
	}

	if r == nil { //nolint:nestif // realm doesnt already exist
		if _, err := client.CreateRealm(ctx, token.AccessToken, realm); err != nil {
			return err
		}
		slog.Info("✅ Realm created", slog.String("realm", *realm.Realm))

		// update realm users profile via upconfig
		realmProfileURL := fmt.Sprintf("%s/admin/realms/%s/users/profile", kcConnectParams.BasePath, *realm.Realm)
		realmUserProfileResp, err := client.GetRequestWithBearerAuth(ctx, token.AccessToken).Get(realmProfileURL)
		if err != nil {
			slog.Error("Error retrieving realm users profile ", slog.String("realm", *realm.Realm))
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
		slog.Info("✅ Realm Users Profile Updated", slog.String("realm", *realm.Realm))
	} else {
		slog.Info("⏭️  Realm already exists", slog.String("realm", *realm.Realm))
	}
	return nil
}

func createGroup(ctx context.Context, client *gocloak.GoCloak, token *gocloak.JWT, realmName string, group gocloak.Group) error {
	if group.Name == nil {
		return errors.New("group does not have name")
	}
	_, err := client.CreateGroup(ctx, token.AccessToken, realmName, group)
	if err != nil {
		kcErr := err.(*gocloak.APIError) //nolint:errcheck,errorlint,forcetypeassert // kc error checked below
		if kcErr.Code == http.StatusConflict {
			slog.Warn(fmt.Sprintf("⏭️  group %s already exists", *group.Name))
		} else {
			return err
		}
	} else {
		slog.Info(fmt.Sprintf("✅ Group created: group = %s", *group.Name))
	}
	return nil
}

func createRealmRole(ctx context.Context, client *gocloak.GoCloak, token *gocloak.JWT, realmName string, role gocloak.Role) error {
	if role.Name == nil {
		return errors.New("realm role does not have name")
	}
	_, err := client.CreateRealmRole(ctx, token.AccessToken, realmName, role)
	if err != nil {
		kcErr := err.(*gocloak.APIError) //nolint:errcheck,errorlint,forcetypeassert // kc error checked below
		if kcErr.Code == http.StatusConflict {
			slog.Warn(fmt.Sprintf("⏭️  role %s already exists", *role.Name))
		} else {
			return err
		}
	} else {
		slog.Info(fmt.Sprintf("✅ Role created: role = %s", *role.Name))
	}
	return nil
}

func createClientRole(ctx context.Context, client *gocloak.GoCloak, token *gocloak.JWT, realmName string, clientID string, role gocloak.Role) error {
	if role.Name == nil {
		return errors.New("client role does not have name")
	}
	results, err := client.GetClients(ctx, token.AccessToken, realmName, gocloak.GetClientsParams{ClientID: &clientID})
	if err != nil || len(results) == 0 {
		slog.Error(fmt.Sprintf("Error getting %s's client: %s", clientID, err))
		return err
	}
	idOfClient := results[0].ID

	_, err = client.CreateClientRole(ctx, token.AccessToken, realmName, *idOfClient, role)
	if err != nil {
		kcErr := err.(*gocloak.APIError) //nolint:errcheck,errorlint,forcetypeassert // kc error checked below
		if kcErr.Code == http.StatusConflict {
			slog.Warn(fmt.Sprintf("⏭️  role %s already exists for client %s", *role.Name, clientID))
		} else {
			return err
		}
	} else {
		slog.Info(fmt.Sprintf("✅ Client role created for client %s: role = %s", clientID, *role.Name))
	}
	return nil
}

func createClient(ctx context.Context, client *gocloak.GoCloak, token *gocloak.JWT, connectParams *KeycloakConnectParams, newClient gocloak.Client, realmRoles []gocloak.Role, clientRoles map[string][]gocloak.Role) (string, error) {
	var longClientID string

	clientID := *newClient.ClientID
	longClientID, err := client.CreateClient(ctx, token.AccessToken, connectParams.Realm, newClient)
	if err != nil {
		switch kcErrCode(err) {
		case http.StatusConflict:
			slog.Warn(fmt.Sprintf("⏭️  client %s already exists", clientID))
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
			slog.Error(fmt.Sprintf("❗️  Error creating client %s : %s", clientID, err))
			return "", err
		}
	} else {
		slog.Info(fmt.Sprintf("✅ Client created: client id = %s, client identifier=%s", clientID, longClientID))
	}

	// Get service account user
	user, err := client.GetClientServiceAccount(ctx, token.AccessToken, connectParams.Realm, longClientID)
	if err != nil {
		slog.Error(fmt.Sprintf("Error getting service account user for client %s : %s", clientID, err))
		return "", err
	}
	slog.Info(fmt.Sprintf("ℹ️  Service account user for client %s : %s", clientID, *user.Username))

	if realmRoles != nil {
		slog.Info(fmt.Sprintf("Adding realm roles to client %s via service account %s", longClientID, *user.Username))
		if err := client.AddRealmRoleToUser(ctx, token.AccessToken, connectParams.Realm, *user.ID, realmRoles); err != nil {
			for _, role := range realmRoles {
				slog.Warn(fmt.Sprintf("Error adding role %s", *role.Name))
			}
			return "", err
		}
		for _, role := range realmRoles {
			slog.Info(fmt.Sprintf("✅ Realm Role %s added to client %s", *role.Name, longClientID))
		}
	}
	if clientRoles != nil {
		slog.Info(fmt.Sprintf("Adding client roles to client %s via service account %s", longClientID, *user.Username))
		for clientIDRole, roles := range clientRoles {
			if err := client.AddClientRolesToUser(ctx, token.AccessToken, connectParams.Realm, clientIDRole, *user.ID, roles); err != nil {
				for _, role := range roles {
					slog.Warn(fmt.Sprintf("Error adding role %s", *role.Name))
				}
				return "", err
			}
			for _, role := range roles {
				slog.Info(fmt.Sprintf("✅ Client Role %s added to client %s", *role.Name, longClientID))
			}
		}
	}

	return longClientID, nil
}

func createUser(ctx context.Context, client *gocloak.GoCloak, token *gocloak.JWT, connectParams *KeycloakConnectParams, newUser gocloak.User) (*string, error) { //nolint:unparam // return var to be used in future
	username := *newUser.Username
	longUserID, err := client.CreateUser(ctx, token.AccessToken, connectParams.Realm, newUser)
	if err != nil {
		switch kcErrCode(err) {
		case http.StatusConflict:
			slog.Warn(fmt.Sprintf("user %s already exists", username))
			users, err := client.GetUsers(ctx, token.AccessToken, connectParams.Realm, gocloak.GetUsersParams{Username: newUser.Username})
			if err != nil {
				return nil, err
			}
			if len(users) == 1 {
				longUserID = *users[0].ID
			} else {
				err = fmt.Errorf("error, %s user not found", username)
				return nil, err
			}
		default:
			slog.Error(fmt.Sprintf("Error creating user %s : %s", username, err))
			return nil, err
		}
	} else {
		slog.Info(fmt.Sprintf("✅ User created: username = %s, user identifier=%s", username, longUserID))
	}
	// assign realm roles to user
	// retrieve the roles by name
	if newUser.RealmRoles != nil {
		roles, err := getRealmRolesByList(ctx, connectParams.Realm, client, token, *newUser.RealmRoles)
		if err != nil {
			return nil, err
		}
		err = client.AddRealmRoleToUser(ctx, token.AccessToken, connectParams.Realm, longUserID, roles)
		if err != nil {
			slog.Error(fmt.Sprintf("Error adding realm roles to user %s : %s", *newUser.RealmRoles, connectParams.Realm))
			return nil, err
		}
	}
	// assign client roles to user
	if newUser.ClientRoles != nil {
		for clientID, roles := range *newUser.ClientRoles {
			results, err := client.GetClients(ctx, token.AccessToken, connectParams.Realm, gocloak.GetClientsParams{ClientID: &clientID})
			if err != nil || len(results) == 0 {
				slog.Error(fmt.Sprintf("Error getting %s's client: %s", clientID, err))
				return nil, err
			}
			idOfClient := results[0].ID

			clientRoles, err := getClientRolesByList(ctx, connectParams, client, token, *idOfClient, roles)
			if err != nil {
				slog.Error(fmt.Sprintf("Error getting client roles: %s", err))
				return nil, err
			}

			if err := client.AddClientRolesToUser(ctx, token.AccessToken, connectParams.Realm, *idOfClient, longUserID, clientRoles); err != nil {
				for _, role := range clientRoles {
					slog.Warn(fmt.Sprintf("Error adding role %s", *role.Name))
				}
				return nil, err
			}
			for _, role := range clientRoles {
				slog.Info(fmt.Sprintf("✅ Client Role %s added to user %s", *role.Name, longUserID))
			}
		}
	}

	return &longUserID, nil
}

func getRealmRolesByList(ctx context.Context, realmName string, client *gocloak.GoCloak, token *gocloak.JWT, rolesToAdd []string) ([]gocloak.Role, error) {
	var roles []gocloak.Role
	for _, roleName := range rolesToAdd {
		role, err := client.GetRealmRole(
			ctx,
			token.AccessToken,
			realmName,
			roleName)
		if err != nil {
			slog.Error(fmt.Sprintf("Error getting realm role for realm %s : %s", roleName, realmName))
			return nil, err
		}
		roles = append(roles, *role)
	}
	return roles, nil
}

func getClientRolesByList(ctx context.Context, connectParams *KeycloakConnectParams, client *gocloak.GoCloak, token *gocloak.JWT, idClient string, roles []string) ([]gocloak.Role, error) {
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

func getIDOfClient(ctx context.Context, client *gocloak.GoCloak, token *gocloak.JWT, connectParams *KeycloakConnectParams, clientName *string) (*string, error) {
	results, err := client.GetClients(ctx, token.AccessToken, connectParams.Realm, gocloak.GetClientsParams{ClientID: clientName})
	if err != nil || len(results) == 0 {
		slog.Error(fmt.Sprintf("Error getting realm management client: %s", err))
		return nil, err
	}
	clientID := results[0].ID
	return clientID, nil
}

func createTokenExchange(ctx context.Context, connectParams *KeycloakConnectParams, startClientID string, targetClientID string) error {
	client, token, err := keycloakLogin(ctx, connectParams)
	if err != nil {
		return err
	}
	// Step 1- enable permissions for target client
	idForTargetClientID, err := getIDOfClient(ctx, client, token, connectParams, &targetClientID)
	if err != nil {
		return err
	}
	enabled := true
	mgmtPermissionsRepr, err := client.UpdateClientManagementPermissions(ctx, token.AccessToken,
		connectParams.Realm, *idForTargetClientID,
		gocloak.ManagementPermissionRepresentation{Enabled: &enabled})
	if err != nil {
		slog.Error(fmt.Sprintf("Error creating management permissions : %s", err))
		return err
	}
	tokenExchangePolicyPermissionResourceID := mgmtPermissionsRepr.Resource
	scopePermissions := *mgmtPermissionsRepr.ScopePermissions
	tokenExchangePolicyScopePermissionID := scopePermissions["token-exchange"]
	slog.Debug(fmt.Sprintf("Creating management permission: resource = %s , scope permission id = %s", *tokenExchangePolicyPermissionResourceID, tokenExchangePolicyScopePermissionID))

	slog.Debug("Step 2 - Get realm mgmt client id")
	realmMangementClientName := "realm-management"
	realmManagementClientID, err := getIDOfClient(ctx, client, token, connectParams, &realmMangementClientName)
	if err != nil {
		return err
	}
	slog.Debug(fmt.Sprintf("%s client id=%s", realmMangementClientName, *realmManagementClientID))

	slog.Debug("Step 3 - Add policy for token exchange")
	policyType := "client"
	policyName := fmt.Sprintf("%s-%s-exchange-policy", targetClientID, startClientID)
	realmMgmtExchangePolicyRepresentation := gocloak.PolicyRepresentation{
		Logic: gocloak.POSITIVE,
		Name:  &policyName,
		Type:  &policyType,
	}
	policyClients := []string{startClientID}
	realmMgmtExchangePolicyRepresentation.ClientPolicyRepresentation.Clients = &policyClients

	realmMgmtPolicy, err := client.CreatePolicy(ctx, token.AccessToken, connectParams.Realm,
		*realmManagementClientID, realmMgmtExchangePolicyRepresentation)
	if err != nil {
		switch kcErrCode(err) {
		case http.StatusConflict:
			slog.Warn(fmt.Sprintf("⏭️  policy %s already exists; skipping remainder of token exchange creation", *realmMgmtExchangePolicyRepresentation.Name))
			return nil
		default:
			slog.Error(fmt.Sprintf("Error create realm management policy: %s", err))
			return err
		}
	}
	tokenExchangePolicyID := realmMgmtPolicy.ID
	slog.Info(fmt.Sprintf("✅ Created Token Exchange Policy %s", *tokenExchangePolicyID))

	slog.Debug("Step 4 - Get Token Exchange Scope Identifier")
	resourceRep, err := client.GetResource(ctx, token.AccessToken, connectParams.Realm, *realmManagementClientID, *tokenExchangePolicyPermissionResourceID)
	if err != nil {
		slog.Error(fmt.Sprintf("Error getting resource : %s", err))
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
		return fmt.Errorf("no token exchange scope found")
	}
	slog.Debug(fmt.Sprintf("Token exchange scope id =%s", *tokenExchangeScopeID))

	clientPermissionName := fmt.Sprintf("token-exchange.permission.client.%s", *idForTargetClientID)
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
		slog.Error("Error creating permission scope", "error", err)
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
			slog.Warn(fmt.Sprintf("⏭️  authentication flow %s already exists; skipping remainder of cert exchange creation", topLevelFlowName))
			return nil
		default:
			slog.Error(fmt.Sprintf("Error create realm certificate authentication flow: %s", err))
			return err
		}
	}

	provider := "direct-grant-auth-x509-username"
	if err := client.CreateAuthenticationExecution(ctx, token.AccessToken, connectParams.Realm,
		topLevelFlowName, gocloak.CreateAuthenticationExecutionRepresentation{
			Provider: &provider,
		}); err != nil {
		slog.Error(fmt.Sprintf("Error create realm management policy: %s", err))
		return err
	}

	authExecutions, err := client.GetAuthenticationExecutions(ctx, token.AccessToken, connectParams.Realm, topLevelFlowName)
	if err != nil {
		slog.Error(fmt.Sprintf("Error gettings executions %s", err))
		return err
	}
	if len(authExecutions) != 1 {
		err = fmt.Errorf("expected a single flow execution for %s", topLevelFlowName)
		slog.Error("Error setting up authentication flow", "error", err)
		return err
	}

	requiredRequirement := "REQUIRED"
	execution := authExecutions[0]
	executionConfig := make(map[string]any)
	executionConfig["alias"] = fmt.Sprintf("%s X509 Validate Username", topLevelFlowName)
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
		slog.Error(fmt.Sprintf("Error updating x509 auth flow configs %s : %s", clientID, err))
		return err
	}

	execution.Requirement = &requiredRequirement
	if err := client.UpdateAuthenticationExecution(ctx, token.AccessToken, connectParams.Realm, topLevelFlowName, *execution); err != nil {
		slog.Error(fmt.Sprintf("Error updating x509 auth flow requjirement %s : %s", clientID, err))
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
		return fmt.Errorf("could not find client")
	}
	updatedClient := clients[0]

	flowBindings := make(map[string]string)
	flowBindings["direct_grant"] = *flowID
	updatedClient.AuthenticationFlowBindingOverrides = &flowBindings
	if err := client.UpdateClient(ctx, token.AccessToken, connectParams.Realm, *updatedClient); err != nil {
		slog.Error(fmt.Sprintf("Error updating client auth flow binding overrides %s : %s", clientID, err))
		return err
	}

	slog.Info(fmt.Sprintf("✅ Created Cert Exchange Authentication %s", *flowID))

	return nil
}

// updateExecutionConfig Posts an authentication execution config (body) to keycloak for a given execution
func updateExecutionConfig(ctx context.Context, client *gocloak.GoCloak, execution *gocloak.ModifyAuthenticationExecutionRepresentation,
	connectParams *KeycloakConnectParams, accessToken string, body interface{}) error {
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
