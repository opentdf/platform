package fixtures

import (
	"context"
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
	client, token, err := keycloakLogin(&kcConnectParams)
	if err != nil {
		return err
	}

	// Create realm
	r, err := client.GetRealm(ctx, token.AccessToken, kcConnectParams.Realm)
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
	if r == nil {
		realm := gocloak.RealmRepresentation{
			Realm:   gocloak.StringP(kcConnectParams.Realm),
			Enabled: gocloak.BoolP(true),
		}

		if _, err := client.CreateRealm(ctx, token.AccessToken, realm); err != nil {
			return err
		}
		slog.Info("✅ Realm created", slog.String("realm", kcConnectParams.Realm))

		// update realm users profile via upconfig
		realmProfileUrl := fmt.Sprintf("%s/admin/realms/%s/users/profile", kcConnectParams.BasePath, kcConnectParams.Realm)
		realmUserProfileResp, err := client.GetRequestWithBearerAuth(ctx, token.AccessToken).Get(realmProfileUrl)
		if err != nil {
			return err
		}
		var upConfig map[string]interface{}
		err = json.Unmarshal([]byte(realmUserProfileResp.String()), &upConfig)
		if err != nil {
			return err
		}
		upConfig["unmanagedAttributePolicy"] = "ENABLED"
		_, err = client.GetRequestWithBearerAuth(ctx, token.AccessToken).SetBody(upConfig).Put(realmProfileUrl)
		if err != nil {
			return err
		}
		slog.Info("✅ Realm Users Profile Updated", slog.String("realm", kcConnectParams.Realm))

	} else {
		slog.Info("⏭️  Realm already exists", slog.String("realm", kcConnectParams.Realm))
	}

	opentdfClientId := "opentdf"
	opentdfSdkClientId := "opentdf-sdk"
	opentdfOrgAdminRoleName := "opentdf-org-admin"
	opentdfAdminRoleName := "opentdf-admin"
	opentdfReadonlyRoleName := "opentdf-readonly"
	testingOnlyRoleName := "opentdf-testing-role"
	opentdfERSClientId := "tdf-entity-resolution"
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
	_, err = createClient(&kcConnectParams, gocloak.Client{
		ClientID:                gocloak.StringP(opentdfClientId),
		Enabled:                 gocloak.BoolP(true),
		Name:                    gocloak.StringP(opentdfClientId),
		ServiceAccountsEnabled:  gocloak.BoolP(true),
		ClientAuthenticatorType: gocloak.StringP("client-secret"),
		Secret:                  gocloak.StringP("secret"),
		ProtocolMappers:         &protocolMappers,
	}, []gocloak.Role{*opentdfOrgAdminRole}, nil, "")
	if err != nil {
		return err
	}

	testScope := gocloak.ClientScope{
		Name:                  gocloak.StringP("testscope"),
		Description:           gocloak.StringP("a scope for testing"),
		Protocol:              gocloak.StringP("openid-connect"),
		ClientScopeAttributes: &gocloak.ClientScopeAttributes{IncludeInTokenScope: gocloak.StringP("true")},
	}

	testScopeID, err := client.CreateClientScope(ctx, token.AccessToken, kcConnectParams.Realm, testScope)
	if err != nil {
		slog.Error(fmt.Sprintf("Error creating a test scope: %s", err))
		return err
	}

	// Create TDF SDK Client
	sdkNumericID, err := createClient(&kcConnectParams, gocloak.Client{
		ClientID: gocloak.StringP(opentdfSdkClientId),
		Enabled:  gocloak.BoolP(true),
		// OptionalClientScopes:    &[]string{"testscope"},
		Name:                    gocloak.StringP(opentdfSdkClientId),
		ServiceAccountsEnabled:  gocloak.BoolP(true),
		ClientAuthenticatorType: gocloak.StringP("client-secret"),
		Secret:                  gocloak.StringP("secret"),
		ProtocolMappers:         &protocolMappers,
	}, []gocloak.Role{*opentdfReadonlyRole, *testingOnlyRole}, nil, "")
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
	realmManagementClientId, err := getIdOfClient(client, token, &kcConnectParams, &realmMangementClientName)
	if err != nil {
		return err
	}
	clientRolesToAdd, addErr := getClientRolesByList(&kcConnectParams, client, token, ctx, *realmManagementClientId, []string{"view-clients", "query-clients", "view-users", "query-users"})
	if addErr != nil {
		slog.Error(fmt.Sprintf("Error getting client roles : %s", err))
		return err
	}
	_, err = createClient(&kcConnectParams, gocloak.Client{
		ClientID:                gocloak.StringP(opentdfERSClientId),
		Enabled:                 gocloak.BoolP(true),
		Name:                    gocloak.StringP(opentdfERSClientId),
		ServiceAccountsEnabled:  gocloak.BoolP(true),
		ClientAuthenticatorType: gocloak.StringP("client-secret"),
		Secret:                  gocloak.StringP("secret"),
		ProtocolMappers:         &protocolMappers,
	}, nil, clientRolesToAdd, *realmManagementClientId)
	if err != nil {
		return err
	}

	// opentdfSdkClientNumericId, err := getIdOfClient(client, token, &kcConnectParams, &opentdfClientId)
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
	_, err = createUser(&kcConnectParams, user)
	if err != nil {
		panic("Oh no!, failed to create user :(")
	}

	// Create token exchange opentdf->opentdf sdk
	if err := createTokenExchange(&kcConnectParams, opentdfClientId, opentdfSdkClientId); err != nil {
		return err
	}

	return nil

}

func keycloakLogin(connectParams *KeycloakConnectParams) (*gocloak.GoCloak, *gocloak.JWT, error) {
	client := gocloak.NewClient(connectParams.BasePath)
	// restyClient := client.RestyClient()
	// TODO allow insecure TLS....
	// restyClient.SetTLSClientConfig(tlsConfig)
	// Get Token from master
	token, err := client.LoginAdmin(context.Background(), connectParams.Username, connectParams.Password, "master")
	if err != nil {
		slog.Error(fmt.Sprintf("Error logging into keycloak: %s", err))
	}
	return client, token, err
}

func createClient(connectParams *KeycloakConnectParams, newClient gocloak.Client, realmRoles []gocloak.Role, clientRoles []gocloak.Role, clientIdRole string) (string, error) {
	var longClientId string
	client, token, err := keycloakLogin(connectParams)
	if err != nil {
		return "", err
	}
	clientId := *newClient.ClientID
	if longClientId, err = client.CreateClient(context.Background(), token.AccessToken, connectParams.Realm, newClient); err != nil {
		switch kcErrCode(err) {
		case http.StatusConflict:
			slog.Warn(fmt.Sprintf("⏭️  client %s already exists", clientId))
			clients, err := client.GetClients(context.Background(), token.AccessToken, connectParams.Realm, gocloak.GetClientsParams{ClientID: newClient.ClientID})
			if err != nil {
				return "", err
			}
			if len(clients) == 1 {
				longClientId = *clients[0].ID
			} else {
				err = fmt.Errorf("❗️ error, %s client not found", clientId)
				return "", err
			}
		default:
			slog.Error(fmt.Sprintf("❗️  Error creating client %s : %s", clientId, err))
			return "", err
		}
	} else {
		slog.Info(fmt.Sprintf("✅ Client created: client id = %s, client identifier=%s", clientId, longClientId))
	}

	// Get service account user
	user, err := client.GetClientServiceAccount(context.Background(), token.AccessToken, connectParams.Realm, longClientId)
	if err != nil {
		slog.Error(fmt.Sprintf("Error getting service account user for client %s : %s", clientId, err))
		return "", err
	}
	slog.Info(fmt.Sprintf("ℹ️  Service account user for client %s : %s", clientId, *user.Username))

	if realmRoles != nil {
		slog.Info(fmt.Sprintf("Adding realm roles to client %s via service account %s", longClientId, *user.Username))
		if err := client.AddRealmRoleToUser(context.Background(), token.AccessToken, connectParams.Realm, *user.ID, realmRoles); err != nil {
			for _, role := range realmRoles {
				slog.Warn(fmt.Sprintf("Error adding role %s", *role.Name))
			}
			return "", err
		} else {
			for _, role := range realmRoles {
				slog.Info(fmt.Sprintf("✅ Realm Role %s added to client %s", *role.Name, longClientId))
			}
		}
	}

	if clientRoles != nil {
		slog.Info(fmt.Sprintf("Adding client roles to client %s via service account %s", longClientId, *user.Username))
		if err := client.AddClientRolesToUser(context.Background(), token.AccessToken, connectParams.Realm, clientIdRole, *user.ID, clientRoles); err != nil {
			for _, role := range clientRoles {
				slog.Warn(fmt.Sprintf("Error adding role %s", *role.Name))
			}
			return "", err
		}
		for _, role := range clientRoles {
			slog.Info(fmt.Sprintf("✅ Client Role %s added to client %s", *role.Name, longClientId))
		}
	}

	return longClientId, nil
}

func createUser(connectParams *KeycloakConnectParams, newUser gocloak.User) (*string, error) {
	client, token, err := keycloakLogin(connectParams)
	if err != nil {
		return nil, err
	}
	username := *newUser.Username
	longUserId, err := client.CreateUser(context.Background(), token.AccessToken, connectParams.Realm, newUser)
	if err != nil {
		switch kcErrCode(err) {
		case http.StatusConflict:
			slog.Warn(fmt.Sprintf("user %s already exists", username))
			users, err := client.GetUsers(context.Background(), token.AccessToken, connectParams.Realm, gocloak.GetUsersParams{Username: newUser.Username})
			if err != nil {
				return nil, err
			}
			if len(users) == 1 {
				longUserId = *users[0].ID
			} else {
				err = fmt.Errorf("error, %s user not found", username)
				return nil, err
			}
		default:
			slog.Error(fmt.Sprintf("Error creating user %s : %s", username, err))
			return nil, err
		}
	} else {
		slog.Info(fmt.Sprintf("✅ User created: username = %s, user identifier=%s", username, longUserId))
	}
	return &longUserId, nil
}

func getClientRolesByList(connectParams *KeycloakConnectParams, client *gocloak.GoCloak, token *gocloak.JWT, ctx context.Context, idClient string, roles []string) (clientRoles []gocloak.Role, getErr error) {
	var notFoundRoles []string

	if roleObjects, tmpErr := client.GetClientRoles(ctx, token.AccessToken, connectParams.Realm, idClient, gocloak.GetRoleParams{}); tmpErr != nil {
		getErr = fmt.Errorf("failed to get roles for client (error: %s)", tmpErr.Error())

		return nil, getErr
	} else {
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
	}

	if len(notFoundRoles) > 0 {
		getErr = fmt.Errorf("failed to found role(s) '%s' for client", strings.Join(notFoundRoles, ", "))
	}

	return clientRoles, getErr
}

func getIdOfClient(client *gocloak.GoCloak, token *gocloak.JWT, connectParams *KeycloakConnectParams, clientName *string) (*string, error) {
	results, err := client.GetClients(context.Background(), token.AccessToken, connectParams.Realm, gocloak.GetClientsParams{ClientID: clientName})
	if err != nil || len(results) == 0 {
		slog.Error(fmt.Sprintf("Error getting realm management client: %s", err))
		return nil, err
	}
	clientId := results[0].ID
	return clientId, nil
}

func createTokenExchange(connectParams *KeycloakConnectParams, startClientId string, targetClientId string) error {
	client, token, err := keycloakLogin(connectParams)
	if err != nil {
		return err
	}
	// Step 1- enable permissions for target client
	idForTargetClientId, err := getIdOfClient(client, token, connectParams, &targetClientId)
	if err != nil {
		return err
	}
	enabled := true
	mgmtPermissionsRepr, err := client.UpdateClientManagementPermissions(context.Background(), token.AccessToken,
		connectParams.Realm, *idForTargetClientId,
		gocloak.ManagementPermissionRepresentation{Enabled: &enabled})
	if err != nil {
		slog.Error(fmt.Sprintf("Error creating management permissions : %s", err))
		return err
	}
	tokenExchangePolicyPermissionResourceId := mgmtPermissionsRepr.Resource
	scopePermissions := *mgmtPermissionsRepr.ScopePermissions
	tokenExchangePolicyScopePermissionId := scopePermissions["token-exchange"]
	slog.Debug(fmt.Sprintf("Creating management permission: resource = %s , scope permission id = %s", *tokenExchangePolicyPermissionResourceId, tokenExchangePolicyScopePermissionId))

	slog.Debug("Step 2 - Get realm mgmt client id")
	realmMangementClientName := "realm-management"
	realmManagementClientId, err := getIdOfClient(client, token, connectParams, &realmMangementClientName)
	if err != nil {
		return err
	}
	slog.Debug(fmt.Sprintf("%s client id=%s", realmMangementClientName, *realmManagementClientId))

	slog.Debug("Step 3 - Add policy for token exchange")
	policyType := "client"
	policyName := fmt.Sprintf("%s-%s-exchange-policy", targetClientId, startClientId)
	realmMgmtExchangePolicyRepresentation := gocloak.PolicyRepresentation{
		Logic: gocloak.POSITIVE,
		Name:  &policyName,
		Type:  &policyType,
	}
	policyClients := []string{startClientId}
	realmMgmtExchangePolicyRepresentation.ClientPolicyRepresentation.Clients = &policyClients

	realmMgmtPolicy, err := client.CreatePolicy(context.Background(), token.AccessToken, connectParams.Realm,
		*realmManagementClientId, realmMgmtExchangePolicyRepresentation)
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
	tokenExchangePolicyId := realmMgmtPolicy.ID
	slog.Info(fmt.Sprintf("✅ Created Token Exchange Policy %s", *tokenExchangePolicyId))

	slog.Debug("Step 4 - Get Token Exchange Scope Identifier")
	resourceRep, err := client.GetResource(context.Background(), token.AccessToken, connectParams.Realm, *realmManagementClientId, *tokenExchangePolicyPermissionResourceId)
	if err != nil {
		slog.Error(fmt.Sprintf("Error getting resource : %s", err))
		return err
	}
	var tokenExchangeScopeId *string
	tokenExchangeScopeId = nil
	for _, scope := range *resourceRep.Scopes {
		if *scope.Name == "token-exchange" {
			tokenExchangeScopeId = scope.ID
		}
	}
	if tokenExchangeScopeId == nil {
		return fmt.Errorf("no token exchange scope found")
	}
	slog.Debug(fmt.Sprintf("Token exchange scope id =%s", *tokenExchangeScopeId))

	clientPermissionName := fmt.Sprintf("token-exchange.permission.client.%s", *idForTargetClientId)
	clientType := "Scope"
	clientPermissionResources := []string{*tokenExchangePolicyPermissionResourceId}
	clientPermissionPolicies := []string{*tokenExchangePolicyId}
	clientPermissionScopes := []string{*tokenExchangeScopeId}
	permissionScopePolicyRepresentation := gocloak.PolicyRepresentation{
		ID:               &tokenExchangePolicyScopePermissionId,
		Name:             &clientPermissionName,
		Type:             &clientType,
		Logic:            gocloak.POSITIVE,
		DecisionStrategy: gocloak.UNANIMOUS,
		Resources:        &clientPermissionResources,
		Policies:         &clientPermissionPolicies,
		Scopes:           &clientPermissionScopes,
	}
	if err := client.UpdatePermissionScope(context.Background(), token.AccessToken, connectParams.Realm,
		*realmManagementClientId, tokenExchangePolicyScopePermissionId, permissionScopePolicyRepresentation); err != nil {
		slog.Error("Error creating permission scope : %s", err)
		return err
	}
	return nil
}
