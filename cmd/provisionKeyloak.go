package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/opentdf/platform/internal/config"
	"github.com/spf13/cobra"
)

const (
	provKcEndpoint = "endpoint"
	provKcUsername = "admin"
	provKcPassword = "changeme"
	provKcRealm    = "opentdf"
)

type keycloakConnectParams struct {
	BasePath         string
	Username         string
	Password         string
	Realm            string
	AllowInsecureTLS bool
}

var (
	provisionKeycloakCmd = &cobra.Command{
		Use:   "keycloak",
		Short: "Run local provision of keycloak data",
		Long: `
 ** Local Development and Testing Only **
 This command will create the following Keyclaok resource:
 - Realm
 - Roles
 - Client
 - Users

 This command is intended for local development and testing purposes only.
 `,
		RunE: func(cmd *cobra.Command, args []string) error {
			kcEndpoint, _ := cmd.Flags().GetString(provKcEndpoint)
			realmName, _ := cmd.Flags().GetString(provKcRealm)
			kcUsername, _ := cmd.Flags().GetString(provKcUsername)
			kcPassword, _ := cmd.Flags().GetString(provKcPassword)

			kcConnectParams := keycloakConnectParams{
				BasePath:         kcEndpoint,
				Username:         kcUsername,
				Password:         kcPassword,
				Realm:            realmName,
				AllowInsecureTLS: true,
			}

			config, err := config.LoadConfig("")
			ctx := context.Background()

			// Create realm, if it does not exist.
			client, token, err := keycloakLogin(&kcConnectParams)
			if err != nil {
				return err
			}

			//Create realm
			r, err := client.GetRealm(ctx, token.AccessToken, realmName)
			if err != nil {
				kcErr := err.(*gocloak.APIError)
				if kcErr.Code == 409 {
					slog.Info(fmt.Sprintf("⏭️ %s realm already exists, skipping create", realmName))
				} else if kcErr.Code != 404 {
					return err
				}
			}

			if r == nil {
				realm := gocloak.RealmRepresentation{
					Realm:   gocloak.StringP(realmName),
					Enabled: gocloak.BoolP(true),
				}

				if _, err := client.CreateRealm(ctx, token.AccessToken, realm); err != nil {
					return err
				}
				slog.Info("✅ Realm created", slog.String("realm", realmName))

				//update realm users profile via upconfig
				realmProfileUrl := fmt.Sprintf("%s/admin/realms/%s/users/profile", kcConnectParams.BasePath, realmName)
				realmUserProfileResp, err := client.GetRequestWithBearerAuth(ctx, token.AccessToken).Get(realmProfileUrl)
				var upConfig map[string]interface{}
				err = json.Unmarshal([]byte(realmUserProfileResp.String()), &upConfig)
				if err != nil {
					return err
				}
				upConfig["unmanagedAttributePolicy"] = "ENABLED"
				realmUserProfileResp, err = client.GetRequestWithBearerAuth(ctx, token.AccessToken).SetBody(upConfig).Put(realmProfileUrl)
				if err != nil {
					return err
				}
				slog.Info("✅ Realm Users Profile Updated", slog.String("realm", realmName))

			} else {
				slog.Info("⏭️  Realm already exists", slog.String("realm", realmName))
			}

			opentdfClientId := "opentdf"
			opentdfSdkClientId := "opentdf-sdk"
			opentdfOrgAdminRoleName := "opentdf-org-admin"
			opentdfAdminRoleName := "opentdf-admin"
			opentdfReadonlyRoleName := "opentdf-readonly"
			opentdfERSClientId := "tdf-entity-resolution"
			realmMangementClientName := "realm-management"

			protocolMappers := []gocloak.ProtocolMapperRepresentation{
				{
					Name:           gocloak.StringP("audience-mapper"),
					Protocol:       gocloak.StringP("openid-connect"),
					ProtocolMapper: gocloak.StringP("oidc-audience-mapper"),
					Config: &map[string]string{
						"included.client.audience": config.Server.Auth.Audience,
						"included.custom.audience": "custom_audience",
						"access.token.claim":       "true",
						"id.token.claim":           "true",
					},
				},
			}

			// Create Roles
			roles := []string{opentdfOrgAdminRoleName, opentdfAdminRoleName, opentdfReadonlyRoleName}
			for _, role := range roles {
				_, err := client.CreateRealmRole(ctx, token.AccessToken, realmName, gocloak.Role{
					Name: gocloak.StringP(role),
				})
				if err != nil {
					kcErr := err.(*gocloak.APIError)
					if kcErr.Code == 409 {
						slog.Warn(fmt.Sprintf("⏭️  role %s already exists", role))
					} else {
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
			realmRoles, err := client.GetRealmRoles(ctx, token.AccessToken, realmName, gocloak.GetRoleParams{
				Search: gocloak.StringP("opentdf"),
			})
			if err != nil {
				return err
			}

			slog.Info(fmt.Sprintf("✅ Roles found: %d", len(realmRoles))) //, slog.String("roles", fmt.Sprintf("%v", realmRoles))
			for _, role := range realmRoles {
				switch *role.Name {
				case opentdfOrgAdminRoleName:
					opentdfOrgAdminRole = role
				// case opentdfAdminRoleName:
				// 	opentdfAdminRole = role
				case opentdfReadonlyRoleName:
					opentdfReadonlyRole = role
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

			// Create TDF SDK Client
			_, err = createClient(&kcConnectParams, gocloak.Client{
				ClientID:                gocloak.StringP(opentdfSdkClientId),
				Enabled:                 gocloak.BoolP(true),
				Name:                    gocloak.StringP(opentdfSdkClientId),
				ServiceAccountsEnabled:  gocloak.BoolP(true),
				ClientAuthenticatorType: gocloak.StringP("client-secret"),
				Secret:                  gocloak.StringP("secret"),
				ProtocolMappers:         &protocolMappers,
			}, []gocloak.Role{*opentdfReadonlyRole}, nil, "")
			if err != nil {
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

		},
	}
)

func keycloakLogin(connectParams *keycloakConnectParams) (*gocloak.GoCloak, *gocloak.JWT, error) {
	client := gocloak.NewClient(connectParams.BasePath)
	//restyClient := client.RestyClient()
	//TODO allow insecure TLS....
	//restyClient.SetTLSClientConfig(tlsConfig)
	//Get Token from master
	token, err := client.LoginAdmin(context.Background(), connectParams.Username, connectParams.Password, "master")
	if err != nil {
		slog.Error(fmt.Sprintf("Error logging into keycloak: %s", err))
	}
	return client, token, err
}

func createClient(connectParams *keycloakConnectParams, newClient gocloak.Client, realmRoles []gocloak.Role, clientRoles []gocloak.Role, clientIdRole string) (string, error) {
	var longClientId string
	client, token, err := keycloakLogin(connectParams)
	if err != nil {
		return "", err
	}
	clientId := *newClient.ClientID

	if longClientId, err = client.CreateClient(context.Background(), token.AccessToken, connectParams.Realm, newClient); err != nil {
		kcErr := err.(*gocloak.APIError)
		if kcErr.Code == 409 {
			slog.Warn(fmt.Sprintf("⏭️  client %s already exists", clientId))
			clients, err := client.GetClients(context.Background(), token.AccessToken, connectParams.Realm, gocloak.GetClientsParams{ClientID: newClient.ClientID})
			if err != nil {
				return "", err
			}
			if len(clients) == 1 {
				longClientId = *clients[0].ID
			} else {
				err = fmt.Errorf("error, %s client not found", clientId)
				return "", err
			}
		} else {
			slog.Error(fmt.Sprintf("Error creating client %s : %s", clientId, err))
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
		} else {
			for _, role := range clientRoles {
				slog.Info(fmt.Sprintf("✅ Client Role %s added to client %s", *role.Name, longClientId))
			}
		}
	}

	return longClientId, nil
}

func createUser(connectParams *keycloakConnectParams, newUser gocloak.User) (*string, error) {
	client, token, err := keycloakLogin(connectParams)
	if err != nil {
		return nil, err
	}
	username := *newUser.Username
	longUserId, err := client.CreateUser(context.Background(), token.AccessToken, connectParams.Realm, newUser)
	if err != nil {
		kcErr := err.(*gocloak.APIError)
		if kcErr.Code == 409 {
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
		} else {
			slog.Error(fmt.Sprintf("Error creating user %s : %s", username, err))
			return nil, err
		}
	} else {
		slog.Info(fmt.Sprintf("✅ User created: username = %s, user identifier=%s", username, longUserId))
	}
	return &longUserId, nil
}

func getClientRolesByList(connectParams *keycloakConnectParams, client *gocloak.GoCloak, token *gocloak.JWT, ctx context.Context, idClient string, roles []string) (clientRoles []gocloak.Role, getErr error) {
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

func getIdOfClient(client *gocloak.GoCloak, token *gocloak.JWT, connectParams *keycloakConnectParams, clientName *string) (*string, error) {
	results, err := client.GetClients(context.Background(), token.AccessToken, connectParams.Realm, gocloak.GetClientsParams{ClientID: clientName})
	if err != nil || len(results) == 0 {
		slog.Error(fmt.Sprintf("Error getting realm management client: %s", err))
		return nil, err
	}
	clientId := results[0].ID
	return clientId, nil
}

func createTokenExchange(connectParams *keycloakConnectParams, startClientId string, targetClientId string) error {
	client, token, err := keycloakLogin(connectParams)
	if err != nil {
		return err
	}
	//Step 1- enable permissions for target client
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
		kcErr := err.(*gocloak.APIError)
		if kcErr.Code == 409 {
			slog.Warn(fmt.Sprintf("⏭️  policy %s already exists; skipping remainder of token exchange creation", *realmMgmtExchangePolicyRepresentation.Name))
			return nil
		}
		slog.Error(fmt.Sprintf("Error create realm management policy: %s", err))
		return err
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

func init() {

	provisionKeycloakCmd.Flags().StringP(provKcEndpoint, "e", "http://localhost:8888/auth", "Keycloak endpoint")
	provisionKeycloakCmd.Flags().StringP(provKcUsername, "u", "admin", "Keycloak username")
	provisionKeycloakCmd.Flags().StringP(provKcPassword, "p", "changeme", "Keycloak password")
	provisionKeycloakCmd.Flags().StringP(provKcRealm, "r", "opentdf", "OpenTDF Keycloak Realm name")

	provisionCmd.AddCommand(provisionKeycloakCmd)

	rootCmd.AddCommand(provisionKeycloakCmd)

}
