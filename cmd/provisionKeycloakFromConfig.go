package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

var (
	provKeycloakFilename = "./cmd/keycloak_data.yaml"
	keycloakData         KeycloakData
)

type KeycloakData struct {
	Realms []RealmToCreate `yaml:"realms" json:"realms"`
}
type RealmToCreate struct {
	RealmRepresentation gocloak.RealmRepresentation `yaml:"realm_repepresentation" json:"realm_repepresentation"`
	Clients             []Client                    `yaml:"clients,omitempty" json:"clients,omitempty"`
	Users               []gocloak.User              `yaml:"users,omitempty" json:"users,omitempty"`
	CustomRealmRoles    []gocloak.Role              `yaml:"custom_realm_roles,omitempty" json:"custom_realm_roles,omitempty"`
	CustomGroups        []gocloak.Group             `yaml:"custom_groups,omitempty" json:"custom_groups,omitempty"`
}

type Client struct {
	Client        gocloak.Client      `yaml:"client" json:"client"`
	SaRealmRoles  []string            `yaml:"sa_realm_roles,omitempty" json:"sa_realm_roles,omitempty"`
	SaClientRoles map[string][]string `yaml:"sa_client_roles,omitempty" json:"sa_client_roles,omitempty"`
}

var (
	provisionKeycloakFromConfigCmd = &cobra.Command{
		Use:   "keycloak-from-config",
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
			// realmName, _ := cmd.Flags().GetString(provKcRealm)
			kcUsername, _ := cmd.Flags().GetString(provKcUsername)
			kcPassword, _ := cmd.Flags().GetString(provKcPassword)
			keycloakFilename, _ := cmd.Flags().GetString(provKeycloakFilename)

			// config, err := config.LoadConfig("")
			LoadKeycloakData(keycloakFilename)
			ctx := context.Background()

			// for each realm to create
			for _, realmToCreate := range keycloakData.Realms {

				// login and try to create the realm
				if realmToCreate.RealmRepresentation.Realm == nil {
					return errors.New("realm does not have name")
				}

				kcConnectParams := keycloakConnectParams{
					BasePath:         kcEndpoint,
					Username:         kcUsername,
					Password:         kcPassword,
					Realm:            *realmToCreate.RealmRepresentation.Realm,
					AllowInsecureTLS: true,
				}
				err := createRealm(ctx, kcConnectParams, realmToCreate.RealmRepresentation)
				if err != nil {
					return err
				}

				//login to new realm
				client, token, err := keycloakLogin(&kcConnectParams)
				if err != nil {
					return err
				}

				// create the custom roles
				if realmToCreate.CustomRealmRoles != nil {
					for _, customRole := range realmToCreate.CustomRealmRoles {
						err = createRole(ctx, client, token, *realmToCreate.RealmRepresentation.Realm, customRole)
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
						err = createCustomClient(ctx, client, token, *realmToCreate.RealmRepresentation.Realm, customClient)
						if err != nil {
							return err
						}
					}
				}

				// create the users
				if realmToCreate.Users != nil {
					for _, customUser := range realmToCreate.Users {
						err = createCustomUser(ctx, client, token, *realmToCreate.RealmRepresentation.Realm, customUser)
						if err != nil {
							return err
						}
					}
				}

			}

			return nil
		},
	}
)

func createRealm(ctx context.Context, kcConnectParams keycloakConnectParams, realm gocloak.RealmRepresentation) error {
	// Create realm, if it does not exist.
	client, token, err := keycloakLogin(&kcConnectParams)
	if err != nil {
		return err
	}

	//Create realm
	r, err := client.GetRealm(ctx, token.AccessToken, *realm.Realm)
	if err != nil {
		kcErr := err.(*gocloak.APIError)
		if kcErr.Code == 409 {
			slog.Info(fmt.Sprintf("⏭️ %s realm already exists, skipping create", *realm.Realm))
		} else if kcErr.Code != 404 {
			return err
		}
	}

	if r == nil {
		if _, err := client.CreateRealm(ctx, token.AccessToken, realm); err != nil {
			return err
		}
		slog.Info("✅ Realm created", slog.String("realm", *realm.Realm))

		//update realm users profile via upconfig
		realmProfileUrl := fmt.Sprintf("%s/admin/realms/%s/users/profile", kcConnectParams.BasePath, *realm.Realm)
		realmUserProfileResp, err := client.GetRequestWithBearerAuth(ctx, token.AccessToken).Get(realmProfileUrl)
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
		_, err = client.GetRequestWithBearerAuth(ctx, token.AccessToken).SetBody(upConfig).Put(realmProfileUrl)
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
		kcErr := err.(*gocloak.APIError)
		if kcErr.Code == 409 {
			slog.Warn(fmt.Sprintf("⏭️  group %s already exists", *group.Name))
		} else {
			return err
		}
	} else {
		slog.Info(fmt.Sprintf("✅ Group created: group = %s", *group.Name))
	}
	return nil
}

func createRole(ctx context.Context, client *gocloak.GoCloak, token *gocloak.JWT, realmName string, role gocloak.Role) error {
	if role.Name == nil {
		return errors.New("realm role does not have name")
	}
	_, err := client.CreateRealmRole(ctx, token.AccessToken, realmName, role)
	if err != nil {
		kcErr := err.(*gocloak.APIError)
		if kcErr.Code == 409 {
			slog.Warn(fmt.Sprintf("⏭️  role %s already exists", *role.Name))
		} else {
			return err
		}
	} else {
		slog.Info(fmt.Sprintf("✅ Role created: role = %s", *role.Name))
	}
	return nil
}

func createCustomClient(ctx context.Context, client *gocloak.GoCloak, token *gocloak.JWT, realmName string, clientToCreate Client) error {
	if clientToCreate.Client.ClientID == nil {
		return errors.New("Client does not have clientID")
	}

	longClientId, err := client.CreateClient(context.Background(), token.AccessToken, realmName, clientToCreate.Client)

	if err != nil {
		kcErr := err.(*gocloak.APIError)
		if kcErr.Code == 409 {
			slog.Warn(fmt.Sprintf("⏭️  client %s already exists", *clientToCreate.Client.ClientID))
			clients, err := client.GetClients(context.Background(), token.AccessToken, realmName, gocloak.GetClientsParams{ClientID: clientToCreate.Client.ClientID})
			if err != nil {
				return err
			}
			if len(clients) == 1 {
				longClientId = *clients[0].ID
			} else {
				err = fmt.Errorf("error, %s client not found", *clientToCreate.Client.ClientID)
				return err
			}
		} else {
			slog.Error(fmt.Sprintf("Error creating client %s : %s", *clientToCreate.Client.ClientID, err))
			return err
		}
	} else {
		slog.Info(fmt.Sprintf("✅ Client created: client id = %s, client identifier=%s", *clientToCreate.Client.ClientID, longClientId))
	}

	// get the service account
	user, err := client.GetClientServiceAccount(context.Background(), token.AccessToken, realmName, longClientId)
	if err != nil {
		slog.Error(fmt.Sprintf("Error getting service account user for client %s : %s", *clientToCreate.Client.ClientID, err))
		return err
	}
	slog.Info(fmt.Sprintf("ℹ️  Service account user for client %s : %s", *clientToCreate.Client.ClientID, *user.Username))

	// assign realm roles
	if clientToCreate.SaRealmRoles != nil {
		err = assignRealmRolesToClientSA(ctx, client, token, realmName, longClientId, user, clientToCreate.SaRealmRoles)
		if err != nil {
			return err
		}
	}

	// assign client roles
	if clientToCreate.SaClientRoles != nil {
		err = assignClientRolesToClientSA(ctx, client, token, realmName, longClientId, user, clientToCreate.SaClientRoles)
		if err != nil {
			return err
		}
	}

	return nil

}
func assignRealmRolesToClientSA(ctx context.Context, client *gocloak.GoCloak, token *gocloak.JWT, realmName string, longClientId string, user *gocloak.User, rolesToAdd []string) error {
	slog.Info(fmt.Sprintf("Adding realm roles to client %s via service account %s", longClientId, *user.Username))

	// retrieve the roles by name
	var roles []gocloak.Role
	for _, roleName := range rolesToAdd {
		role, err := client.GetRealmRole(
			ctx,
			token.AccessToken,
			realmName,
			roleName)
		if err != nil {
			slog.Error(fmt.Sprintf("Error getting realm role for realm %s : %s", roleName, realmName))
			return err
		}
		roles = append(roles, *role)

	}

	if err := client.AddRealmRoleToUser(context.Background(), token.AccessToken, realmName, *user.ID, roles); err != nil {
		for _, role := range roles {
			slog.Warn(fmt.Sprintf("Error adding role %s", *role.Name))
		}
		return err
	} else {
		for _, role := range roles {
			slog.Info(fmt.Sprintf("✅ Realm Role %s added to client %s", *role.Name, longClientId))
		}
	}

	return nil
}

func assignClientRolesToClientSA(ctx context.Context, client *gocloak.GoCloak, token *gocloak.JWT, realmName string, longClientId string, user *gocloak.User, rolesToAdd map[string][]string) error {
	slog.Info(fmt.Sprintf("Adding client roles to client %s via service account %s", longClientId, *user.Username))

	for clientName, roles := range rolesToAdd {
		results, err := client.GetClients(context.Background(), token.AccessToken, realmName, gocloak.GetClientsParams{ClientID: &clientName})
		if err != nil || len(results) == 0 {
			slog.Error(fmt.Sprintf("Error getting %s's client: %s", clientName, err))
			return err
		}
		clientId := results[0].ID
		clientRoles, err := getClientRolesFromList(realmName, client, token, ctx, *clientId, roles)
		if err != nil {
			slog.Error(fmt.Sprintf("Error getting client roles: %s", err))
			return err
		}

		if err := client.AddClientRolesToUser(context.Background(), token.AccessToken, realmName, *clientId, *user.ID, clientRoles); err != nil {
			for _, role := range clientRoles {
				slog.Warn(fmt.Sprintf("Error adding role %s", *role.Name))
			}
			return err
		} else {
			for _, role := range clientRoles {
				slog.Info(fmt.Sprintf("✅ Client Role %s added to client %s", *role.Name, longClientId))
			}
		}

	}
	return nil
}
func getClientRolesFromList(realmName string, client *gocloak.GoCloak, token *gocloak.JWT, ctx context.Context, idClient string, roles []string) (clientRoles []gocloak.Role, getErr error) {
	var notFoundRoles []string

	if roleObjects, tmpErr := client.GetClientRoles(ctx, token.AccessToken, realmName, idClient, gocloak.GetRoleParams{}); tmpErr != nil {
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
func createCustomUser(ctx context.Context, client *gocloak.GoCloak, token *gocloak.JWT, realmName string, userToCreate gocloak.User) error {
	if userToCreate.Username == nil {
		return errors.New("user does not have username")
	}
	longUserId, err := client.CreateUser(context.Background(), token.AccessToken, realmName, userToCreate)
	if err != nil {
		kcErr := err.(*gocloak.APIError)
		if kcErr.Code == 409 {
			slog.Warn(fmt.Sprintf("user %s already exists", *userToCreate.Username))
			users, err := client.GetUsers(context.Background(), token.AccessToken, realmName, gocloak.GetUsersParams{Username: userToCreate.Username})
			if err != nil {
				return err
			}
			if len(users) != 1 {
				err = fmt.Errorf("error, %s user not found", *userToCreate.Username)
				return err
			}
		} else {
			slog.Error(fmt.Sprintf("Error creating user %s : %s", *userToCreate.Username, err))
			return err
		}
	} else {
		slog.Info(fmt.Sprintf("✅ User created: username = %s, user identifier=%s", *userToCreate.Username, longUserId))
	}
	return nil
}

func convert(i interface{}) interface{} {
	switch x := i.(type) {
	case map[interface{}]interface{}:
		m2 := map[string]interface{}{}
		for k, v := range x {
			m2[k.(string)] = convert(v)
		}
		return m2
	case []interface{}:
		for i, v := range x {
			x[i] = convert(v)
		}
	}
	return i
}

func LoadKeycloakData(file string) {
	var yamlData = make(map[interface{}]interface{})

	f, err := os.Open(file)
	if err != nil {
		panic(fmt.Errorf("error when opening YAML file: %s", err.Error()))
	}

	fileData, err := io.ReadAll(f)
	if err != nil {
		panic(fmt.Errorf("error reading YAML file: %s", err.Error()))
	}

	err = yaml.Unmarshal(fileData, &yamlData)
	if err != nil {
		panic(fmt.Errorf("error unmarshaling yaml file %s", err.Error()))
	}

	cleanedYaml := convert(yamlData)

	kcData, err := json.Marshal(cleanedYaml)
	if err != nil {
		panic(fmt.Errorf("error converting yaml to json: %s", err.Error()))
	}
	slog.Info("", slog.Any("kcData", kcData))

	if err := json.Unmarshal(kcData, &keycloakData); err != nil {
		slog.Error("could not unmarshal json into data object", slog.String("error", err.Error()))
		panic(err)
	}

	slog.Info("Fully loaded keycloak data", slog.Any("keycloakData", keycloakData))
	// panic("hi")
}

func init() {

	provisionKeycloakFromConfigCmd.Flags().StringP(provKcEndpoint, "e", "http://localhost:8888/auth", "Keycloak endpoint")
	provisionKeycloakFromConfigCmd.Flags().StringP(provKcUsername, "u", "admin", "Keycloak username")
	provisionKeycloakFromConfigCmd.Flags().StringP(provKcPassword, "p", "changeme", "Keycloak password")
	provisionKeycloakFromConfigCmd.Flags().StringP(provKeycloakFilename, "f", "./cmd/keycloak_data.yaml", "Keycloak config file")
	// provisionKeycloakFromConfigCmd.Flags().StringP(provKcRealm, "r", "opentdf", "OpenTDF Keycloak Realm name")

	provisionCmd.AddCommand(provisionKeycloakFromConfigCmd)

	rootCmd.AddCommand(provisionKeycloakFromConfigCmd)

}
