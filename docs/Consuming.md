# Consumers 

The information below is meant for users of the OpenTDF platform.

To contribute/develop, see [here](./Contributing.md).

## Running the Platform Locally

> [!WARNING]
> This quickstart guide is intended for development and testing purposes only. The OpenTDF platform team does not
> provide recommendations for production deployments.

**Update `/etc/hosts`**


In order for the services to communicate correctly you will need to update your `/etc/hosts` file.

```shell
echo -e "127.0.0.1 platform.opentdf.local\n127.0.0.1 keycloak.opentdf.local" | sudo tee -a /etc/hosts
```

**Start Platform Services**
   
Start all services including automated provisioning with [compose-spec](https://compose-spec.io).

```shell
# If running on Apple M4 chip
JAVA_OPTS_APPEND="-XX:UseSVE=0" docker compose --file docker-compose.consumer.yaml up -d

# Or on other architectures
docker compose --file docker-compose.consumer.yaml up -d
```

This will automatically:
- Download configuration files from GitHub
- Generate development keys and certificates
- Start the background services (Keycloak, PostgreSQL)
- Provision Keycloak with initial configuration
- Add sample attributes and metadata
- Start the OpenTDF Platform server

## 🎉 Your platform is ready to use!

You can now access the platform services.

* Find platform configuration at https://platform.opentdf.local:8443/.well-known/opentdf-configuration , and
* Find Keycloak at https://keycloak.opentdf.local:9443/auth/ .

### Optional: Trust the Local Certificate

If you want to trust the auto-generated certificate on your host machine:

```shell
# For macOS
docker compose cp keycloak:/keys/localhost.crt ./
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./localhost.crt

# For Linux
docker compose cp keycloak:/keys/localhost.crt ./
sudo cp ./localhost.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates
```

To remove the certificate later:
```shell
sudo security delete-certificate -c "localhost"  # macOS
```

##  Next steps
* Try out our CLI (`otdfctl`): https://github.com/opentdf/otdfctl
   ```sh
   otdfctl auth client-credentials --host https://platform.opentdf.local:8443 --tls-no-verify
   ```
* Join our slack channel ([click here](https://join.slack.com/t/opentdf/shared_invite/zt-1e3jhnedw-wjviK~qRH_T1zG4dfaa~3A))
* Connect with the team
