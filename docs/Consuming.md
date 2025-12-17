# Consumers 

The information below is meant for users of the OpenTDF platform.

To contribute/develop, see [here](./Contributing.md).

## Running the Platform Locally

> [!WARNING]
> This quickstart guide is intended for development and testing purposes only. The OpenTDF platform team does not
> provide recommendations for production deployments.

To get started with the OpenTDF platform make sure you are running the same Go version found in the `go.mod` file.

<!-- markdownlint-disable MD034 github embedded sourcecode -->
https://github.com/opentdf/platform/blob/main/service/go.mod#L3

1. **Initialize Platform Configuration**
   ```shell
   cp opentdf-dev.yaml opentdf.yaml

   # Generate development keys/certs for the platform infrastructure.
   ./.github/scripts/init-temp-keys.sh

   # The following command is for macOS to trust the local certificate.
   # For Linux, you may need to use a different command, e.g.:
   # sudo cp ./keys/localhost.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates
   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./keys/localhost.crt
   ```
   - Optional: Update the [configuration](./Configuring.md) as needed.
   - Optional: To remove the certificate, run:
     ```shell
     sudo security delete-certificate -c "localhost"
     ```
2. **Start Platform Services**
   
   Start all services including automated provisioning with [compose-spec](https://compose-spec.io).

   ```shell
   # If running on Apple M4 chip
   JAVA_OPTS_APPEND="-XX:UseSVE=0" docker compose up

   # Or on other architectures
   docker compose up
   ```
   
   This will automatically:
   - Start the background services (Keycloak, PostgreSQL)
   - Provision Keycloak with initial configuration
   - Add sample attributes and metadata
   - Start the OpenTDF Platform server

## 🎉 Your platform is ready to use!

You can now access platform services at http://localhost:8080/ , and Keycloak at http://localhost:8888/auth/ .

##  Next steps
* Try out our CLI (`otdfctl`): https://github.com/opentdf/otdfctl
   ```sh
   otdfctl auth client-credentials --host http://localhost:8080 --client-id opentdf --client-secret secret
   ```
* Join our slack channel ([click here](https://join.slack.com/t/opentdf/shared_invite/zt-1e3jhnedw-wjviK~qRH_T1zG4dfaa~3A))
* Connect with the team
