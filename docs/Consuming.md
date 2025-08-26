# Consumers 

The information below is meant for users of the OpenTDF platform.

To contribute/develop, see [here](./Contributing.md).

## Running the Platform Locally

1. **Initialize Platform Configuration**
   ```shell
   cp opentdf-dev.yaml opentdf.yaml
   sed -i '' 's/e1/ec1/g' opentdf.yaml
   yq eval '.services.kas.ec_tdf_enabled = true' -i opentdf.yaml
   .github/scripts/init-temp-keys.sh
   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./keys/localhost.crt
   ```
   - Optional: Update the [configuration](./Configuring.md) as needed.
   - Optional: To remove the certificate, run:
     ```shell
     sudo security delete-certificate -c "localhost"
     ```
2. **Start Background Services**
   ```shell
   docker compose up
   ```
3. **Provision Keycloak**
   ```shell
   go run ./service provision keycloak
   ```
4. **Add Sample Attributes and Metadata**
   ```shell
   go run ./service provision fixtures
   ```
5. **Start Server**
   ```shell
   go run ./service start
   ```

## 🎉 Your platform is ready to use!

You can now access platform services at http://localhost:8080/ , and Keycloak at http://localhost:8888/auth/ .

##  Next steps
* Try out our CLI (`otdfctl`): https://github.com/opentdf/otdfctl
   ```sh
   otdfctl auth client-credentials --host http://localhost:8080 --client-id opentdf --client-secret secret
   ```
* Join our slack channel ([click here](https://join.slack.com/t/opentdf/shared_invite/zt-1e3jhnedw-wjviK~qRH_T1zG4dfaa~3A))
* Connect with the team
