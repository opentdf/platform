# Consumers 

The information below is meant for users of the OpenTDF platform.

To contribute/develop, see [here](./Contributing.md).

## Running the Platform Locally

1. Initialize KAS Keys ```.github/scripts/init-temp-keys.sh -o kas-keys```
1. Stand up the local Postgres database and Keycloak instances using `docker-compose up -d --wait`.
1. Copy the `opentdf-example.yaml` file to `opentdf.yaml` and update the [configuration](./docs/configuration.md) as needed.
1. Bootstrap Keycloak

   ```sh
   docker run --network opentdf_platform \
         -v "$(pwd)/opentdf.yaml:/home/nonroot/.opentdf/opentdf.yaml" \
         -it registry.opentdf.io/platform:nightly provision keycloak -e http://keycloak:8888/auth
   ```
1. Start the platform

   Exposes the server at localhost:8080
   ```sh
   docker run --network opentdf_platform \
      -p "127.0.0.1:8080:8080" \
      -v "$(pwd)/kas-keys/:/keys/" \
      -v "$(pwd)/opentdf.yaml:/home/nonroot/.opentdf/opentdf.yaml" \
      -it registry.opentdf.io/platform:nightly start
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
