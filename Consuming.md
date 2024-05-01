# Consumers 

The information below is meant for users of the OpenTDF platform.

To contribute/develop, see [here](./Contributing.md).

## Running the Platform Locally

1. Initialize KAS Keys ```.github/scripts/init-temp-keys.sh -o kas-keys```
2. Stand up the local Postgres database and Keycloak instances using `docker-compose up -d --wait`.
3. Copy the `opentdf-example.yaml` file to `opentdf.yaml` and update the [configuration](./docs/configuration.md) as needed.
Bootstrap Keycloak

   ```sh
   docker run --network opentdf_platform \
         -v "$(pwd)/opentdf.yaml:/home/nonroot/.opentdf/opentdf.yaml" \
         -it registry.opentdf.io/platform:nightly provision keycloak -e http://keycloak:8888/auth
   ```
4. Start the platform

   Exposes the server at localhost:8080
   ```sh
   docker run --network opentdf_platform \
      -p "127.0.0.1:8080:8080" \
      -v "$(pwd)/kas-keys/:/keys/" \
      -v "$(pwd)/opentdf.yaml:/home/nonroot/.opentdf/opentdf.yaml" \
      -it registry.opentdf.io/platform:nightly start
   ```
