# Contributing

The information below is meant for developers of the OpenTDF platform.

For end-users/consumers, see [here](./Consuming.md).

## Running the development stack

> [!NOTE]
> Migrations are handled automatically by the server. This can be disabled via the config file, as
> needed. They can also be run manually using the `migrate` command
> (`go run github.com/opentdf/platform/service migrate up`).

1.  Configure KAS and Keycloak keys: `.github/scripts/init-temp-keys.sh`. Creates temporary keys for the local KAS and Keycloak Certificate Exchange. 
2. `docker-compose up`. Starts both the local Postgres database (contains the ABAC policy configuration data) and Keycloak (the local IdP).
   1. Note: You will have to add the ``localhost.crt`` as a trusted certificate to do TLS authentication at ``localhost:8443``.
3. Create an OpenTDF config file: `opentdf.yaml`
   1. The `opentdf-dev.yaml` file is the more secure starting point, but you will likely need to modify it to match your environment. This configuration is recommended as it is more secure but it does require valid development keypairs.
   2. The `opentdf-example-no-kas.yaml` file is simpler to run but less secure. This file configures the platform to startup without a KAS instances and without endpoint authentication.
4. Provision keycloak: `go run github.com/opentdf/platform/service provision keycloak`. Updates the local Keycloak configuration for local testing and development by creating a realm, roles, a client, and users.
5. Run the server: `go run github.com/opentdf/platform/service start`. Runs the OpenTDF platform capabilities as a monolithic service.
   1. _Alt_ use the hot-reload development environment `air`
6. The server is now running on `localhost:8080` (or the port specified in the config file)

Note: support was added to provision a set of fixture data into the database.
Run `go run github.com/opentdf/platform/service provision fixtures -h` for more information.