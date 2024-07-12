# Contributing

The information below is meant for developers of the OpenTDF platform.

For end-users/consumers, see [here](./Consuming.md).

## Running the development stack

> [!NOTE]
> Database schema migrations are handled automatically by the server.
> This can be disabled via the config file, as needed.
> They can also be run manually using the `migrate` command,
> `go run github.com/opentdf/platform/service migrate up`.

1. `.github/scripts/init-temp-keys.sh`
   creates KAS and Keycloak keys.
   These are developer mode only keys for the local KAS and Keycloak Certificate Exchange.
2. `docker compose up`
   starts both the local Postgres database (contains the ABAC policy configuration data)
   and Keycloak (the local IdP).
3. *(Optional)* To support HTTPS connections to `localhost:8443`,
   add the `localhost.crt` as a trusted certificate.
   How to do this is [operating system specific](https://deliciousbrains.com/ssl-certificate-authority-for-local-https-development/).
   - For macOS, [install it into the keychain](https://tosbourn.com/getting-os-x-to-trust-self-signed-ssl-certificates/).
   - On Ubuntu linux, copy the file to [`/usr/local/share/ca-certificates` and then use `update-ca-certificates`](https://superuser.com/a/719047)
4. Create an OpenTDF config file: `opentdf.yaml`. 
   You may copy and modify one of the sample configuration files,
   named in the format `opentdf-[option].yaml`.
   1. The `opentdf-dev.yaml` file is the more secure starting point,
   but you will likely need to modify it to match your environment.
   This configuration is recommended as it is more secure
   and allows for use of TDF encryption,
   but it does require valid development keypairs.
   2. The `opentdf-example-no-kas.yaml` file is simpler to run but less secure.
   This file configures the platform to startup without a KAS instances
   and without endpoint authentication.
5. `go run github.com/opentdf/platform/service provision keycloak`
   provisions keycloak with a test configuration.
   This adds a development realm, complete with a test client and users,
   to the keycloak started in step 2 above.
6. `go run github.com/opentdf/platform/service start`
   runs the platform services configured in step 4.
   - *Optional Alternative* The `air` command starts in hot-reload mode.
7. The server is now running on `localhost:8080` (or the port specified in the config file)
8. *(Optional)* `go run github.com/opentdf/platform/service provision fixtures` 
   Add ABAC sample configuration.

All commands to service (`provision`, `start`, etc.) provide detailed `--help`.
