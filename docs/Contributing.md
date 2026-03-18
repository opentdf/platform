# Contributing

The information below is meant for developers of the OpenTDF platform.

For end-users/consumers, see [here](./Consuming.md).

## Running the development stack

> [!NOTE]
> Migrations are handled automatically by the server. This can be disabled via the config file, as
> needed. They can also be run manually using the `migrate` command
> (`go run github.com/opentdf/platform/service migrate up`).

1.  Configure KAS and Keycloak keys: `.github/scripts/init-temp-keys.sh`. Creates temporary keys for the local KAS and Keycloak Certificate Exchange. 
2. `docker compose up`. Starts both the local Postgres database (contains the ABAC policy configuration data) and Keycloak (the local IdP).
   1. Note: You will have to add the ``localhost.crt`` as a trusted certificate to do TLS authentication at ``localhost:8443``. On a mac, this is `security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ./keys/localhost.crt`
3. Create an OpenTDF config file: `opentdf.yaml`
   1. The `opentdf-dev.yaml` file is the more secure starting point, but you will likely need to modify it to match your environment. This configuration is recommended as it is more secure but it does require valid development keypairs.
   2. The `opentdf-core-mode.yaml` file is simpler to run but less secure. This file configures the platform to startup without a KAS instances, without a built-in ERS instance, and without endpoint authentication.
4. Provision keycloak: `go run github.com/opentdf/platform/service provision keycloak`. Updates the local Keycloak configuration for local testing and development by creating a realm, roles, a client, and users.
5. Run the server: `go run github.com/opentdf/platform/service start`. Runs the OpenTDF platform capabilities as a monolithic service.
   1. _Alt_ use the hot-reload development environment `air`
6. The server is now running on `localhost:8080` (or the port specified in the config file)

Note: support was added to provision a set of fixture data into the database.
Run `go run github.com/opentdf/platform/service provision fixtures -h` for more information.

## Running with Distributed Tracing (OpenTelemetry)

The platform incorporates OpenTelemetry for distributed tracing, providing insights into request flows and performance across services.

To enable distributed tracing with Jaeger:

1. Start the development stack with the tracing profile:
   ```bash
   docker compose --profile tracing up
   ```
   This will start Jaeger alongside the other services.

2. Configure tracing in your `opentdf.yaml`:
   ```yaml
   server:
     trace:
       enabled: true
       provider:
         name: otlp
         otlp:
           protocol: grpc
           endpoint: "localhost:4317"
           insecure: true
   ```

3. Access the Jaeger UI at http://localhost:16686 to view traces:
   - Search for traces by service name "opentdf-service"
   - View detailed spans and timing information
   - Analyze request flows across services

Note: When using the file provider (`name: file`), traces will be written to local files instead of being sent to Jaeger.

## API Documentation Generation

To generate all protobuf, gRPC, and OpenAPI documentation (including OpenAPI v2 and v3.1 for ConnectRPC), run:

```fish
make proto-generate
```

This will output documentation to `docs/openapi` and `docs/grpc`.

### Required Tools

Install the following tools if you haven't already:

```fish
# Install buf
brew install bufbuild/buf/buf
# or
go install github.com/bufbuild/buf/cmd/buf@latest

# Install protoc-gen-doc
go install github.com/pseudomuto/protoc-gen-doc/cmd/protoc-gen-doc@v1.5.1

# Install protoc-gen-connect-openapi
go install github.com/sudorandom/protoc-gen-connect-openapi@latest
```

Make sure your Go bin directory (usually `$HOME/go/bin`) is in your `PATH`.

## Advice for Code Contributors

* Make sure to run our linters with `make lint`
* Follow our [Error Guidelines](./Contributing-errors.md)
