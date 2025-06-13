# Test-Ready Service (TRS)

The Test-Ready Service (TRS) is a service that provides a pattern or recipe for building
services, integrated to the OpenTDF platform, that enable developers to test functionality 
through unit and integration testing. 

## Motivation

This `example` is just a recipe, think of it as a template you can copy to use for 
testing your own services.

From time-to-time, a service must be embedded into the OpenTDF platform AND tested in such
a way that an external event triggers the service to perform some action.

This need to invert the control of the test so that an external event can be observed
is a distinguishing factor for the Test-Ready Service (TRS). 

## Usage

```bash
# Prerequisites
./.github/scripts/init-temp-keys.sh
docker-compose -f docker-compose.yaml up
```

Next, in a new terminal tab, run the following commands to provision 
the Keycloak service and execute the TRS integration tests:

```bash
cp opentdf-dev.yaml opentdf.yaml
go run ./service provision keycloak
cd examples/trs/
go test -timeout 30s -run ^TestTRSIntegration$
```

The exit code of the tests should be 0, indicating that all tests passed. As an extra 
verbose (sanity check), you could run the following command to print a message based on the exit code:

```bash
[ $? -eq 0 ] && echo 'All tests pass' || echo 'Test failure'
```