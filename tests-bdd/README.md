# Cucumber Platform Testing

BDD via [cucumber framework](https://cucumber.io/docs/cucumber/api/) for platform and related individual components.

# Run Smoke Tests
```shell
CUKES_LOG_HANDLER=console  COMPOSE_LOG_HANDLER=console go test ./tests-bdd -v --tags=cukes --godog.random --godog.format=pretty ./features/smoke.feature
```