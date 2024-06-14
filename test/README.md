# Integration Tests

To run locally, first install bats:

```sh
brew install bats-core
brew tap bats-core/bats-core
brew install bats-support
brew install bats-assert
export BATS_LIB_PATH=/opt/homebrew/lib
```

Then, run:

```sh
./test/[your test].bats
```
