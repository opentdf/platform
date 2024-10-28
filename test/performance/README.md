## Before Running

1. add a no-attribute ZTDF encrypted by the keys in your platform instance as `no-attrs.txt.tdf`
2. run the platform with containerized resources (i.e. `docker compose up`)
3. add any additional HTTP GET requests or gRPC requests via Go SDK to the various test functions in `main.go`

## Results

Results of each individual test run are printed to stdout.

Averages across test runs are appended as a JSON array to a file `results.json` in the directory
where the test process is run.

## Next steps

1. Move some variables to runtime env/config:
   1. list of HTTP GET endpoints
   2. quantity of test runs per test
   3. max concurrency
   4. minimum concurrency
   5. result artifact location
2. Support encrypt of a no-attributes TDF on the fly
3. Support encrypt and testing decrypt performance of a TDF containing attributes on the fly
4. General clean up
