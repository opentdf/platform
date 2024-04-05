package sample

my_json = {
  "testing1": {
    "testing2": {
      "testing3": ["helloworld"]
    }
  }
}
req = ".testing1.testing2.testing3[]"
res := jq.evaluate(my_json, req)

# res := keycloak.resolve.entities(input.req, input.config)
