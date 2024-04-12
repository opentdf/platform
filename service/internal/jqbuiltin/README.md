## Testing an OPA builtin with a rego query

1. Set up your main.go to be the following
```
func main() {
	logLevel := &slog.LevelVar{}
	logLevel.Set(slog.LevelDebug)

	opts := &slog.HandlerOptions{
		Level: logLevel,
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, opts))

	slog.SetDefault(logger)

	jqbuiltin.JQBuiltin()

	if err := cmd.RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
```

2. Build the executable
```
cd service
go build -o opa++
```

3. Create an example rego file
```
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
```

4. Perform the query
```
./opa++ eval -d example.rego 'data.sample.res'
```

