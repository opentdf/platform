## examples completion zsh

Generate the autocompletion script for zsh

### Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(examples completion zsh)

To load completions for every new session, execute once:

#### Linux:

	examples completion zsh > "${fpath[1]}/_examples"

#### macOS:

	examples completion zsh > $(brew --prefix)/share/zsh/site-functions/_examples

You will need to start a new shell for this setup to take effect.


```
examples completion zsh [flags]
```

### Options

```
  -h, --help              help for zsh
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
  -e, --platformEndpoint string   Platform Endpoint (default "localhost:8080")
```

### SEE ALSO

* [examples completion](examples_completion.md)	 - Generate the autocompletion script for the specified shell

###### Auto generated by spf13/cobra on 14-Feb-2024
