package man

import (
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"

	"github.com/adrg/frontmatter"
	docsEmbed "github.com/opentdf/otdfctl/docs"
	"github.com/spf13/cobra"
)

var Docs Manual

type CommandOpts func(d *Doc)

type Doc struct {
	cobra.Command
	DocFlags       []DocFlag
	DocSubcommands []*Doc
}

// deprecated
func (d *Doc) GetShort(subCmds []string) string {
	return fmt.Sprintf("%s [%s]", d.Short, strings.Join(subCmds, ", "))
}

func (d *Doc) AddSubcommands(subCmds ...*Doc) {
	cmds := make([]string, 0)
	for _, c := range subCmds {
		cmds = append(cmds, c.Use)
		d.DocSubcommands = append(d.DocSubcommands, c)
		d.AddCommand(&c.Command)
	}
	d.Short = d.GetShort(cmds)
}

func WithSubcommands(subCmds ...*Doc) CommandOpts {
	return func(d *Doc) {
		for _, c := range subCmds {
			d.DocSubcommands = append(d.DocSubcommands, c)
			d.AddCommand(&c.Command)
		}
	}
}

func WithRun(f func(cmd *cobra.Command, args []string)) CommandOpts {
	return func(d *Doc) {
		d.Run = f
	}
}

// Hide any global or persisent flags from parent commands on the given command
func WithHiddenFlags(flags ...string) CommandOpts {
	return func(d *Doc) {
		// to hide root global flags, must set a custom help func that hides then calls the parent help func
		d.SetHelpFunc(func(command *cobra.Command, strings []string) {
			for _, f := range flags {
				//nolint:errcheck // hidden flag err is not a concern
				command.Flags().MarkHidden(f)
			}
			d.Parent().HelpFunc()(command, strings)
		})
	}
}

type Manual struct {
	lang string
	Docs map[string]*Doc
	En   map[string]*Doc
	Fr   map[string]*Doc
}

func (m *Manual) SetLang(l string) {
	switch l {
	case "en", "fr":
		m.lang = l
	default:
		panic(fmt.Sprintf("Unknown language: %s", l))
	}
}

func (m Manual) GetDoc(cmd string) *Doc {
	if m.lang != "en" {
		//nolint:gocritic // other languages may be supported
		switch m.lang {
		case "fr":
			if _, ok := m.Fr[cmd]; ok {
				return m.Fr[cmd]
			}
			// if no doc found in french, fallback to english
			slog.Debug(fmt.Sprintf("No doc found for cmd, %s in %s", cmd, m.lang))
		}
	}

	if _, ok := m.En[cmd]; !ok {
		panic(fmt.Sprintf("No doc found for cmd, %s", cmd))
	}

	return m.En[cmd]
}

func (m Manual) GetCommand(cmd string, opts ...CommandOpts) *Doc {
	d := m.GetDoc(cmd)

	for _, opt := range opts {
		opt(d)
	}

	if len(d.DocSubcommands) > 0 {
		s := make([]string, 0)
		for _, c := range d.DocSubcommands {
			s = append(s, c.Use)
		}
		d.Short = d.GetShort(s)
	}

	return d
}

//nolint:mnd,gocritic // allow file separator counts to be hardcoded
func ProcessEmbeddedDocs(manFiles embed.FS) {
	err := fs.WalkDir(manFiles, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		// extract language from filename
		p := strings.Split(d.Name(), ".")
		cmd := p[0]
		lang := "en"

		// check if file is a markdown file
		if p[len(p)-1] != "md" {
			return nil
		} else if len(p) < 2 || len(p) > 3 {
			return nil
		} else if len(p) == 3 {
			lang = p[1]
		}

		// remove extension and extract command from path
		p = strings.Split(path, "/")
		// remove leading and trailing slashes
		p = p[1 : len(p)-1]
		// if the last element is not _index, it is a subcommand
		if cmd != "_index" {
			p = append(p, cmd)
		}
		cmd = strings.Join(p, "/")

		if cmd == "" {
			cmd = "<root>"
		}

		slog.Debug("Found doc", slog.String("cmd", cmd), slog.String("lang", lang))
		c, err := manFiles.ReadFile(path)
		if err != nil {
			return fmt.Errorf("could not read file, %s: %s ", path, err.Error())
		}

		doc, err := ProcessDoc(string(c))
		if err != nil {
			return fmt.Errorf("could not process doc, %s: %s", path, err.Error())
		}

		slog.Debug("Adding doc: ", cmd, " ", lang, "\n")
		switch lang {
		case "fr":
			Docs.Fr[cmd] = doc
		case "en":
			Docs.En[cmd] = doc
		default:

			return fmt.Errorf("unknown language [%s]", lang)
		}
		return nil
	})
	if err != nil {
		panic("Could not read embedded files: " + err.Error())
	}
}

func init() {
	slog.Debug("Loading docs from embed")
	Docs = Manual{
		Docs: make(map[string]*Doc),
		En:   make(map[string]*Doc),
		Fr:   make(map[string]*Doc),
	}

	ProcessEmbeddedDocs(docsEmbed.ManFiles)
}

func ProcessDoc(doc string) (*Doc, error) {
	if len(doc) == 0 {
		return nil, fmt.Errorf("empty document")
	}
	var matter struct {
		Title   string `yaml:"title"`
		Command struct {
			Name          string    `yaml:"name"`
			Args          []string  `yaml:"arguments"`
			ArbitraryArgs []string  `yaml:"arbitraryArgs"`
			Hidden        bool      `yaml:"hidden"`
			Aliases       []string  `yaml:"aliases"`
			Flags         []DocFlag `yaml:"flags"`
		} `yaml:"command"`
	}
	rest, err := frontmatter.Parse(strings.NewReader(doc), &matter)
	if err != nil {
		return nil, err
	}

	c := matter.Command

	if c.Name == "" {
		return nil, fmt.Errorf("required 'command' property")
	}

	long := "# " + matter.Title + "\n\n" + strings.TrimSpace(string(rest))

	var args cobra.PositionalArgs
	if len(c.Args) > 0 {
		args = cobra.ExactArgs(len(c.Args))
	}
	if len(c.ArbitraryArgs) > 0 {
		args = cobra.ArbitraryArgs
	}

	d := Doc{
		cobra.Command{
			Use:     c.Name,
			Args:    args,
			Hidden:  c.Hidden,
			Aliases: c.Aliases,
			Short:   matter.Title,
			Long:    styleDoc(long),
		},
		c.Flags,
		nil,
	}

	return &d, nil
}
