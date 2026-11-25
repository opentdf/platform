package main

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	scip "github.com/scip-code/scip/bindings/go/scip"
	"google.golang.org/protobuf/proto"
)

const (
	minimumArgs   = 4
	usageExitCode = 2
	outputPerm    = 0o600
)

func main() {
	if len(os.Args) < minimumArgs {
		fmt.Fprintf(os.Stderr, "usage: %s <repo-root> <output> <module-prefix=input.scip>...\n", os.Args[0])
		os.Exit(usageExitCode)
	}

	repoRoot, err := filepath.Abs(os.Args[1])
	if err != nil {
		fatal("resolve repo root", err)
	}

	outputPath, err := filepath.Abs(os.Args[2])
	if err != nil {
		fatal("resolve output path", err)
	}

	repoURL := (&url.URL{Scheme: "file", Path: filepath.ToSlash(repoRoot)}).String()
	merged := &scip.Index{}
	seenDocs := make(map[string]struct{})
	externalSymbols := make(map[string]*scip.SymbolInformation)
	metadataInitialized := false

	for _, arg := range os.Args[3:] {
		modulePrefix, inputPath, ok := strings.Cut(arg, "=")
		if !ok {
			fatalf("invalid input %q: expected <module-prefix>=<path>", arg)
		}

		modulePrefix = strings.TrimPrefix(filepath.ToSlash(modulePrefix), "./")
		if modulePrefix == "." {
			modulePrefix = ""
		}

		data, err := os.ReadFile(inputPath)
		if err != nil {
			fatal("read input "+inputPath, err)
		}

		var idx scip.Index
		if err := proto.Unmarshal(data, &idx); err != nil {
			fatal("decode input "+inputPath, err)
		}

		if metadata := idx.GetMetadata(); metadata != nil && !metadataInitialized {
			clonedMetadata, metadataOK := proto.Clone(metadata).(*scip.Metadata)
			if !metadataOK {
				fatalf("clone metadata for %s: unexpected type", inputPath)
			}
			merged.Metadata = clonedMetadata
			merged.Metadata.ProjectRoot = repoURL
			metadataInitialized = true
		}

		for _, doc := range idx.GetDocuments() {
			if doc == nil {
				continue
			}

			rel := filepath.ToSlash(doc.GetRelativePath())
			if modulePrefix != "" {
				rel = path.Clean(path.Join(modulePrefix, rel))
			} else {
				rel = path.Clean(rel)
			}

			doc.RelativePath = rel
			if _, exists := seenDocs[rel]; exists {
				fatalf("duplicate document path after merge: %s", rel)
			}
			seenDocs[rel] = struct{}{}
			merged.Documents = append(merged.Documents, doc)
		}

		for _, sym := range idx.GetExternalSymbols() {
			if sym == nil || sym.GetSymbol() == "" {
				continue
			}
			if _, exists := externalSymbols[sym.GetSymbol()]; !exists {
				externalSymbols[sym.GetSymbol()] = sym
			}
		}
	}

	if !metadataInitialized {
		merged.Metadata = &scip.Metadata{ProjectRoot: repoURL}
	}

	merged.Metadata.ProjectRoot = repoURL

	merged.ExternalSymbols = make([]*scip.SymbolInformation, 0, len(externalSymbols))
	for _, sym := range externalSymbols {
		merged.ExternalSymbols = append(merged.ExternalSymbols, sym)
	}

	documents := merged.GetDocuments()
	sort.Slice(documents, func(i, j int) bool {
		return documents[i].GetRelativePath() < documents[j].GetRelativePath()
	})

	mergedExternalSymbols := merged.GetExternalSymbols()
	sort.Slice(mergedExternalSymbols, func(i, j int) bool {
		return mergedExternalSymbols[i].GetSymbol() < mergedExternalSymbols[j].GetSymbol()
	})

	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(merged)
	if err != nil {
		fatal("encode merged index", err)
	}

	if err := os.WriteFile(outputPath, payload, outputPerm); err != nil {
		fatal("write merged index", err)
	}
}

func fatal(context string, err error) {
	fatalf("%s: %v", context, err)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
