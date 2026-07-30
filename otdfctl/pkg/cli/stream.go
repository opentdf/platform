package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"strings"
	"text/tabwriter"
)

// tabwriter configuration for the streamed styled table.
const (
	streamTabMinWidth = 0
	streamTabWidth    = 2
	streamTabPadding  = 2
)

// StreamList renders a list of items incrementally to w.
//
// In JSON mode (the printer configured for JSON output) it writes a JSON array,
// encoding one item at a time so the full result set is never held in memory.
// This is the memory-bounded path, suitable for very large lists.
//
// In styled mode it writes a tab-aligned table with the given column headers,
// one row per item derived from row. Column alignment requires measuring every
// cell, so the styled path buffers rows until the stream completes; use JSON
// mode when memory bounds matter for a large result set.
//
// items is an iter.Seq2 yielding (item, err) so callers can feed a paged
// iterator without materializing it. A non-nil err (for example, a failed page
// fetch) aborts the stream and is returned, so a mid-iteration failure surfaces
// to the caller rather than looking like normal exhaustion. row maps an item to
// its table cells and is only invoked in styled mode.
func (c *Cli) StreamList(w io.Writer, headers []string, row func(any) []string, items iter.Seq2[any, error]) error {
	if c.printer != nil && c.printer.json {
		return streamJSONArray(w, items)
	}
	return streamTable(w, headers, row, items)
}

// streamJSONArray writes items as a pretty-printed JSON array, marshaling one
// item at a time to bound memory. Indentation and HTML-escaping match printJSON.
// A non-nil iterator error aborts before closing the array and is returned.
func streamJSONArray(w io.Writer, items iter.Seq2[any, error]) error {
	if _, err := io.WriteString(w, "["); err != nil {
		return err
	}
	first := true
	for item, err := range items {
		if err != nil {
			return err
		}
		b, err := marshalStreamItem(item)
		if err != nil {
			return err
		}
		sep := ",\n  "
		if first {
			sep = "\n  "
			first = false
		}
		if _, err := io.WriteString(w, sep); err != nil {
			return err
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
	}
	tail := "]\n"
	if !first {
		tail = "\n]\n"
	}
	_, err := io.WriteString(w, tail)
	return err
}

// marshalStreamItem encodes a single item indented for placement inside the
// streamed array, without a trailing newline.
func marshalStreamItem(item any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("  ", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(item); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// streamTable writes a tab-aligned table of headers followed by one row per
// item. tabwriter buffers writes and only reports errors on Flush, so the
// per-row writes are not error-checked (fmt.Fprint* returns are excluded from
// errcheck); a non-nil iterator error aborts before Flush and is returned.
func streamTable(w io.Writer, headers []string, row func(any) []string, items iter.Seq2[any, error]) error {
	tw := tabwriter.NewWriter(w, streamTabMinWidth, streamTabWidth, streamTabPadding, ' ', 0)
	if len(headers) > 0 {
		fmt.Fprintln(tw, strings.Join(headers, "\t"))
	}
	for item, err := range items {
		if err != nil {
			return err
		}
		fmt.Fprintln(tw, strings.Join(row(item), "\t"))
	}
	return tw.Flush()
}
