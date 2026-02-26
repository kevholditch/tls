package prettyprint

import (
	"fmt"
	"io"
	"text/tabwriter"
)

type blockTitleStyle int

const (
	blockTitleNone blockTitleStyle = iota
	blockTitlePlain
	blockTitleKeyValue
)

type blockRowKind int

const (
	blockRowKeyValue blockRowKind = iota
	blockRowText
	blockRowIndentedText
)

type outputRow struct {
	kind  blockRowKind
	key   string
	value string
	text  string
}

type outputBlock struct {
	title      string
	titleStyle blockTitleStyle
	rows       []outputRow
}

func kvRow(key, value string) outputRow {
	return outputRow{kind: blockRowKeyValue, key: key, value: value}
}

func textRow(text string) outputRow {
	return outputRow{kind: blockRowText, text: text}
}

func indentedTextRow(text string) outputRow {
	return outputRow{kind: blockRowIndentedText, text: text}
}

func renderBlocks(w io.Writer, blocks []outputBlock) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	for i, block := range blocks {
		if i > 0 {
			if _, err := fmt.Fprintln(tw, "\t"); err != nil {
				return err
			}
		}

		switch block.titleStyle {
		case blockTitlePlain:
			if _, err := fmt.Fprintln(tw, block.title); err != nil {
				return err
			}
		case blockTitleKeyValue:
			if _, err := fmt.Fprintf(tw, "%s:\t\n", block.title); err != nil {
				return err
			}
		}

		for _, row := range block.rows {
			switch row.kind {
			case blockRowKeyValue:
				if _, err := fmt.Fprintf(tw, "%s:\t%s\n", row.key, row.value); err != nil {
					return err
				}
			case blockRowText:
				if _, err := fmt.Fprintln(tw, row.text); err != nil {
					return err
				}
			case blockRowIndentedText:
				if _, err := fmt.Fprintf(tw, "\t%s\n", row.text); err != nil {
					return err
				}
			}
		}
	}

	return tw.Flush()
}
