// Command tfreview reviews `terraform show -json` plan output.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"tfreview/internal/plan"
)

// Exit codes (spec section 7).
const (
	exitApprove        = 0
	exitNeedsAttention = 1
	exitInputError     = 3
	exitConfigError    = 4
)

const emptyStdinMessage = "no plan JSON on stdin; did the upstream command fail?"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, stdinIsTerminal()))
}

// run is main without process globals. stdinTTY reports whether stdin is an
// interactive terminal, in which case reading it would block forever.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer, stdinTTY bool) int {
	fs := flag.NewFlagSet("tfreview", flag.ContinueOnError)
	fs.SetOutput(stderr)
	planPath := fs.String("plan", "", "path to `terraform show -json` output (default: stdin)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: terraform show -json tfplan | tfreview")
		fmt.Fprintln(stderr, "       tfreview --plan plan.json")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitApprove
		}
		return exitConfigError
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "tfreview: unexpected argument %q\n", fs.Arg(0))
		fs.Usage()
		return exitConfigError
	}

	var in io.Reader
	source := "stdin"
	if *planPath != "" {
		f, err := os.Open(*planPath)
		if err != nil {
			fmt.Fprintf(stderr, "tfreview: %v\n", err)
			return exitInputError
		}
		defer f.Close()
		in, source = f, *planPath
	} else {
		if stdinTTY {
			fmt.Fprintln(stderr, "tfreview: "+emptyStdinMessage)
			fs.Usage()
			return exitInputError
		}
		in = stdin
	}

	p, err := plan.Parse(in)
	if err != nil {
		switch {
		case errors.Is(err, plan.ErrEmptyInput) && source == "stdin":
			fmt.Fprintln(stderr, "tfreview: "+emptyStdinMessage)
		case errors.Is(err, plan.ErrEmptyInput):
			fmt.Fprintf(stderr, "tfreview: plan file %s is empty\n", source)
		default:
			fmt.Fprintf(stderr, "tfreview: %s: %v\n", source, err)
		}
		return exitInputError
	}

	printPlan(stdout, p)

	// An errored or partial plan forces at least needs-attention (section 4).
	if p.Errored || !p.Complete {
		return exitNeedsAttention
	}
	return exitApprove
}

func printPlan(w io.Writer, p *plan.Plan) {
	if p.Errored {
		fmt.Fprintln(w, "WARNING: plan errored; Terraform did not finish planning and this list may be incomplete")
	}
	if !p.Complete {
		fmt.Fprintln(w, "WARNING: plan is incomplete (complete: false); some changes are deferred and not shown")
	}
	for _, msg := range p.Warnings {
		fmt.Fprintln(w, "WARNING: "+msg)
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ADDRESS\tACTION\tREASON")
	for _, c := range p.Changes {
		action := c.Action.String()
		if c.Action == plan.Unknown {
			action += "(" + strings.Join(c.RawActions, ",") + ")"
		}
		reason := c.ActionReason
		if reason == "" {
			reason = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.Address, action, reason)
	}
	tw.Flush()
}

func stdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
