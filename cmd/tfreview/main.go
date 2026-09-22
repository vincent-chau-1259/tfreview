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

	"tfreview/internal/classify"
	"tfreview/internal/plan"
	"tfreview/internal/predicates"
	"tfreview/internal/rules"
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
	rulesPath := fs.String("rules", "", "path to a rules YAML file (default: built-in rules)")
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

	set, err := loadRules(*rulesPath)
	if err != nil {
		fmt.Fprintf(stderr, "tfreview: %v\n", err)
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

	printPlan(stdout, p, classify.Classify(p.Changes, set))

	// An errored or partial plan forces at least needs-attention (section 4).
	if p.Errored || !p.Complete {
		return exitNeedsAttention
	}
	return exitApprove
}

func loadRules(path string) (*rules.Set, error) {
	if path == "" {
		set, err := rules.Default(predicates.Registry())
		if err != nil {
			return nil, fmt.Errorf("built-in rules: %w", err)
		}
		return set, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	set, err := rules.Load(f, predicates.Registry())
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return set, nil
}

func printPlan(w io.Writer, p *plan.Plan, results []classify.Result) {
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
	fmt.Fprintln(tw, "ADDRESS\tACTION\tSEVERITY\tRULES\tREASON")
	var details []string
	for _, r := range results {
		c := r.Change
		action := c.Action.String()
		if c.Action == plan.Unknown {
			action += "(" + strings.Join(c.RawActions, ",") + ")"
		}
		severity, ids := "unmatched", "-"
		if r.Matched() {
			severity = r.Severity.String()
			var names []string
			for _, m := range r.Matches {
				names = append(names, m.RuleID)
				if m.Detail != "" {
					details = append(details, fmt.Sprintf("  %s [%s] %s", c.Address, m.RuleID, m.Detail))
				}
			}
			ids = strings.Join(names, ",")
		}
		reason := c.ActionReason
		if reason == "" {
			reason = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", c.Address, action, severity, ids, reason)
	}
	tw.Flush()
	if len(details) > 0 {
		fmt.Fprintln(w, "\nDetails:")
		for _, d := range details {
			fmt.Fprintln(w, d)
		}
	}
	if n := len(p.Changes) - len(results); n > 0 {
		fmt.Fprintf(w, "\n%d change(s) not shown (data sources and no-op)\n", n)
	}
}

func stdinIsTerminal() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
