// Package classify evaluates rules against plan changes.
package classify

import (
	"tfreview/internal/plan"
	"tfreview/internal/rules"
)

// Match is one rule that matched a change.
type Match struct {
	RuleID   string
	Severity rules.Severity
	Meaning  string
	Detail   string // from the rule's predicate; names paths, never sensitive values
	Block    bool
}

// Result is the classification of one change.
type Result struct {
	Change  plan.Change
	Matches []Match

	// Severity is the highest severity among Matches, or rules.None when no
	// rule matched.
	Severity rules.Severity
}

// Matched reports whether any rule matched.
func (r Result) Matched() bool { return len(r.Matches) > 0 }

// Block reports whether a matching rule has `verdict: block`.
func (r Result) Block() bool {
	for _, m := range r.Matches {
		if m.Block {
			return true
		}
	}
	return false
}

// Classify evaluates every rule against every change and returns one Result
// per change that belongs in the review, in plan order.
//
// Data sources are always excluded. No-op changes are excluded unless a
// rule matches them, which is how the default rules report pure moves.
// Everything else is kept, including changes no rule matched and changes
// with Unknown actions.
func Classify(changes []plan.Change, set *rules.Set) []Result {
	var out []Result
	for _, c := range changes {
		if c.Mode == "data" {
			continue
		}
		res := Result{Change: c}
		for _, r := range set.Rules {
			ok, detail := r.Match(c)
			if !ok {
				continue
			}
			res.Matches = append(res.Matches, Match{
				RuleID: r.ID, Severity: r.Severity, Meaning: r.Meaning, Detail: detail, Block: r.Block,
			})
			if r.Severity > res.Severity {
				res.Severity = r.Severity
			}
		}
		if c.Action == plan.NoOp && !res.Matched() {
			continue
		}
		out = append(out, res)
	}
	return out
}
