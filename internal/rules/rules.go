// Package rules loads YAML rules into compiled matchers.
//
// YAML selects which changes a rule applies to; registered Go predicates
// judge anything YAML cannot express.
package rules

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"tfreview/internal/plan"
)

//go:embed default.yaml
var defaultYAML []byte

// Severity of a matched rule. None means no rule matched.
type Severity int

const (
	None Severity = iota
	Low
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	}
	return "none"
}

// Verdict is a review outcome, as configured in the unmatched block or by
// `verdict: block` on a rule.
type Verdict string

const (
	Approve        Verdict = "approve"
	NeedsAttention Verdict = "needs-attention"
	Block          Verdict = "block"
)

// Predicate judges a change that a rule's selectors already matched. The
// detail names paths, never sensitive values.
type Predicate func(c plan.Change) (matched bool, detail string)

// Registry maps predicate names used in rules files to implementations.
type Registry map[string]Predicate

// Set is a loaded rules file.
type Set struct {
	Unmatched Unmatched
	Rules     []*Rule
}

// Unmatched configures verdicts for changes no rule matched. Unknown
// actions are always needs-attention and are not configurable.
type Unmatched struct {
	Destructive Verdict // delete, replace
	Other       Verdict // create, update, forget, ...
}

// Rule is a compiled rule.
type Rule struct {
	ID       string
	Severity Severity
	Meaning  string
	Block    bool // verdict: block

	types         []string
	actions       map[plan.Action]bool
	addresses     []string
	predicateName string
	predicate     Predicate
}

// PredicateName returns the rule's predicate, or "".
func (r *Rule) PredicateName() string { return r.predicateName }

// Match reports whether every selector in the rule's `when` matches c. The
// detail comes from the predicate, if any.
func (r *Rule) Match(c plan.Change) (bool, string) {
	if r.types != nil && !anyGlob(r.types, c.Type) {
		return false, ""
	}
	if r.actions != nil && !r.actions[c.Action] {
		return false, ""
	}
	if r.addresses != nil && !anyGlob(r.addresses, c.Address) {
		return false, ""
	}
	if r.predicate != nil {
		return r.predicate(c)
	}
	return true, ""
}

// Default loads the rules embedded in the binary.
func Default(reg Registry) (*Set, error) {
	return Load(bytes.NewReader(defaultYAML), reg)
}

type rawFile struct {
	Version   int           `yaml:"version"`
	Unmatched *rawUnmatched `yaml:"unmatched"`
	Rules     []rawRule     `yaml:"rules"`
}

type rawUnmatched struct {
	Destructive string `yaml:"destructive"`
	Other       string `yaml:"other"`
}

type rawRule struct {
	ID       string  `yaml:"id"`
	When     rawWhen `yaml:"when"`
	Severity string  `yaml:"severity"`
	Meaning  string  `yaml:"meaning"`
	Verdict  string  `yaml:"verdict"`
}

type rawWhen struct {
	TypeMatches    []string `yaml:"type_matches"`
	ActionIn       []string `yaml:"action_in"`
	AddressMatches []string `yaml:"address_matches"`
	Predicate      string   `yaml:"predicate"`
}

// Load parses and validates a rules file. All problems found are reported
// together. Unknown fields, unknown predicates, duplicate ids and invalid
// severities, actions, verdicts or globs are errors.
func Load(r io.Reader, reg Registry) (*Set, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)
	var raw rawFile
	if err := dec.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("rules file is empty")
		}
		return nil, fmt.Errorf("invalid rules YAML: %w", err)
	}
	if raw.Version != 1 {
		return nil, fmt.Errorf("unsupported rules version %d: want 1", raw.Version)
	}

	var errs []error
	set := &Set{Unmatched: Unmatched{Destructive: NeedsAttention, Other: Approve}}
	if u := raw.Unmatched; u != nil {
		if u.Destructive != "" {
			v, err := parseVerdict(u.Destructive)
			errs = appendErr(errs, "unmatched.destructive", err)
			set.Unmatched.Destructive = v
		}
		if u.Other != "" {
			v, err := parseVerdict(u.Other)
			errs = appendErr(errs, "unmatched.other", err)
			set.Unmatched.Other = v
		}
	}

	seen := map[string]bool{}
	for i, rr := range raw.Rules {
		where := fmt.Sprintf("rule %d", i+1)
		if rr.ID != "" {
			where = fmt.Sprintf("rule %q", rr.ID)
		}
		rule, ruleErrs := compile(rr, reg)
		if rr.ID != "" && seen[rr.ID] {
			ruleErrs = append(ruleErrs, errors.New("duplicate id"))
		}
		seen[rr.ID] = true
		for _, err := range ruleErrs {
			errs = append(errs, fmt.Errorf("%s: %w", where, err))
		}
		set.Rules = append(set.Rules, rule)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return set, nil
}

func compile(rr rawRule, reg Registry) (*Rule, []error) {
	var errs []error
	r := &Rule{ID: rr.ID, Meaning: strings.TrimSpace(rr.Meaning)}
	if rr.ID == "" {
		errs = append(errs, errors.New("missing id"))
	}

	switch rr.Severity {
	case "high":
		r.Severity = High
	case "medium":
		r.Severity = Medium
	case "low":
		r.Severity = Low
	case "":
		errs = append(errs, errors.New("missing severity"))
	default:
		errs = append(errs, fmt.Errorf("invalid severity %q: want high, medium or low", rr.Severity))
	}

	switch rr.Verdict {
	case "":
	case string(Block):
		r.Block = true
	default:
		errs = append(errs, fmt.Errorf("invalid verdict %q: only block may be set on a rule", rr.Verdict))
	}

	w := rr.When
	if w.TypeMatches == nil && w.ActionIn == nil && w.AddressMatches == nil && w.Predicate == "" {
		errs = append(errs, errors.New("when must set at least one of type_matches, action_in, address_matches, predicate"))
	}
	var err error
	if r.types, err = compileGlobs("type_matches", w.TypeMatches); err != nil {
		errs = append(errs, err)
	}
	if r.addresses, err = compileGlobs("address_matches", w.AddressMatches); err != nil {
		errs = append(errs, err)
	}
	if w.ActionIn != nil {
		if len(w.ActionIn) == 0 {
			errs = append(errs, errors.New("action_in is empty"))
		}
		r.actions = map[plan.Action]bool{}
		for _, name := range w.ActionIn {
			a, ok := parseAction(name)
			if !ok {
				errs = append(errs, fmt.Errorf("action_in: unknown action %q", name))
				continue
			}
			r.actions[a] = true
		}
	}
	if w.Predicate != "" {
		p, ok := reg[w.Predicate]
		if !ok {
			errs = append(errs, fmt.Errorf("unknown predicate %q", w.Predicate))
		}
		r.predicateName, r.predicate = w.Predicate, p
	}
	return r, errs
}

func compileGlobs(field string, globs []string) ([]string, error) {
	if globs == nil {
		return nil, nil
	}
	if len(globs) == 0 {
		return nil, fmt.Errorf("%s is empty", field)
	}
	for _, g := range globs {
		if g == "" {
			return nil, fmt.Errorf("%s: empty pattern", field)
		}
	}
	return globs, nil
}

// parseAction accepts the action names used in plan JSON plus "replace".
// Unknown is deliberately not selectable: it is always needs-attention.
func parseAction(name string) (plan.Action, bool) {
	for a := plan.NoOp; a <= plan.Forget; a++ {
		if a.String() == name {
			return a, true
		}
	}
	return 0, false
}

func parseVerdict(s string) (Verdict, error) {
	switch v := Verdict(s); v {
	case Approve, NeedsAttention, Block:
		return v, nil
	}
	return "", fmt.Errorf("invalid verdict %q: want approve, needs-attention or block", s)
}

func appendErr(errs []error, where string, err error) []error {
	if err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", where, err))
	}
	return errs
}

func anyGlob(patterns []string, s string) bool {
	for _, p := range patterns {
		if Glob(p, s) {
			return true
		}
	}
	return false
}

// Glob matches s against pattern, where * matches any run of characters
// and everything else is literal. Unlike path.Match, brackets are literal,
// so address patterns like `aws_instance.web[*]` work as written.
func Glob(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	last := parts[len(parts)-1]
	for _, mid := range parts[1 : len(parts)-1] {
		i := strings.Index(s, mid)
		if i < 0 {
			return false
		}
		s = s[i+len(mid):]
	}
	return len(s) >= len(last) && strings.HasSuffix(s, last)
}
