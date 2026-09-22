package rules_test

import (
	"strings"
	"testing"

	"tfreview/internal/plan"
	"tfreview/internal/predicates"
	"tfreview/internal/rules"
)

func TestDefaultRulesLoad(t *testing.T) {
	set, err := rules.Default(predicates.Registry())
	if err != nil {
		t.Fatalf("default rules: %v", err)
	}
	if set.Unmatched.Destructive != rules.NeedsAttention || set.Unmatched.Other != rules.Approve {
		t.Errorf("unmatched = %+v", set.Unmatched)
	}
	want := map[string]rules.Severity{
		"stateful-destroy":            rules.High,
		"sg-ingress-widened":          rules.High,
		"encryption-disabled":         rules.High,
		"deletion-protection-removed": rules.Medium,
		"backup-retention-reduced":    rules.Medium,
		"sensitive-attribute-changed": rules.Medium,
		"moved-then-replaced":         rules.High,
		"moved":                       rules.Low,
		"removed-from-state":          rules.Medium,
		"new-resource":                rules.Low,
	}
	got := map[string]rules.Severity{}
	for _, r := range set.Rules {
		got[r.ID] = r.Severity
		if r.Meaning == "" {
			t.Errorf("rule %s has no meaning", r.ID)
		}
		if r.Block {
			t.Errorf("default rule %s blocks; no default rule should", r.ID)
		}
	}
	for id, sev := range want {
		if got[id] != sev {
			t.Errorf("rule %s severity = %v, want %v", id, got[id], sev)
		}
	}
	if len(got) != len(want) {
		t.Errorf("default rules = %v, want exactly %v", got, want)
	}
}

func load(body string) (*rules.Set, error) {
	return rules.Load(strings.NewReader(body), predicates.Registry())
}

func TestLoadErrors(t *testing.T) {
	const ok = "    when: {action_in: [create]}\n    severity: low\n"
	tests := []struct {
		name string
		body string
		want []string
	}{
		{"empty", "", []string{"empty"}},
		{"bad yaml", "version: [", []string{"invalid rules YAML"}},
		{"unknown field", "version: 1\nrulez: []\n", []string{"rulez"}},
		{"unknown when field", "version: 1\nrules:\n  - id: a\n    when: {type: [x]}\n    severity: low\n", []string{"type"}},
		{"missing version", "rules: []\n", []string{"unsupported rules version 0"}},
		{"version 2", "version: 2\n", []string{"unsupported rules version 2"}},
		{"missing id", "version: 1\nrules:\n  -\n" + ok, []string{"rule 1: missing id"}},
		{"duplicate id", "version: 1\nrules:\n  - id: a\n" + ok + "  - id: a\n" + ok, []string{`rule "a": duplicate id`}},
		{"bad severity", "version: 1\nrules:\n  - id: a\n    when: {action_in: [create]}\n    severity: critical\n", []string{`invalid severity "critical"`}},
		{"missing severity", "version: 1\nrules:\n  - id: a\n    when: {action_in: [create]}\n", []string{"missing severity"}},
		{"bad verdict", "version: 1\nrules:\n  - id: a\n    verdict: approve\n" + ok, []string{`only block may be set`}},
		{"bad action", "version: 1\nrules:\n  - id: a\n    when: {action_in: [destroy]}\n    severity: low\n", []string{`unknown action "destroy"`}},
		{"unknown not selectable", "version: 1\nrules:\n  - id: a\n    when: {action_in: [unknown]}\n    severity: low\n", []string{`unknown action "unknown"`}},
		{"empty when", "version: 1\nrules:\n  - id: a\n    severity: low\n", []string{"when must set"}},
		{"empty list", "version: 1\nrules:\n  - id: a\n    when: {type_matches: []}\n    severity: low\n", []string{"type_matches is empty"}},
		{"unknown predicate", "version: 1\nrules:\n  - id: a\n    when: {predicate: nope}\n    severity: low\n", []string{`unknown predicate "nope"`}},
		{"bad unmatched", "version: 1\nunmatched: {destructive: ignore}\n", []string{`unmatched.destructive: invalid verdict "ignore"`}},
		{
			"all errors reported",
			"version: 1\nrules:\n  - id: a\n    when: {predicate: nope}\n    severity: low\n  - id: b\n    when: {action_in: [x]}\n    severity: huge\n",
			[]string{`rule "a": unknown predicate`, `rule "b": action_in: unknown action "x"`, `rule "b": invalid severity "huge"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(tt.body)
			if err == nil {
				t.Fatal("expected an error")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not contain %q", err, w)
				}
			}
		})
	}
}

func TestLoadDefaultsAndBlock(t *testing.T) {
	set, err := load("version: 1\nunmatched: {other: needs-attention}\nrules:\n  - id: a\n    when: {address_matches: ['module.prod.*']}\n    severity: high\n    verdict: block\n")
	if err != nil {
		t.Fatal(err)
	}
	if set.Unmatched.Destructive != rules.NeedsAttention || set.Unmatched.Other != rules.NeedsAttention {
		t.Errorf("unmatched = %+v", set.Unmatched)
	}
	if !set.Rules[0].Block {
		t.Error("verdict: block not set")
	}
}

func TestRuleMatch(t *testing.T) {
	set, err := load(`version: 1
rules:
  - id: typed
    when: {type_matches: [aws_db_*, aws_s3_bucket]}
    severity: low
  - id: acted
    when: {action_in: [delete, replace]}
    severity: low
  - id: addressed
    when: {address_matches: ['aws_instance.web[*]']}
    severity: low
  - id: all-of
    when: {type_matches: [aws_db_instance], action_in: [replace], predicate: was_moved}
    severity: low
`)
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]*rules.Rule{}
	for _, r := range set.Rules {
		byID[r.ID] = r
	}
	tests := []struct {
		rule string
		c    plan.Change
		want bool
	}{
		{"typed", plan.Change{Type: "aws_db_instance"}, true},
		{"typed", plan.Change{Type: "aws_s3_bucket"}, true},
		{"typed", plan.Change{Type: "aws_s3_bucket_policy"}, false},
		{"acted", plan.Change{Action: plan.Replace}, true},
		{"acted", plan.Change{Action: plan.Update}, false},
		{"acted", plan.Change{Action: plan.Unknown}, false},
		{"addressed", plan.Change{Address: "aws_instance.web[0]"}, true},
		{"addressed", plan.Change{Address: `aws_instance.web["a"]`}, true},
		{"addressed", plan.Change{Address: "aws_instance.web"}, false},
		{"all-of", plan.Change{Type: "aws_db_instance", Action: plan.Replace, PreviousAddress: "x"}, true},
		{"all-of", plan.Change{Type: "aws_db_instance", Action: plan.Replace}, false},
		{"all-of", plan.Change{Type: "aws_db_instance", Action: plan.Update, PreviousAddress: "x"}, false},
	}
	for _, tt := range tests {
		got, _ := byID[tt.rule].Match(tt.c)
		if got != tt.want {
			t.Errorf("%s.Match(%+v) = %v, want %v", tt.rule, tt.c, got, tt.want)
		}
	}
}

func TestGlob(t *testing.T) {
	tests := []struct {
		pattern, s string
		want       bool
	}{
		{"aws_s3_bucket", "aws_s3_bucket", true},
		{"aws_s3_bucket", "aws_s3_bucket_policy", false},
		{"aws_elasticache_*", "aws_elasticache_cluster", true},
		{"aws_elasticache_*", "aws_elasticache_", true},
		{"aws_elasticache_*", "aws_elasticach", false},
		{"*", "", true},
		{"*_policy", "aws_iam_policy", true},
		{"*_policy", "aws_iam_policy_attachment", false},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "ac", false},
		{"a*b*b", "ab", false},
		{"a*b*b", "abb", true},
		{"module.*.aws_db_instance.*", "module.db.aws_db_instance.main", true},
		{"aws_instance.web[*]", "aws_instance.web[0]", true},
		{"aws_instance.web[0]", "aws_instance.web0", false},
	}
	for _, tt := range tests {
		if got := rules.Glob(tt.pattern, tt.s); got != tt.want {
			t.Errorf("Glob(%q, %q) = %v, want %v", tt.pattern, tt.s, got, tt.want)
		}
	}
}
