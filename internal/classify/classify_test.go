package classify_test

import (
	"bytes"
	"strings"
	"testing"

	"tfreview/internal/classify"
	"tfreview/internal/plan"
	"tfreview/internal/planfix"
	"tfreview/internal/predicates"
	"tfreview/internal/rules"
)

func classifyFix(t *testing.T, set *rules.Set, fix *planfix.Plan) map[string]classify.Result {
	t.Helper()
	p, err := plan.Parse(bytes.NewReader(fix.JSON()))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]classify.Result{}
	for _, r := range classify.Classify(p.Changes, set) {
		out[r.Change.Address] = r
	}
	return out
}

func ids(r classify.Result) string {
	var out []string
	for _, m := range r.Matches {
		out = append(out, m.RuleID)
	}
	return strings.Join(out, ",")
}

func TestClassifyDefaultRules(t *testing.T) {
	set, err := rules.Default(predicates.Registry())
	if err != nil {
		t.Fatal(err)
	}
	fix := planfix.New()
	fix.Resource("aws_db_instance.main", "delete", "create").
		Before(map[string]any{"password": "p-SECRET", "backup_retention_period": 7}).
		After(map[string]any{"password": "p-SECRET", "backup_retention_period": 1}).
		BeforeSensitive(map[string]any{"password": true}).
		AfterSensitive(map[string]any{"password": true})
	fix.Resource("aws_db_instance.renamed", "delete", "create").MovedFrom("aws_db_instance.old").
		Before(map[string]any{}).After(map[string]any{})
	fix.Resource("aws_instance.moved", "no-op").MovedFrom("aws_instance.was").
		Before(map[string]any{}).After(map[string]any{})
	fix.Resource("aws_instance.same", "no-op").Before(map[string]any{}).After(map[string]any{})
	fix.Resource("data.aws_ami.u", "read")
	fix.Resource("aws_instance.web", "update").Before(map[string]any{"ami": "a"}).After(map[string]any{"ami": "b"})
	fix.Resource("aws_instance.old", "delete").Before(map[string]any{})
	fix.Resource("aws_iam_role.r", "create").After(map[string]any{})
	fix.Resource("terraform_data.gone", "forget").Before(map[string]any{})
	fix.Resource("aws_s3_bucket.logs", "create", "update")

	got := classifyFix(t, set, fix)
	tests := []struct {
		addr     string
		severity rules.Severity
		ids      string
	}{
		{"aws_db_instance.main", rules.High, "stateful-destroy,backup-retention-reduced,sensitive-attribute-changed"},
		{"aws_db_instance.renamed", rules.High, "stateful-destroy,moved-then-replaced"},
		{"aws_instance.moved", rules.Low, "moved"},
		{"aws_instance.web", rules.None, ""},
		{"aws_instance.old", rules.None, ""},
		{"aws_iam_role.r", rules.Low, "new-resource"},
		{"terraform_data.gone", rules.Medium, "removed-from-state"},
		{"aws_s3_bucket.logs", rules.None, ""},
	}
	for _, tt := range tests {
		r, ok := got[tt.addr]
		if !ok {
			t.Errorf("%s missing from results", tt.addr)
			continue
		}
		if r.Severity != tt.severity || ids(r) != tt.ids {
			t.Errorf("%s: severity %v rules %q, want %v %q", tt.addr, r.Severity, ids(r), tt.severity, tt.ids)
		}
		if r.Matched() != (tt.ids != "") {
			t.Errorf("%s: Matched() = %v", tt.addr, r.Matched())
		}
	}
	for _, excluded := range []string{"aws_instance.same", "data.aws_ami.u"} {
		if _, ok := got[excluded]; ok {
			t.Errorf("%s should be excluded", excluded)
		}
	}
	if len(got) != len(tests) {
		t.Errorf("got %d results, want %d", len(got), len(tests))
	}

	// Details are recorded per match and never carry sensitive values.
	for _, r := range got {
		for _, m := range r.Matches {
			if strings.Contains(m.Detail, "SECRET") {
				t.Errorf("%s [%s] detail leaks a sensitive value: %q", r.Change.Address, m.RuleID, m.Detail)
			}
		}
	}
	main := got["aws_db_instance.main"]
	if d := main.Matches[1].Detail; d != "backup_retention_period: 7 -> 1" {
		t.Errorf("backup detail = %q", d)
	}
}

func TestClassifyOrderAndBlock(t *testing.T) {
	set, err := rules.Load(strings.NewReader(`version: 1
rules:
  - id: low-any
    when: {type_matches: ['*']}
    severity: low
  - id: prod-block
    when: {address_matches: ['module.prod.*']}
    severity: medium
    verdict: block
`), predicates.Registry())
	if err != nil {
		t.Fatal(err)
	}
	fix := planfix.New()
	fix.Resource("module.prod.aws_instance.a", "update").Before(map[string]any{}).After(map[string]any{"x": 1})
	fix.Resource("aws_instance.b", "update").Before(map[string]any{}).After(map[string]any{"x": 1})

	p, _ := plan.Parse(bytes.NewReader(fix.JSON()))
	res := classify.Classify(p.Changes, set)
	if len(res) != 2 || res[0].Change.Address != "module.prod.aws_instance.a" {
		t.Fatalf("results not in plan order: %+v", res)
	}
	if !res[0].Block() || res[0].Severity != rules.Medium {
		t.Errorf("prod: block %v severity %v", res[0].Block(), res[0].Severity)
	}
	if res[1].Block() || res[1].Severity != rules.Low {
		t.Errorf("b: block %v severity %v", res[1].Block(), res[1].Severity)
	}
}
