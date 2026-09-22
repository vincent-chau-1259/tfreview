package plan_test

import (
	"fmt"
	"strings"
	"testing"

	"tfreview/internal/plan"
	"tfreview/internal/planfix"
)

// row is a compact expected DiffEntry: path, before, after, changed.
type row struct {
	path, before, after string
	changed             bool
}

func diffRows(c plan.Change) []row {
	var out []row
	for _, e := range c.Diff() {
		out = append(out, row{e.Path, e.Before, e.After, e.Changed})
	}
	return out
}

func assertRows(t *testing.T, got, want []row) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("diff mismatch\n got: %v\nwant: %v", got, want)
	}
}

func singleChange(t *testing.T, fix *planfix.Plan) plan.Change {
	t.Helper()
	p := parse(t, fix)
	if len(p.Changes) != 1 {
		t.Fatalf("got %d changes, want 1", len(p.Changes))
	}
	return p.Changes[0]
}

func TestDiffFlatten(t *testing.T) {
	tests := []struct {
		name string
		fix  func(*planfix.Plan)
		want []row
	}{
		{
			name: "nested blocks and lists",
			fix: func(p *planfix.Plan) {
				p.Resource("aws_security_group.web", "update").
					Before(map[string]any{
						"name": "web",
						"ingress": []any{
							map[string]any{"from_port": 443, "cidr_blocks": []any{"10.0.0.0/8"}},
						},
					}).
					After(map[string]any{
						"name": "web",
						"ingress": []any{
							map[string]any{"from_port": 443, "cidr_blocks": []any{"10.0.0.0/8", "0.0.0.0/0"}},
						},
					})
			},
			want: []row{
				{"ingress.0.cidr_blocks.0", `"10.0.0.0/8"`, `"10.0.0.0/8"`, false},
				{"ingress.0.cidr_blocks.1", "", `"0.0.0.0/0"`, true},
				{"ingress.0.from_port", "443", "443", false},
				{"name", `"web"`, `"web"`, false},
			},
		},
		{
			name: "create has no before",
			fix: func(p *planfix.Plan) {
				p.Resource("terraform_data.x").After(map[string]any{"input": "a", "enabled": true, "n": nil})
			},
			want: []row{
				{"enabled", "", "true", true},
				{"input", "", `"a"`, true},
				{"n", "", "null", true},
			},
		},
		{
			name: "delete has no after",
			fix: func(p *planfix.Plan) {
				p.Resource("terraform_data.x", "delete").Before(map[string]any{"input": "a"})
			},
			want: []row{{"input", `"a"`, "", true}},
		},
		{
			name: "empty containers are leaves",
			fix: func(p *planfix.Plan) {
				p.Resource("aws_instance.x", "update").
					Before(map[string]any{"tags": map[string]any{"env": "prod"}, "sgs": []any{}}).
					After(map[string]any{"tags": map[string]any{}, "sgs": []any{"sg-1"}})
			},
			want: []row{
				{"sgs", "[]", "", true},
				{"sgs.0", "", `"sg-1"`, true},
				{"tags", "", "{}", true},
				{"tags.env", `"prod"`, "", true},
			},
		},
		{
			name: "list indices sort numerically",
			fix: func(p *planfix.Plan) {
				l := make([]any, 11)
				for i := range l {
					l[i] = i
				}
				p.Resource("terraform_data.x").After(map[string]any{"l": l[9:]})
			},
			want: []row{
				{"l.0", "", "9", true},
				{"l.1", "", "10", true},
			},
		},
		{
			name: "large numbers keep precision",
			fix: func(p *planfix.Plan) {
				p.Resource("terraform_data.x").After(map[string]any{"n": int64(9007199254740993)})
			},
			want: []row{{"n", "", "9007199254740993", true}},
		},
		{
			name: "known after apply: absent, null, nested and whole block",
			fix: func(p *planfix.Plan) {
				p.Resource("aws_instance.x", "update").
					Before(map[string]any{"id": "i-1", "arn": "arn:1", "name": "a", "ebs": []any{map[string]any{"size": 8}}}).
					After(map[string]any{"arn": nil, "name": "a", "ebs": []any{map[string]any{"size": 8}}}).
					AfterUnknown(map[string]any{
						"id":        true,
						"arn":       true,
						"ebs":       []any{map[string]any{"volume_id": true}},
						"network":   true,
						"tags_all":  map[string]any{},
						"public_ip": false,
					})
			},
			want: []row{
				{"arn", `"arn:1"`, plan.KnownAfterApply, true},
				{"ebs.0.size", "8", "8", false},
				{"ebs.0.volume_id", "", plan.KnownAfterApply, true},
				{"id", `"i-1"`, plan.KnownAfterApply, true},
				{"name", `"a"`, `"a"`, false},
				{"network", "", plan.KnownAfterApply, true},
				{"public_ip", "", "null", true},
				{"tags_all", "", "null", true},
			},
		},
		{
			name: "after_unknown root literal true",
			fix: func(p *planfix.Plan) {
				p.Resource("terraform_data.x").AfterUnknown(true)
			},
			want: []row{{"", "", plan.KnownAfterApply, true}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fix := planfix.New()
			tt.fix(fix)
			assertRows(t, diffRows(singleChange(t, fix)), tt.want)
		})
	}
}

func TestDiffSensitivity(t *testing.T) {
	const secret = "hunter2-SECRET"
	const secret2 = "correct-horse-SECRET"
	tests := []struct {
		name string
		fix  func(*planfix.Plan)
		want []row
		// sensitive lists paths whose entry must report Sensitive().
		sensitive []string
	}{
		{
			name: "sensitive leaf changed on update",
			fix: func(p *planfix.Plan) {
				p.Resource("aws_db_instance.main", "update").
					Before(map[string]any{"password": secret, "size": "small"}).
					After(map[string]any{"password": secret2, "size": "small"}).
					BeforeSensitive(map[string]any{"password": true}).
					AfterSensitive(map[string]any{"password": true})
			},
			want: []row{
				{"password", plan.SensitiveValue, plan.SensitiveValue, true},
				{"size", `"small"`, `"small"`, false},
			},
			sensitive: []string{"password"},
		},
		{
			name: "sensitive leaf unchanged on update",
			fix: func(p *planfix.Plan) {
				p.Resource("aws_db_instance.main", "update").
					Before(map[string]any{"password": secret, "size": "small"}).
					After(map[string]any{"password": secret, "size": "large"}).
					BeforeSensitive(map[string]any{"password": true}).
					AfterSensitive(map[string]any{"password": true})
			},
			want: []row{
				{"password", plan.SensitiveValue, plan.SensitiveValue, false},
				{"size", `"small"`, `"large"`, true},
			},
			sensitive: []string{"password"},
		},
		{
			name: "sensitive only on one side",
			fix: func(p *planfix.Plan) {
				p.Resource("aws_ssm_parameter.p", "update").
					Before(map[string]any{"value": secret}).
					After(map[string]any{"value": secret2}).
					AfterSensitive(map[string]any{"value": true})
			},
			// Terraform shows both sides masked when either is sensitive.
			want:      []row{{"value", plan.SensitiveValue, plan.SensitiveValue, true}},
			sensitive: []string{"value"},
		},
		{
			name: "nested sensitive path inside a block",
			fix: func(p *planfix.Plan) {
				p.Resource("aws_instance.x", "update").
					Before(map[string]any{"cfg": []any{map[string]any{"token": secret, "port": 1}}}).
					After(map[string]any{"cfg": []any{map[string]any{"token": secret2, "port": 1}}}).
					BeforeSensitive(map[string]any{"cfg": []any{map[string]any{"token": true}}}).
					AfterSensitive(map[string]any{"cfg": []any{map[string]any{"token": true}}})
			},
			want: []row{
				{"cfg.0.port", "1", "1", false},
				{"cfg.0.token", plan.SensitiveValue, plan.SensitiveValue, true},
			},
			sensitive: []string{"cfg.0.token"},
		},
		{
			name: "sensitive whole block masks every leaf beneath",
			fix: func(p *planfix.Plan) {
				p.Resource("aws_instance.x", "create").
					After(map[string]any{"cfg": map[string]any{"a": secret, "b": []any{secret2}}, "name": "n"}).
					AfterSensitive(map[string]any{"cfg": true})
			},
			want: []row{
				{"cfg.a", "", plan.SensitiveValue, true},
				{"cfg.b.0", "", plan.SensitiveValue, true},
				{"name", "", `"n"`, true},
			},
			sensitive: []string{"cfg.a", "cfg.b.0"},
		},
		{
			name: "after_sensitive root literal true",
			fix: func(p *planfix.Plan) {
				p.Resource("aws_db_instance.main", "delete", "create").
					Before(map[string]any{"password": secret, "id": "db-1"}).
					After(map[string]any{"password": secret, "id": "db-1"}).
					BeforeSensitive(true).
					AfterSensitive(true)
			},
			want: []row{
				{"id", plan.SensitiveValue, plan.SensitiveValue, false},
				{"password", plan.SensitiveValue, plan.SensitiveValue, false},
			},
			sensitive: []string{"id", "password"},
		},
		{
			name: "sensitive wins over unknown",
			fix: func(p *planfix.Plan) {
				p.Resource("aws_db_instance.main").
					After(map[string]any{}).
					AfterUnknown(map[string]any{"password": true}).
					AfterSensitive(map[string]any{"password": true})
			},
			want:      []row{{"password", "", plan.SensitiveValue, true}},
			sensitive: []string{"password"},
		},
		{
			// Seen in real Terraform 1.15.4 output: terraform_data.output
			// copies a sensitive input but is not marked sensitive itself.
			name: "unmarked echo of a sensitive value",
			fix: func(p *planfix.Plan) {
				p.Resource("terraform_data.b", "update").
					Before(map[string]any{"input": secret, "output": secret, "id": "x"}).
					After(map[string]any{"input": secret2, "id": "x"}).
					AfterUnknown(map[string]any{"output": true}).
					BeforeSensitive(map[string]any{"input": true}).
					AfterSensitive(map[string]any{"input": true})
			},
			want: []row{
				{"id", `"x"`, `"x"`, false},
				{"input", plan.SensitiveValue, plan.SensitiveValue, true},
				{"output", plan.SensitiveValue, plan.KnownAfterApply, true},
			},
		},
		{
			name: "sensitive null",
			fix: func(p *planfix.Plan) {
				p.Resource("aws_db_instance.main", "update").
					Before(map[string]any{"password": nil}).
					After(map[string]any{"password": nil}).
					AfterSensitive(map[string]any{"password": true})
			},
			want:      []row{{"password", plan.SensitiveValue, plan.SensitiveValue, false}},
			sensitive: []string{"password"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fix := planfix.New()
			tt.fix(fix)
			c := singleChange(t, fix)
			entries := c.Diff()
			assertRows(t, diffRows(c), tt.want)

			wantSensitive := map[string]bool{}
			for _, p := range tt.sensitive {
				wantSensitive[p] = true
			}
			for _, e := range entries {
				if tt.sensitive != nil && e.Sensitive() != wantSensitive[e.Path] {
					t.Errorf("%s: Sensitive() = %v, want %v", e.Path, e.Sensitive(), wantSensitive[e.Path])
				}
				// No part of an entry may contain a secret, whichever side was marked.
				if s := fmt.Sprintf("%+v", e); strings.Contains(s, secret) || strings.Contains(s, secret2) {
					t.Errorf("%s: entry leaks a sensitive value: %s", e.Path, s)
				}
			}
		})
	}
}
