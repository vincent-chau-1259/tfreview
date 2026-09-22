package plan_test

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	"tfreview/internal/plan"
	"tfreview/internal/planfix"
)

func parse(t *testing.T, p *planfix.Plan) *plan.Plan {
	t.Helper()
	got, err := plan.Parse(bytes.NewReader(p.JSON()))
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, p)
	}
	return got
}

func TestParseEmpty(t *testing.T) {
	for _, in := range []string{"", "  \n\t"} {
		if _, err := plan.Parse(strings.NewReader(in)); !errors.Is(err, plan.ErrEmptyInput) {
			t.Errorf("Parse(%q) error = %v, want ErrEmptyInput", in, err)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	for _, in := range []string{"not json", `{"format_version":`, `[]`, `{}`} {
		if _, err := plan.Parse(strings.NewReader(in)); err == nil || errors.Is(err, plan.ErrEmptyInput) {
			t.Errorf("Parse(%q) error = %v, want invalid plan error", in, err)
		}
	}
}

func TestParseTrailingData(t *testing.T) {
	doc := planfix.New().String()
	for _, in := range []string{doc + doc, doc + "\nlog: done\n", doc + "}", doc + " 1"} {
		_, err := plan.Parse(strings.NewReader(in))
		if err == nil || !strings.Contains(err.Error(), "unexpected data after the plan document") {
			t.Errorf("Parse(plan + %q) error = %v, want trailing data error", in[len(doc):], err)
		}
	}
	if _, err := plan.Parse(strings.NewReader(doc + "\n \t\n")); err != nil {
		t.Errorf("trailing whitespace should be accepted: %v", err)
	}
}

func TestParseFormatVersion(t *testing.T) {
	tests := []struct {
		version string
		ok      bool
	}{
		{"1.0", true},
		{"1.2", true},
		{"1.99", true},
		{"0.2", false},
		{"2.0", false},
		{"10.0", false},
	}
	for _, tt := range tests {
		_, err := plan.Parse(bytes.NewReader(planfix.New().FormatVersion(tt.version).JSON()))
		if (err == nil) != tt.ok {
			t.Errorf("format_version %q: err = %v, want ok=%v", tt.version, err, tt.ok)
		}
		if err != nil && !strings.Contains(err.Error(), tt.version) {
			t.Errorf("format_version %q: error %q does not name the version", tt.version, err)
		}
	}
}

func TestParseErroredAndComplete(t *testing.T) {
	tests := []struct {
		name         string
		fix          *planfix.Plan
		errored      bool
		wantComplete bool
	}{
		{"defaults", planfix.New(), false, true},
		{"errored", planfix.New().Errored(), true, true},
		{"complete false", planfix.New().Complete(false), false, false},
		{"complete true", planfix.New().Complete(true), false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := parse(t, tt.fix)
			if p.Errored != tt.errored || p.Complete != tt.wantComplete {
				t.Errorf("Errored=%v Complete=%v, want %v %v", p.Errored, p.Complete, tt.errored, tt.wantComplete)
			}
		})
	}
}

func TestParseChangeFields(t *testing.T) {
	fix := planfix.New()
	fix.Resource(`module.net["a"].module.sg.aws_security_group.web[0]`, "create", "delete").
		ActionReason("replace_because_cannot_update").
		ReplacePaths([]any{"ingress", 0, "cidr_blocks"}).
		Before(map[string]any{"name": "web"}).
		After(map[string]any{"name": "web2"})
	fix.Resource(`aws_db_instance.main`, "no-op").MovedFrom("aws_db_instance.old").
		Before(map[string]any{}).After(map[string]any{})
	fix.Resource(`data.aws_ami.ubuntu["x"]`, "read")
	fix.Resource(`terraform_data.gone`, "forget").Before(map[string]any{})

	p := parse(t, fix)
	if len(p.Changes) != 4 {
		t.Fatalf("got %d changes, want 4", len(p.Changes))
	}
	sg := p.Changes[0]
	if sg.Address != `module.net["a"].module.sg.aws_security_group.web[0]` ||
		sg.ModuleAddress != `module.net["a"].module.sg` ||
		sg.Mode != "managed" || sg.Type != "aws_security_group" || sg.Name != "web" ||
		sg.Index != 0 || sg.ProviderName != "registry.terraform.io/hashicorp/aws" {
		t.Errorf("identity fields wrong: %+v", sg)
	}
	if sg.Action != plan.Replace || !sg.CreateBeforeDestroy {
		t.Errorf("action = %v cbd=%v, want replace cbd", sg.Action, sg.CreateBeforeDestroy)
	}
	if sg.ActionReason != "replace_because_cannot_update" {
		t.Errorf("ActionReason = %q", sg.ActionReason)
	}
	if want := [][]any{{"ingress", 0, "cidr_blocks"}}; !reflect.DeepEqual(sg.ReplacePaths, want) {
		t.Errorf("ReplacePaths = %#v, want %#v", sg.ReplacePaths, want)
	}

	moved := p.Changes[1]
	if moved.Action != plan.NoOp || moved.PreviousAddress != "aws_db_instance.old" {
		t.Errorf("moved: action %v previous %q", moved.Action, moved.PreviousAddress)
	}
	ds := p.Changes[2]
	if ds.Mode != "data" || ds.Action != plan.Read || ds.Index != "x" {
		t.Errorf("data source: %+v", ds)
	}
	if p.Changes[3].Action != plan.Forget {
		t.Errorf("forget: %v", p.Changes[3].Action)
	}
	if len(p.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", p.Warnings)
	}
}

func TestParseUnknownActionWarns(t *testing.T) {
	fix := planfix.New()
	fix.Resource("aws_s3_bucket.logs", "create", "update")
	fix.Resource("aws_s3_bucket.ok", "create")

	p := parse(t, fix)
	if len(p.Changes) != 2 {
		t.Fatalf("unknown-action change must be kept; got %d changes", len(p.Changes))
	}
	c := p.Changes[0]
	if c.Action != plan.Unknown || !reflect.DeepEqual(c.RawActions, []string{"create", "update"}) {
		t.Errorf("action = %v raw = %v", c.Action, c.RawActions)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "aws_s3_bucket.logs") {
		t.Errorf("warnings = %v, want one naming aws_s3_bucket.logs", p.Warnings)
	}
}
