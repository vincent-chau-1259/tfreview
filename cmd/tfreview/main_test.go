package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tfreview/internal/planfix"
)

func runCLI(t *testing.T, args []string, stdin string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(args, strings.NewReader(stdin), &out, &errOut, false)
	return code, out.String(), errOut.String()
}

func TestEmptyStdin(t *testing.T) {
	code, stdout, stderr := runCLI(t, nil, "")
	if code != exitInputError {
		t.Errorf("exit = %d, want %d", code, exitInputError)
	}
	if want := "no plan JSON on stdin; did the upstream command fail?"; !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want it to contain %q", stderr, want)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
}

func TestErroredPlan(t *testing.T) {
	fix := planfix.New().Errored()
	fix.Resource("terraform_data.a", "create")

	code, stdout, _ := runCLI(t, nil, fix.String())
	if code != exitNeedsAttention {
		t.Errorf("exit = %d, want %d", code, exitNeedsAttention)
	}
	if !strings.HasPrefix(stdout, "WARNING: plan errored") {
		t.Errorf("stdout should lead with the errored warning, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "terraform_data.a") {
		t.Errorf("changes still listed for an errored plan, got:\n%s", stdout)
	}
}

func TestPlanFileListsChanges(t *testing.T) {
	fix := planfix.New()
	fix.Resource("aws_db_instance.main", "delete", "create").
		ActionReason("replace_because_cannot_update").
		Before(map[string]any{}).After(map[string]any{})
	fix.Resource("aws_s3_bucket.logs", "create", "update")
	path := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(path, fix.JSON(), 0o600); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runCLI(t, []string{"--plan", path}, "")
	if code != exitApprove {
		t.Errorf("exit = %d, want %d (stderr %q)", code, exitApprove, stderr)
	}
	rows := tableRows(stdout)
	for addr, want := range map[string][]string{
		"aws_db_instance.main": {"replace", "high", "stateful-destroy", "replace_because_cannot_update"},
		"aws_s3_bucket.logs":   {"unknown(create,update)", "unmatched", "-", "-"},
	} {
		if got := rows[addr]; strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("row %s = %v, want %v", addr, got, want)
		}
	}
	if !strings.Contains(stdout, "WARNING: aws_s3_bucket.logs: unrecognised actions") {
		t.Errorf("missing unknown-action warning:\n%s", stdout)
	}
}

// tableRows maps each table row's address to its remaining columns.
func tableRows(out string) map[string][]string {
	rows := map[string][]string{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 5 && f[0] != "ADDRESS" {
			rows[f[0]] = f[1:]
		}
	}
	return rows
}

func TestDetailsAndExclusions(t *testing.T) {
	fix := planfix.New()
	fix.Resource("aws_db_instance.main", "update").
		Before(map[string]any{"backup_retention_period": 7}).
		After(map[string]any{"backup_retention_period": 0})
	fix.Resource("data.aws_ami.u", "read")
	fix.Resource("aws_instance.same", "no-op").Before(map[string]any{}).After(map[string]any{})

	code, stdout, stderr := runCLI(t, nil, fix.String())
	if code != exitApprove {
		t.Fatalf("exit = %d, stderr %q", code, stderr)
	}
	if got := tableRows(stdout)["aws_db_instance.main"]; len(got) < 2 || got[1] != "medium" {
		t.Errorf("row = %v, want medium", got)
	}
	for _, want := range []string{
		"aws_db_instance.main [backup-retention-reduced] backup_retention_period: 7 -> 0 (backups disabled)",
		"2 change(s) not shown",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
		}
	}
	if _, ok := tableRows(stdout)["aws_instance.same"]; ok {
		t.Error("no-op change without a matching rule should not be listed")
	}
}

func TestRulesFlag(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	custom := write("ok.yaml", "version: 1\nrules:\n  - id: any-create\n    when: {action_in: [create]}\n    severity: high\n")
	bad := write("bad.yaml", "version: 1\nrules:\n  - id: x\n    when: {predicate: no_such_thing}\n    severity: high\n")

	fix := planfix.New()
	fix.Resource("terraform_data.a")

	code, stdout, _ := runCLI(t, []string{"--rules", custom}, fix.String())
	if code != exitApprove || tableRows(stdout)["terraform_data.a"][1] != "high" {
		t.Errorf("custom rules: exit %d\n%s", code, stdout)
	}

	for _, tt := range []struct{ path, want string }{
		{bad, `unknown predicate "no_such_thing"`},
		{filepath.Join(dir, "missing.yaml"), "no such file"},
	} {
		code, _, stderr := runCLI(t, []string{"--rules", tt.path}, fix.String())
		if code != exitConfigError || !strings.Contains(stderr, tt.want) {
			t.Errorf("--rules %s: exit %d stderr %q; want %d containing %q", tt.path, code, stderr, exitConfigError, tt.want)
		}
	}
}

func TestInputErrors(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		stdin string
		want  string
	}{
		{"invalid json", nil, "{", "invalid plan JSON"},
		{"unsupported format", nil, planfix.New().FormatVersion("2.0").String(), `unsupported plan format_version "2.0"`},
		{"missing file", []string{"--plan", filepath.Join(t.TempDir(), "nope.json")}, "", "no such file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := runCLI(t, tt.args, tt.stdin)
			if code != exitInputError || !strings.Contains(stderr, tt.want) {
				t.Errorf("exit = %d stderr = %q; want %d containing %q", code, stderr, exitInputError, tt.want)
			}
		})
	}
}
