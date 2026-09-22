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
	for _, want := range []string{
		"aws_db_instance.main  replace                 replace_because_cannot_update",
		"aws_s3_bucket.logs    unknown(create,update)  -",
		"WARNING: aws_s3_bucket.logs: unrecognised actions",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout missing %q:\n%s", want, stdout)
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
