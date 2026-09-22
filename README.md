# tfreview

`tfreview` reads the JSON form of a Terraform plan and reviews the changes in it. The goal is a ranked list of changes with a verdict for each one and for the plan as a whole, so the risky parts of a large plan stand out.

It is a standalone CLI. It does not wrap or extend the Terraform CLI. It reads `terraform show -json` output from a file or stdin.

## Status

Early. Plan parsing works, and the CLI lists the parsed changes. Rules, severity, verdicts, blast radius and the formatted output (terminal, markdown, json) are not built yet.

## Install

Requires Go 1.25 or later.

```bash
go install ./cmd/tfreview    # installs to ~/go/bin
```

## Usage

```bash
terraform plan -out=tfplan
terraform show -json tfplan | tfreview

tfreview --plan plan.json
```

Terraform does not support external subcommands, so `terraform review` is not possible. A shell function gives you a one-step workflow:

```bash
tfr() { terraform plan -out=tfplan "$@" && terraform show -json tfplan | tfreview; }
```

In CI, run with `set -o pipefail`. Otherwise a failing `terraform show` is masked, and `tfreview` only sees empty input.

### Current output

For now the output is a plain list of changes, with any warnings above it:

```
WARNING: aws_s3_bucket.logs: unrecognised actions ["create" "update"]; treated as unknown and flagged for attention
ADDRESS               ACTION                  REASON
aws_db_instance.main  replace                 replace_because_cannot_update
aws_s3_bucket.logs    unknown(create,update)  -
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Plan parsed |
| 1 | Plan is `errored` or `complete: false` (needs attention) |
| 3 | Input error: empty, unreadable or invalid plan JSON, or an unsupported `format_version` |
| 4 | Invalid flags or arguments |

Codes 1 and 2 will carry the `needs-attention` and `block` verdicts once classification exists. Code 5 is reserved for internal errors.

## How it reads plans

- **Supported input:** Terraform 1.x plan JSON (`format_version` 1.x). An unknown major version is rejected, not guessed at.
- **Unrecognised actions:** a change whose `actions` combination is not recognised is kept, marked `unknown`, and reported with a warning. A newer Terraform version degrades the review instead of breaking it.
- **Errored or partial plans:** an errored plan, or one with `complete: false`, is reported with a warning at the top of the output.
- **Diffs:** attribute diffs are flattened to dotted paths such as `ingress.0.cidr_blocks.0`. Values not known until apply show as `(known after apply)`.
- **Sensitive values:** these show as `(sensitive)`. The raw value never appears in output, and here the tool goes further than Terraform's own markers:
  - A path marked sensitive on either side of the diff is hidden on both sides.
  - A plain-text value that equals a sensitive value in the same change is also hidden. Terraform does not always mark copies. For example, `terraform_data.output` echoes a sensitive `input` without the sensitive marker.

## Development

```bash
go vet ./...
go test ./...
```

Tests do not use real work plans. Plan JSON for tests comes from `internal/planfix`, a builder for actions, before and after values, sensitivity markers, prior-state dependencies, nested modules and moved resources:

```go
p := planfix.New()
p.Resource("aws_db_instance.main", "delete", "create").
	Before(map[string]any{"password": "x"}).
	After(map[string]any{"password": "x"}).
	AfterSensitive(map[string]any{"password": true})
data := p.JSON()
```

### Layout

```
cmd/tfreview/       CLI: flags, input, exit codes
internal/plan/      plan JSON -> Change, Action, flattened Diff
internal/planfix/   plan JSON builder for tests
```

Planned: `internal/rules` and `internal/classify` (YAML rules plus Go predicates), `internal/graph` (blast radius from state and config dependencies), `internal/review` and `internal/render`.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
