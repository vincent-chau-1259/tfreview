# tfreview

`tfreview` reads the JSON form of a Terraform plan and reviews the changes in it. The goal is a ranked list of changes with a verdict for each one and for the plan as a whole, so the risky parts of a large plan stand out.

It is a standalone CLI. It does not wrap or extend the Terraform CLI. It reads `terraform show -json` output from a file or stdin.

## Status

Early. Plan parsing and rule-based classification work: each change gets a severity and the rules it matched. Verdicts, blast radius and the formatted output (terminal, markdown, json) are not built yet.

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
tfreview --plan plan.json --rules my-rules.yaml
```

Terraform does not support external subcommands, so `terraform review` is not possible. A shell function gives you a one-step workflow:

```bash
tfr() { terraform plan -out=tfplan "$@" && terraform show -json tfplan | tfreview; }
```

In CI, run with `set -o pipefail`. Otherwise a failing `terraform show` is masked, and `tfreview` only sees empty input.

### Current output

For now the output is a table of changes with their severity and matching rules. Warnings appear above it and rule details below it:

```
WARNING: aws_s3_bucket.logs: unrecognised actions ["create" "update"]; treated as unknown and flagged for attention
ADDRESS                 ACTION                  SEVERITY   RULES                                      REASON
aws_db_instance.main    replace                 high       stateful-destroy,backup-retention-reduced  replace_because_cannot_update
aws_security_group.web  update                  high       sg-ingress-widened                         -
aws_instance.app        update                  unmatched  -                                          -
aws_s3_bucket.logs      unknown(create,update)  unmatched  -                                          -

Details:
  aws_db_instance.main [backup-retention-reduced] backup_retention_period: 7 -> 1
  aws_security_group.web [sg-ingress-widened] new ingress: ingress.0: tcp port 22 from 0.0.0.0/0
```

Data sources are not listed, and neither are no-op changes unless a rule matches them (a pure `moved` is reported).

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Plan parsed |
| 1 | Plan is `errored` or `complete: false` (needs attention) |
| 3 | Input error: empty, unreadable or invalid plan JSON, or an unsupported `format_version` |
| 4 | Configuration error: invalid flags or arguments, or a rules file that cannot be read or is invalid |

Codes 1 and 2 will carry the `needs-attention` and `block` verdicts once verdicts are built. Code 5 is reserved for internal errors.

## Rules

Changes are classified by rules written in YAML. A default set is built in; `--rules <file>` replaces it. A rule selects changes by resource type, action or address (with `*` globs), and can call a Go predicate for checks YAML cannot express. A change takes the highest severity among the rules it matches.

```yaml
version: 1
unmatched:
  destructive: needs-attention   # delete, replace
  other: approve                 # create, update, forget

rules:
  - id: stateful-destroy
    when:
      type_matches: [aws_db_instance, aws_s3_bucket, aws_elasticache_*]
      action_in: [delete, replace]
    severity: high
    meaning: >
      Destroys stored data unless a final snapshot or backup is configured.
```

The default rules flag:
- **high:** stateful resources being destroyed or replaced; ingress widened to new sources; encryption disabled or a KMS key removed; a resource replaced despite a `moved` block.
- **medium:** deletion protection removed (or `force_destroy` turned on); backup retention reduced or final snapshots skipped; a sensitive value written; a resource removed from Terraform management (`forget`).
- **low:** pure moves and new resources.

Predicates available to rules: `widens_network_access`, `disables_encryption`, `removes_deletion_protection`, `reduces_backup_retention`, `changes_sensitive_attribute`, `was_moved`. See [docs/design.md](docs/design.md) for exact definitions.

## How it reads plans

- **Supported input:** Terraform 1.x plan JSON (`format_version` 1.x). An unknown major version is rejected, not guessed at.
- **Unrecognised actions:** a change whose `actions` combination is not recognised is kept, marked `unknown`, and reported with a warning. A newer Terraform version degrades the review instead of breaking it.
- **Errored or partial plans:** an errored plan, or one with `complete: false`, is reported with a warning at the top of the output.
- **Diffs:** attribute diffs are flattened to dotted paths such as `ingress.0.cidr_blocks.0`. Values not known until apply show as `(known after apply)`.
- **Sensitive values:** these show as `(sensitive)`. The raw value never appears in output, and predicates cannot read it. Here the tool goes further than Terraform's own markers:
  - A path marked sensitive on either side of the diff is hidden on both sides.
  - A plain-text value that equals a sensitive value in the same change is also hidden. Terraform does not always mark copies. For example, `terraform_data.output` echoes a sensitive `input` without the sensitive marker.

## Development

```bash
go vet ./...
go test ./...
```

Tests never use plans from real infrastructure. Plan JSON for tests comes from `internal/planfix`, a builder for actions, before and after values, sensitivity markers, prior-state dependencies, nested modules and moved resources:

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
cmd/tfreview/         CLI: flags, input, exit codes
internal/plan/        plan JSON -> Change, Action, flattened Diff
internal/planfix/     plan JSON builder for tests
internal/rules/       YAML rules -> compiled matchers; embedded default rules
internal/predicates/  Go predicates that rules call by name
internal/classify/    Change + rules -> severity and matched rules
```

Planned: `internal/graph` (blast radius from state and config dependencies), `internal/review` (verdicts) and `internal/render`.

The design, including exact rule and predicate definitions, is in [docs/design.md](docs/design.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
