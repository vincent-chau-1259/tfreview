# tfreview design

This document describes how `tfreview` works and why it is built the way it is. Read it before changing behaviour, adding rules or predicates, or starting work on a component that does not exist yet.

Status markers:
- **Implemented**: in the codebase and covered by tests.
- **Planned**: designed here, not yet built. Contributions should follow the design, or propose a change to it first.

## 1. Purpose and principles

`tfreview` is a standalone CLI. It reads `terraform show -json` output and produces a ranked review of the changes in the plan, with a verdict for each change and for the plan as a whole. It does not extend or wrap the Terraform CLI; it consumes Terraform's JSON output from a file or stdin.

The design rests on a few principles. Changes that break one of them need a strong reason.

- **Deterministic first.** The rule-based review is useful on its own and ships without any LLM component. An optional LLM layer (section 8) sits on top. No deterministic component may depend on it.
- **Never leak sensitive values.** Values Terraform marks as sensitive are never rendered, logged or passed to predicates as output. Section 4 describes how this is enforced, including cases where Terraform's own markers are incomplete.
- **Degrade, don't fail.** Plan features the tool does not recognise, such as a new action combination from a newer Terraform, make the review more cautious. They do not crash it.
- **Don't cry wolf.** A tool that flags everything gets ignored. `block` is reserved for explicit rules. Ordinary updates on resource types no rule covers are approved.
- **Few dependencies.** The standard library, `gopkg.in/yaml.v3`, and one terminal colour package (planned). No CLI framework and no graph library.

## 2. Key design decisions

These are decisions that are easy to get wrong, with the reasoning behind each.

| Decision | Reason |
|---|---|
| No `prevent_destroy` rule | `lifecycle` is not present in plan JSON. A planned destroy on a `prevent_destroy` resource makes `terraform plan` fail, so there is no plan to review. |
| Use `action_reason` and `previous_address` | `action_reason` tells tainted, cannot-update and removed-from-config apart. `previous_address` identifies resources moved with a `moved` block, which settles the "rename shows up as replace" question deterministically. |
| Dependency graph is the union of `prior_state` `depends_on` and configuration references, with provenance | Configuration references are module-scoped and unresolved. State dependencies are absolute but reflect the last apply. Neither alone is complete. |
| Rules: YAML selects, Go predicates judge | Checks such as ingress widening need CIDR and port-range logic that YAML cannot express. |
| high and medium → `needs-attention`; `block` only from explicit rules | Blocking every planned replace trains people to ignore the tool. |
| The LLM compares intent with effect instead of rating risk | The plan says what changes, not whether that was meant. Rules cannot judge intent; a model can, against a question that can be checked. |
| Redaction before anything reaches an LLM | Plan content includes account IDs, ARNs, network ranges and names that should not leave the machine unmodified. |
| `sensitive-attribute-changed` rule | A secret set to a placeholder and then changed by hand is silently reset by any write to the attribute. Plan JSON marks the attribute sensitive, so this is detectable without reading the value. |
| The LLM may only raise verdicts | This keeps the deterministic result a strict lower bound of the LLM-assisted one (section 8). |

## 3. Architecture

```
cmd/tfreview/           flag parsing, subcommand dispatch, exit codes      implemented (skeleton)
internal/plan/          plan JSON -> domain model (Change, Action, Diff)   implemented
internal/planfix/       fixture builder (test helper, produces plan JSON)  implemented
internal/rules/         YAML rules -> compiled matchers, predicate registry implemented
internal/predicates/    Go predicates referenced by rules                  implemented
internal/classify/      Change + rules -> Severity, rule match, rationale  implemented
internal/graph/         dependency edges with provenance, blast radius     planned
internal/review/        Review / Finding / Verdict types; assembles result planned
internal/render/        terminal, markdown, json                           planned
```

The optional LLM layer adds:

```
internal/intent/        loads code diff and intent text, maps hunks to addresses
internal/redact/        reversible, class-preserving placeholder substitution
internal/llm/           Provider interface; Bedrock and Anthropic implementations
internal/agent/         loop, tools, budgets
```

Pipeline:

```
plan JSON -> plan.Parse -> classify -> graph -> review.Assemble -> render
                                                     ^
             (optional) intent.Load -> redact -> agent -> unredact
```

`internal/review` owns the result types and does not know how a finding was produced. Renderers depend only on `review`. This keeps `--no-llm` structural: nothing downstream can depend on model output existing.

The CLI uses stdlib `flag` with manual subcommand dispatch. Revisit this only if a third subcommand appears.

### Usage

```bash
terraform plan -out=tfplan
terraform show -json tfplan | tfreview
tfreview --plan plan.json --format markdown
```

In CI, pipelines must run with `set -o pipefail` so a failing `terraform show` is not masked (see section 7).

## 4. Plan parsing (`internal/plan`) — implemented

### Input

- **Supported input:** `terraform show -json` output from Terraform 1.x (`format_version` 1.x), read from `--plan <file>` or stdin.
- **Version check:** a missing `format_version`, or a major version other than 1, is an input error that names the version found.
- **Empty stdin:** this is an input error (exit 3) with the message `no plan JSON on stdin; did the upstream command fail?`. An empty `--plan` file gets its own message. If stdin is an interactive terminal and no `--plan` is given, the CLI exits 3 instead of blocking.
- **Errored or partial plans:** top-level `errored: true` or `complete: false` is surfaced as a prominent warning in every output format and forces the overall verdict to at least `needs-attention`. A missing `complete` field, as in older Terraform, means complete.
- **Numbers:** JSON is decoded with `UseNumber`, so large integers keep full precision.

### Model

```go
type Action int // NoOp, Create, Read, Update, Delete, Replace, Forget, Unknown

type Change struct {
    Address             string
    PreviousAddress     string // set for moved resources
    ModuleAddress       string
    Mode                string // managed | data
    Type                string
    Name                string
    Index               any    // int, string, or nil
    ProviderName        string
    Action              Action
    RawActions          []string // original actions array, kept for Unknown
    CreateBeforeDestroy bool     // actions == ["create","delete"]
    ActionReason        string
    ReplacePaths        [][]any  // path elements are strings or ints
    Before, After       any
    AfterUnknown        any      // bool or nested mirror of After
    BeforeSensitive     any      // bool or nested mirror of Before
    AfterSensitive      any      // bool or nested mirror of After
    Deposed             string
}
```

### Action mapping

| `actions` | Action |
|---|---|
| `["no-op"]` | NoOp |
| `["create"]` | Create |
| `["read"]` | Read |
| `["update"]` | Update |
| `["delete"]` | Delete |
| `["forget"]` | Forget (Terraform 1.7+ `removed` block with `destroy = false`) |
| `["delete","create"]` | Replace |
| `["create","delete"]` | Replace, `CreateBeforeDestroy = true` |
| anything else | Unknown, with a warning; the change is kept and reviewed |

Unknown action combinations degrade the review rather than failing it, so a newer Terraform version does not break the tool. Because an unrecognised action may be destructive, an Unknown change is always `needs-attention`, regardless of rules or the `unmatched` block. The warning names the address and the raw actions.

### Marker walker

`AfterUnknown`, `BeforeSensitive` and `AfterSensitive` are each either a boolean or a nested structure mirroring the value. `plan.Marked(marks, path)` answers "is path P unknown / sensitive?" for any path:

- A literal `true` at any ancestor, including the root, marks every path beneath it.
- A path that ends on a container is **not** marked. A block where only some fields are sensitive is not itself sensitive.
- A path that runs past the end of the structure, or into a `false`, is not marked.
- Path segments are strings (object keys) or integers (list indices).

### Diff

`Change.Diff()` flattens `Before` and `After` into leaf paths such as `ingress.0.cidr_blocks.0`, sorted with list indices compared numerically (`l.2` before `l.10`). Every leaf is returned, unchanged ones included, with `Changed` computed from the raw values.

- **Rendering:** scalars render as JSON literals and empty containers as `{}` / `[]`. An empty string means the path is absent on that side.
- **Unknown values:** paths marked unknown render as `(known after apply)`, including keys that are absent from `after` but marked in `after_unknown`.
- **Sensitive values:** paths marked sensitive render as `(sensitive)`. Sensitive wins over unknown.
- **Sensitive on either side:** a path marked sensitive on either side is masked on **both** sides, as Terraform's own CLI does, so a value that just became sensitive is not shown in its old form.
- **Unmarked copies:** Terraform's markers are not complete. A sensitive value copied into another attribute can arrive unmarked; `terraform_data.output`, which echoes a sensitive `input`, is an example. Within one change, any string leaf equal to a sensitive leaf's value is therefore masked on the side where it appears. This is a heuristic: a transformed copy (hashed, encoded, interpolated) is not caught. Downstream stages must not assume markers are complete.
- **No raw values:** `DiffEntry` carries only rendered strings, never raw values, so it is safe to log or render.
- **Path format:** the dotted `Path` is for display and is ambiguous for keys containing dots (e.g. `tags.kubernetes.io/role`). Code that needs an exact path should use `Segments`.

Predicates may inspect sensitivity markers and which paths changed, but never read or emit sensitive values, so detail strings and logs cannot leak them.

### Scope

Data sources (`mode: data`) and `no-op` changes are parsed but excluded from findings by default. A `no-op` with a `PreviousAddress` (a pure move) is reported as a low-severity informational finding. A `Replace` with a `PreviousAddress` (a `moved` block that did not preserve the resource) is caught by the default `moved-then-replaced` rule in section 5.

## 5. Classification (`internal/rules`, `internal/classify`, `internal/predicates`) — implemented

The rules file is YAML. A default is embedded in the binary (`internal/rules/default.yaml`), and `--rules <file>` replaces it entirely. A rules file that fails to load is a configuration error (exit 4).

```yaml
version: 1
unmatched:
  destructive: needs-attention   # delete, replace
  other: approve                 # create, update, forget
  # Unknown actions are always needs-attention and are not configurable here.

rules:
  - id: stateful-destroy
    when:
      type_matches: [aws_db_instance, aws_rds_cluster, aws_dynamodb_table,
                     aws_s3_bucket, aws_ebs_volume, aws_efs_file_system,
                     aws_elasticache_*, aws_route53_zone]
      action_in: [delete, replace]
    severity: high
    meaning: >
      Destroys stored data unless a final snapshot or backup is configured.
      Recovery requires restore from backup.

  - id: sg-ingress-widened
    when:
      type_matches: [aws_security_group, aws_security_group_rule,
                     aws_vpc_security_group_ingress_rule]
      action_in: [create, update, replace]
      predicate: widens_network_access
    severity: high
    meaning: >
      Allows traffic from sources that could not reach this resource before.

  - id: sensitive-attribute-changed
    when:
      action_in: [update, replace]
      predicate: changes_sensitive_attribute
    severity: medium
    meaning: >
      A sensitive value is being written. If this value was set manually
      after the initial apply, this change will overwrite it. For values
      the provider cannot read back, state still holds the original
      placeholder, so a replace resets the live secret to it.
```

### Default rules

| id | Selects | Severity |
|---|---|---|
| `stateful-destroy` | stateful types (above), delete or replace | high |
| `sg-ingress-widened` | security group types, create/update/replace, `widens_network_access` | high |
| `encryption-disabled` | update or replace, `disables_encryption` | high |
| `moved-then-replaced` | replace, `was_moved` | high |
| `deletion-protection-removed` | update or replace, `removes_deletion_protection` | medium |
| `backup-retention-reduced` | update or replace, `reduces_backup_retention` | medium |
| `sensitive-attribute-changed` | update or replace, `changes_sensitive_attribute` | medium |
| `removed-from-state` | forget | medium |
| `moved` | no-op, `was_moved` (a pure move; informational) | low |
| `new-resource` | create | low |

`new-resource` is a catch-all for creates. YAML has no negation, so it cannot be restricted to non-stateful types; it does not need to be, because the highest matching severity wins (an ingress-widening create is still high). No default rule sets `verdict: block`.

### Rules file format

`when` fields (every field present must match; at least one is required):
- `type_matches`: list of type names; `*` matches any run of characters.
- `action_in`: list of `no-op`, `create`, `read`, `update`, `delete`, `replace`, `forget`. `unknown` is not selectable: Unknown actions are always needs-attention.
- `address_matches`: list of address globs. Only `*` is special; brackets are literal, so `aws_instance.web[*]` works as written.
- `predicate`: name of a registered Go predicate.

Rule fields: `id` (unique), `severity` (`high` | `medium` | `low`), `meaning`, and optional `verdict: block`. The `meaning` text explains the risk in plain language. It is shown in output and later passed to the LLM layer.

The loader rejects unknown fields, a `version` other than 1, missing or duplicate ids, invalid severities, actions or verdicts, empty lists, an empty `when`, and unknown predicate names. All problems in a file are reported together.

### Predicates

```go
type Predicate func(c plan.Change) (matched bool, detail string)
```

Predicates live in `internal/predicates` and are registered by name in `predicates.Registry()`.

**Reading values.** Predicates read attribute values only through `plan.Change.RawBefore(path)` and `RawAfter(path)`, which return `(value, ok)`. `ok` is false when:
- the path is absent on that side;
- the path is sensitive on **either** side (matching the diff's masking), or is a container with any sensitive descendant, so a secret cannot be read by asking for its parent block;
- for `RawAfter`, the value or any part of it is unknown until apply.

Structure that is not secret (which paths exist, which changed, which are sensitive, unknown or null) comes from `Change.Diff()`. `DiffEntry.BeforeNull` / `AfterNull` report a present null value, including on sensitive paths, since whether a value exists is not itself secret.

**Detail strings** name paths and, where useful, non-sensitive numbers, booleans, protocols, ports and CIDRs. They never contain a value that could be secret.

**Transitions.** Unless stated otherwise, a predicate only looks at paths whose value changed, and both sides must be readable. A value that is unknown after never matches a transition. Attributes are matched by their last path segment wherever they appear, so nested blocks (`ebs_block_device.0.encrypted`) are covered. Boolean attributes accept JSON booleans and the strings `"true"` / `"false"`, which some provider attributes use.

Registry:
- **`widens_network_access`:** covers `aws_security_group` (`ingress` blocks), `aws_security_group_rule` (`type = "ingress"` only) and `aws_vpc_security_group_ingress_rule`. A permission is a (protocol, port range, source) triple; the source is a CIDR, a security group, a prefix list or `self`.
  - **Update and replace:** true when some permission after the change is not covered by a permission before. Coverage requires the same protocol (or all protocols before), a containing port range, and a containing source: a CIDR that contains the new CIDR, the same group, prefix list or self, or `0.0.0.0/0` / `::/0` of the same family (these also cover group, prefix-list and self sources).
  - **Create:** true when any ingress allows a CIDR outside RFC 1918 / ULA private space (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), including `0.0.0.0/0` and `::/0`. Group, prefix-list and self sources are not public.
  - **Unknown values:** a source that is unknown until apply cannot be shown to be covered or private. An unknown CIDR counts as widening. An unknown security group is not public on create, but on update it is a new source. A whole `ingress` attribute or block that is unknown counts as all traffic from an unknown source.
  - **Normalisation:** protocol names and numbers are equated (`-1`/`all`, `6`/`tcp`, `17`/`udp`, `1`/`icmp`, `58`/`icmpv6`), CIDRs are masked, and ports are ignored for all-protocol rules.
  - **Detail:** lists each new permission, e.g. `new ingress: ingress.0: tcp port 22 from 0.0.0.0/0`.
- **`disables_encryption`:** true when `storage_encrypted` (RDS), `encrypted` (EBS, EFS), `at_rest_encryption_enabled` or `transit_encryption_enabled` (ElastiCache) goes true to false, or when `kms_key_id`, `kms_key_arn` or `kms_master_key_id` goes from non-empty to empty, null or removed (its block deleted). A key replaced by another key does not match. `point_in_time_recovery` is not encryption. Detail names the path.
- **`removes_deletion_protection`:** true when `deletion_protection` or `deletion_protection_enabled` (RDS, DynamoDB) or `enable_deletion_protection` (load balancers) goes true to false, or `force_destroy` (S3, ECR and others using that convention) goes false to true. The rule is medium: this is a precursor to damage, not damage.
- **`reduces_backup_retention`:** true when `backup_retention_period` or `snapshot_retention_limit` decreases numerically, when `skip_final_snapshot` or `delete_automated_backups` goes false to true, or when `point_in_time_recovery.N.enabled` goes true to false. A decrease to 0 is marked `(backups disabled)` in the detail. It is deliberately not a separate predicate or a separate high rule: the rule stays medium, and the detail tells the reviewer.
- **`changes_sensitive_attribute`:** uses sensitivity markers only and never reads values. Always false for data sources, and for actions other than update and replace.
  - **Update:** true when any changed path in the flattened diff is marked sensitive in `AfterSensitive` or `BeforeSensitive`.
  - **Replace:** true when any path is marked sensitive in `AfterSensitive` with a non-null `after` value, whether or not it changed, because a replace rewrites every attribute. This is how a forced replace resets a manually rotated password to the placeholder held in state. A sensitive value that is unknown until apply counts as non-null, since a value will be written.
  - **Write-only attributes:** for update and replace, also true when any changed path's last segment ends in `_wo_version`, with detail `<path> changed (write-only value will be rewritten)`. Write-only attributes (`*_wo`, Terraform 1.11+) are detected through this companion attribute, since the value itself is null in plan JSON.
  - **Detail string:** lists the sensitive paths by path only, never by value.
- **`was_moved`:** true when `PreviousAddress` is set, with detail `moved from <address>`. Used by the default `moved-then-replaced` rule (`action_in: [replace]`, severity high): the author used `moved` to keep the resource, and the plan destroys it anyway. Also used by the low-severity `moved` rule for pure moves.

An unknown predicate name in the rules file is a load-time error (exit 4).

### Evaluation

- **Matching:** all rules are evaluated against every change. A change takes the highest severity among the rules that match it, and every matching rule id and predicate detail is recorded, in rules-file order.
- **Exclusions:** data sources are never reviewed. No-op changes are excluded unless a rule matches them, which is how the `moved` rule reports pure moves. Every other change is kept, including unmatched changes and Unknown actions.
- **Unmatched changes:** a change no rule matches is recorded with `matched: false` and rendered with a distinct "no rule matched" marker. Its verdict comes from the `unmatched` block: destructive actions (delete, replace) default to `needs-attention`, everything else to `approve`. Ordinary updates on uncovered types therefore don't make every plan exit 1, while a delete or replace on an uncovered type still gets attention. Unmatched changes have no severity and sort after matched changes with the same verdict. Verdicts are applied by `internal/review` (section 7).

## 6. Blast radius (`internal/graph`) — planned

Edges are the union of two sources, each edge tagged with its provenance:

1. **`state`:** from the `depends_on` of resources in `prior_state`. These are absolute addresses, but they record dependencies as of the last apply, so for resources whose configuration changed they may be stale. `prior_state` is absent entirely on a first plan.
2. **`config`:** from `references` in `configuration` expressions, resolved within the module and following `module_calls` where they can be resolved. References that cannot be resolved are dropped and counted.

Edge direction: both sources yield edges from a resource to what it depends on (`B depends_on A` is stored as `B → A`). Blast radius traverses the reverse adjacency (`A → B`, from a dependency to its dependents), built once from the forward edges.

The blast radius of a change is the set of resources that transitively depend on it. It is reported as a count, the address list and a provenance breakdown, e.g. "4 dependents (3 from state as of last apply, 1 from config)". When `prior_state` is absent, the output says so.

Blast radius is computed for high and medium changes, destructive unmatched changes, and Unknown-action changes. It is implemented with adjacency maps, not a graph library.

## 7. Review, verdicts and output (`internal/review`, `internal/render`) — planned

Severity → verdict:

| Severity | Verdict |
|---|---|
| high | `needs-attention` |
| medium | `needs-attention` |
| low | `approve` |
| unmatched | from the `unmatched` block in section 5 |
| Unknown action | always `needs-attention` |

A matching rule with `verdict: block` sets the change to `block`. No default rule does this. The overall verdict is the worst across all changes (`block` > `needs-attention` > `approve`). Findings sort by verdict, then severity (unmatched last), then address.

Formats (`--format`):
- `terminal` (default): coloured and grouped by verdict, with dependents listed under each change. Colour is disabled when the output is not a TTY or `NO_COLOR` is set.
- `markdown`: for PR comments.
- `json`: a stable schema with `schema_version`.

Warnings (an errored or incomplete plan, unrecognised actions) are part of the review result, not side output:
- **`json`:** a top-level `warnings` array, plus `errored` and `complete` fields. Stdout is always exactly one JSON document, so nothing else is printed to it.
- **`terminal` and `markdown`:** warnings are printed at the top of the output, before any findings.
- **Errors:** input and configuration errors go to stderr in every format.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | approve |
| 1 | needs-attention (also: errored or incomplete plan) |
| 2 | block |
| 3 | input error (empty, unreadable or invalid plan JSON; unsupported `format_version`) |
| 4 | configuration error (invalid flags, invalid rules file, unknown predicate) |
| 5 | internal error |

Plan content is never logged at any level by default. A `--debug` flag may log structure (counts, addresses, timings) but not attribute values.

## 8. LLM layer: intent versus effect — planned, optional

The deterministic review is the product. This layer is worth building only for the misses that need judgment about intent, or about resource types no rule covers. A miss caused by a missing rule should be fixed by adding the rule.

### The question the model answers

The plan JSON shows the effect of a change, not whether it was intended. The model is given three inputs:
- the plan (the effect);
- the code diff (what the author edited);
- optionally, the PR description or commit message (what the author says they meant).

For each change, it judges whether the effect is explained by the edit. Changes it can't explain are labelled `unexpected`. Two typical catches:
- **A hidden replace.** The PR says "rename the DB instance's tag", and the diff edits a `locals` value that also feeds `identifier`. The plan replaces `aws_db_instance.main` with `replace_paths: [["identifier"]]`, and nothing in the intent mentions recreating the database.
- **An unmentioned secret write.** The PR says "bump instance size", but the plan writes `password` on `aws_db_instance.main` (flagged deterministically by `sensitive-attribute-changed`), and the diff does not touch `password`.

`replace_paths` already settles the easy half deterministically. "Replaced because of `identifier`" next to a diff that edits `identifier` on that resource is expected, with no judgment needed. The model's job is the cases where the attribute that forced the change and the edit do not line up.

### Inputs

- **The plan:** already parsed and classified, with blast radius computed.
- **Code diff:**
  - `--diff <file|->` takes a unified diff.
  - `--git-base <ref>` computes `git diff <ref> -- '*.tf' '*.tf.json'` in the working directory. The diff is taken against the working tree, which is what the plan was generated from.
  - With `--git-base`, the JSON output records the resolved base commit, `HEAD`, and `dirty: true|false` (whether tracked files in the pathspec differ from `HEAD`). A review of uncommitted changes can then never be mistaken for a review of a commit.
  - `--include-tfvars` adds `'*.tfvars' '*.tfvars.json'` to the pathspec. They are excluded by default because tfvars files carry values rather than structure, rarely explain intent, and are the most common place for plaintext secrets outside the plan's sensitivity markers. There is no automatic detection.
- **Intent text:** `--intent <text>` or `--intent-file <file>`.
- **No diff:** `--llm` without a code diff prints a warning and runs deterministically. There is no plan-only LLM mode.

### Mapping diff hunks to addresses (deterministic)

`internal/intent` finds the enclosing top-level block header for each hunk (`resource "aws_db_instance" "main"`, `module "db"`, `locals`, `variable "x"`). It uses the hunk's context lines and the `@@` function-context header, or the full file when `--git-base` makes it available.

- **Candidates:** each hunk gets candidate addresses, e.g. `aws_db_instance.main`, plus instance-qualified forms (`aws_db_instance.main[*]`) and module-qualified forms. The module prefix comes from matching the file's directory against `configuration.module_calls[].source`.
- **Indirect hunks:** hunks inside `locals`, `variable` or `output` blocks are tagged as indirect, with no candidate.
- **Hints only:** candidates are hints passed to the model, not assertions. A hunk may have several candidates or none.

Git's default hunk-header heuristic picks the nearest preceding line that starts with a letter, `$` or `_`. In `terraform fmt`-formatted HCL, attributes are indented, so that line is the top-level block header and no custom diff driver is needed. The header is accepted only if it matches a block-header pattern. Otherwise (unformatted HCL, or a header that is an attribute line), the mapper falls back to parsing the full file when `--git-base` provides it, and to no candidate when only `--diff` input is available.

### What gets sent

- **Every non-no-op change** as a compact one-line summary: address, previous address, action, action reason, `replace_paths`, rule matches, blast radius, and the diff hunks that list it as a candidate.
- **Full attribute diffs** for high, medium, unmatched and destructive changes. The model can request the full diff for any other change with a tool.
- **The code diff**, with candidate addresses per hunk.
- **The intent text.** The code diff and intent text are size-limited per file and in total.

### Addresses are not redacted

Terraform addresses and HCL block labels are **not** redacted. The model needs them to connect diff hunks to plan changes and to name changes in its output. The same names appear throughout the code diff, so redacting them consistently would mean rewriting HCL identifiers everywhere. Users must be comfortable with the configured provider seeing resource names.

Consequence for the redactor: a value exactly equal to an address segment or block label is left as it is, so the model never sees one name in two forms. The redactor's tests encode both behaviours.

### Redaction

Redaction is applied to the plan, the code diff and the intent text with one shared mapping, so the same value gets the same placeholder everywhere. Placeholders preserve the class of the value so the model can still judge it:
- **Account IDs:** replaced with `<ACCOUNT_1>`.
- **ARNs:** partition, service and resource type are kept; account and resource name are redacted (`arn:aws:rds:<REGION_1>:<ACCOUNT_1>:db:<NAME_4>`).
- **IPs and CIDRs:** `0.0.0.0/0` and `::/0` stay literal. Others are replaced with a placeholder that carries scope and prefix length, e.g. `<CIDR_3 private /16>`, `<IP_2 public>`.
- **Sensitive values:** anything marked sensitive becomes `<SENSITIVE_n>` and is never unredacted into output. This includes values caught by the echo heuristic in section 4.
- **Predicate details:** detail strings (e.g. from `widens_network_access`) pass through the same redactor, since they already contain judgments computed in the clear.

The mapping is held in memory only and applied in reverse to the model's output.

### Tools

- `get_change_detail(address)`: the full redacted before/after for one change.
- `get_module_source(address)`: offered only when `--config-dir` is given. Local modules resolve via `configuration.module_calls[].source`; registry modules resolve via `.terraform/modules/modules.json`. Output is size-limited.

### Output

The model must call `submit_review` with a strict schema: a list of labelled changes, each with `intent: expected | unexpected | unclear`, a reason, and evidence (diff hunks or attribute paths).

- **Required labels:** high, medium, unmatched and destructive changes must be labelled. The call is rejected as malformed if any of them are missing.
- **Optional labels:** other changes may be labelled, and are treated as `expected` if not.
- **Free text:** a free-text final answer is treated as malformed.

### Verdict authority: raise only

- **`unexpected`:** raises a change to `needs-attention`. It is the only label that changes a verdict.
- **`unclear`:** does not change the verdict; it is shown with its reason.
- **Adding context:** the model can add evidence and reasons to any change, and can recommend approval in its reason text.
- **Never lowering:** the model cannot lower a verdict. This keeps the `--no-llm` result a strict lower bound of the `--llm` result, which is what makes the deterministic fallback trustworthy.

Whether to allow lowering later is a question for evals: how often a lowering would have been wrong.

### Limits and failure handling

- **Budgets:** max steps, max tokens, max wall-clock time and max cost, all configurable.
- **Retries:** transient provider errors are retried with backoff.
- **Logging:** tool failure, refusal, malformed output and budget exhaustion are logged as distinct cases.
- **Fallback:** on any unrecovered failure, the deterministic review is output with a notice that the LLM layer did not complete.

### Providers

- **AWS Bedrock:** the Converse API with tool use, authenticated through the standard AWS credential chain.
- **Anthropic API:** direct, authenticated with `ANTHROPIC_API_KEY`.

The provider is selected with `--provider`. Users are responsible for making sure the provider they configure is approved for the plan content they send, even after redaction.

## 9. Testing

- **Never commit real plans.** Do not commit plan JSON generated from real infrastructure, even with values edited out. Build test plans with `internal/planfix`, or generate them locally from throwaway configurations.
- **`internal/planfix`:** builds plan JSON programmatically, including actions, before/after values, sensitivity markers, prior-state dependencies (`DependsOn`, `PriorResource`), module nesting and moved resources (`MovedFrom`). It does not import `internal/plan`, so parser tests cross the real JSON boundary. `prior_state` is emitted only when some resource existed before, which matches Terraform's behaviour on a first plan.
- **Sensitivity leaks:** fixture secrets contain the marker `SECRET`, so leak checks can search for it.
  - Every sensitivity test asserts that no rendered or formatted diff entry contains a secret.
  - `RawBefore` / `RawAfter` tests assert `ok=false` for every path the diff marks sensitive, including parents of sensitive leaves and root-literal sensitivity.
  - Every predicate test case, and the classify tests, assert that no detail string contains a secret.
- **Rules:** tests cover the embedded default set (every rule id and severity, no default `block`), each load-time error, reporting several errors at once, selector matching, and the glob matcher (including literal brackets in addresses).
- **Predicates:** every predicate gets table tests, run through `planfix` and `plan.Parse`.
  - `widens_network_access` covers:
    - CIDR containment, including unmasked CIDRs and coverage by a second rule;
    - port ranges, protocol names versus numbers, and all-protocol rules;
    - rule addition, removal and reordering;
    - creates with no `before`, including CIDRs that straddle private space;
    - IPv6, including `::/0` not being covered by `0.0.0.0/0`;
    - security groups, prefix lists and `self` as sources;
    - unknown sources and unknown `ingress`;
    - all three resource types, including egress rules being ignored.
  - `disables_encryption`, `removes_deletion_protection` and `reduces_backup_retention` cover each listed attribute, the reverse transition (no match), nested blocks, unknown after values (no match), sensitive values (never read), and for KMS keys: removal, emptying, block deletion and key rotation (no match).
  - `changes_sensitive_attribute`: the cases and expected results are in the table below.
- **Classification:** a mixed plan through the default rules checks highest-severity selection, that every match is recorded in order, the no-op and data-source exclusions, the pure-move exception, and that unmatched and Unknown changes are kept.
- **Renderers:** golden-file tests for all three; `go test -update` regenerates them.
- **Real plans as sanity checks:** plan JSON generated locally with Terraform 1.15.x checks the parser against real output.
  - Built-in `terraform_data` resources need no provider or credentials, and cover create, replace, `moved`, `forget`, `depends_on` and first-plan cases.
  - AWS-typed plans use the AWS provider with fake credentials (`skip_credentials_validation`, `skip_requesting_account_id`, `skip_metadata_api_check`). They cover creates only, since there is no real prior state.
  - **The real-plan checks therefore do not exercise any predicate on update or replace.** Those paths, including `widens_network_access` comparing before and after, are tested only through `planfix`.
- **`internal/intent`:** table tests for hunk-to-address mapping, over unified diffs. They cover plain resources, `count`, `for_each`, nested modules, hunks inside `locals`/`variable`, hunks with no enclosing block in context, and unformatted HCL whose `@@` header is an attribute line. The last case asserts the full-file fallback with `--git-base`, and no candidate without it.
- **Evals:** each case is `evals/cases/<name>/plan.json` plus `expected.yaml`: the expected verdict per change, the expected overall verdict, and required risk keywords. The runner is Go.
  - **Trap cases:** the suite includes rename-as-replace, harmless-looking ingress widening, a destructive change buried in a large plan, a metadata-only plan, and an unknown resource type.
  - **LLM cases:** these add `diff.patch` and optionally `intent.txt`, with the expected `intent` label per change. The core comparison is deterministic versus `--llm` on the same cases.
  - **The `unclear` rate:** this is tracked as a metric in its own right. A high rate means the inputs are insufficient, not that plans are risky.

`changes_sensitive_attribute` test cases:

| Case | Expected |
|---|---|
| Sensitive path changed on update | match |
| Sensitive path unchanged on update | no match |
| Replace where the sensitive value is the same before and after | match |
| Replace where the sensitive attribute is null | no match |
| Nested sensitive path inside a block | covered |
| `AfterSensitive` as a root literal `true` | covered |
| Data-source change (excluded upstream, but the predicate may still be called) | no match |
| `password_wo_version` changed on update | match; detail names the `_wo_version` path |
| `password_wo_version` unchanged on update, other non-sensitive paths changed | no match |
| Replace where the sensitive value is unknown until apply | match |
| Create (no existing secret to overwrite) | no match |
| Any case | no detail string contains a sensitive value |

Before sending a change, run:

```bash
go vet ./...
go test ./...
```

## 10. Roadmap

1. **Done:** plan parsing, fixture builder, CLI skeleton with input and errored-plan handling.
2. **Done:** `internal/rules`, `internal/predicates`, `internal/classify`, the default rules YAML with the `unmatched` block, and `--rules`.
3. `internal/graph`, `internal/review`, the three renderers, and the full set of exit codes. This is the first usable release. `planfix` gains `configuration` support (module calls, expression references) for the graph.
4. Eval cases and runner for the deterministic review.
5. Optional LLM layer: `internal/intent`, `internal/redact`, `internal/llm` (Bedrock and Anthropic), `internal/agent`, and the deterministic-versus-LLM eval comparison.

## 11. Out of scope

- **Interaction and state:** interactive prompts during a review, resumable runs, and stored review history.
- **Packaging:** release automation, a Docker image and a GitHub Action, for now.
- **Rule coverage:** rules for providers other than AWS in the default set. Contributions that add them as separate, opt-in rule files are welcome.
- **LLM behaviour:** plan-only LLM review without a code diff, and the model lowering verdicts.
- **Other tools' jobs:** a secret-pattern scan over the diff (a possible later hardening step), policy enforcement (the territory of OPA and Sentinel), and state management.
