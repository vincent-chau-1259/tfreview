// Package planfix builds `terraform show -json` plan documents for tests.
//
// It has no dependency on internal/plan, so tests of the parser exercise the
// real JSON boundary rather than a shared struct.
//
//	p := planfix.New()
//	p.Resource("aws_db_instance.main", "delete", "create").
//		Before(map[string]any{"password": "x"}).
//		After(map[string]any{"password": "x"}).
//		AfterSensitive(map[string]any{"password": true})
//	data := p.JSON()
package planfix

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// DefaultTerraformVersion is the version recorded in generated plans.
const DefaultTerraformVersion = "1.15.4"

// Plan is a plan document under construction.
type Plan struct {
	formatVersion    string
	terraformVersion string
	errored          bool
	complete         *bool
	changes          []*Resource
	prior            []*priorResource
}

// New returns an empty, complete, non-errored plan with format_version 1.2.
func New() *Plan {
	return &Plan{formatVersion: "1.2", terraformVersion: DefaultTerraformVersion}
}

// FormatVersion overrides format_version.
func (p *Plan) FormatVersion(v string) *Plan { p.formatVersion = v; return p }

// Errored sets errored: true.
func (p *Plan) Errored() *Plan { p.errored = true; return p }

// Complete sets the complete field explicitly.
func (p *Plan) Complete(v bool) *Plan { p.complete = &v; return p }

// Resource adds a resource change. With no actions, it defaults to create.
// The address determines module_address, mode, type, name and index, e.g.
// `module.net["a"].module.sg.aws_security_group.web[0]`.
func (p *Plan) Resource(address string, actions ...string) *Resource {
	if len(actions) == 0 {
		actions = []string{"create"}
	}
	a := mustParseAddress(address)
	r := &Resource{addr: a, actions: actions, provider: defaultProvider(a.typ)}
	p.changes = append(p.changes, r)
	return r
}

// PriorResource adds a resource to prior_state without a matching change,
// for example an unchanged resource that depends on a changed one.
func (p *Plan) PriorResource(address string, dependsOn ...string) *Plan {
	a := mustParseAddress(address)
	p.prior = append(p.prior, &priorResource{
		addr: a, provider: defaultProvider(a.typ), values: map[string]any{}, dependsOn: dependsOn,
	})
	return p
}

// Resource is a resource change under construction.
type Resource struct {
	addr            address
	previousAddress string
	actions         []string
	actionReason    string
	provider        string
	deposed         string
	before, after   any
	afterUnknown    any
	beforeSensitive any
	afterSensitive  any
	replacePaths    [][]any
	dependsOn       []string
	hasDependsOn    bool
}

func (r *Resource) Before(v any) *Resource          { r.before = v; return r }
func (r *Resource) After(v any) *Resource           { r.after = v; return r }
func (r *Resource) AfterUnknown(v any) *Resource    { r.afterUnknown = v; return r }
func (r *Resource) BeforeSensitive(v any) *Resource { r.beforeSensitive = v; return r }
func (r *Resource) AfterSensitive(v any) *Resource  { r.afterSensitive = v; return r }
func (r *Resource) ActionReason(s string) *Resource { r.actionReason = s; return r }
func (r *Resource) Provider(name string) *Resource  { r.provider = name; return r }
func (r *Resource) Deposed(key string) *Resource    { r.deposed = key; return r }

// MovedFrom sets previous_address, as for a `moved` block.
func (r *Resource) MovedFrom(address string) *Resource { r.previousAddress = address; return r }

// ReplacePaths sets replace_paths; each path is a list of strings and ints.
func (r *Resource) ReplacePaths(paths ...[]any) *Resource { r.replacePaths = paths; return r }

// DependsOn records depends_on for this resource in prior_state. The resource
// only appears in prior_state if it existed before the plan (non-null Before)
// or DependsOn was called.
func (r *Resource) DependsOn(addresses ...string) *Resource {
	r.dependsOn = append(r.dependsOn, addresses...)
	r.hasDependsOn = true
	return r
}

type priorResource struct {
	addr            address
	provider        string
	values          any
	sensitiveValues any
	dependsOn       []string
}

// JSON returns the plan document. It panics if marshalling fails, which only
// happens for values encoding/json cannot represent.
func (p *Plan) JSON() []byte {
	data, err := json.MarshalIndent(p.document(), "", "  ")
	if err != nil {
		panic(fmt.Sprintf("planfix: %v", err))
	}
	return data
}

// String returns the plan document as a string.
func (p *Plan) String() string { return string(p.JSON()) }

func (p *Plan) document() map[string]any {
	doc := map[string]any{
		"format_version":    p.formatVersion,
		"terraform_version": p.terraformVersion,
		"resource_changes":  p.resourceChanges(),
		"configuration":     map[string]any{"root_module": map[string]any{}},
	}
	if p.errored {
		doc["errored"] = true
	}
	if p.complete != nil {
		doc["complete"] = *p.complete
	}
	if ps := p.priorState(); ps != nil {
		doc["prior_state"] = ps
	}
	return doc
}

func (p *Plan) resourceChanges() []any {
	out := make([]any, 0, len(p.changes))
	for _, r := range p.changes {
		change := map[string]any{
			"actions":          r.actions,
			"before":           r.before,
			"after":            r.after,
			"after_unknown":    orEmpty(r.afterUnknown),
			"before_sensitive": orFalse(r.beforeSensitive, r.before),
			"after_sensitive":  orFalse(r.afterSensitive, r.after),
		}
		if r.replacePaths != nil {
			change["replace_paths"] = r.replacePaths
		}
		rc := map[string]any{
			"address":       r.addr.String(),
			"mode":          r.addr.mode,
			"type":          r.addr.typ,
			"name":          r.addr.name,
			"provider_name": r.provider,
			"change":        change,
		}
		if r.addr.module != "" {
			rc["module_address"] = r.addr.module
		}
		if r.addr.index != nil {
			rc["index"] = r.addr.index
		}
		if r.previousAddress != "" {
			rc["previous_address"] = r.previousAddress
		}
		if r.actionReason != "" {
			rc["action_reason"] = r.actionReason
		}
		if r.deposed != "" {
			rc["deposed"] = r.deposed
		}
		out = append(out, rc)
	}
	return out
}

// orEmpty mirrors Terraform, which writes after_unknown as {} when nothing is unknown.
func orEmpty(v any) any {
	if v == nil {
		return map[string]any{}
	}
	return v
}

// orFalse mirrors Terraform's sensitivity markers: false for a null value,
// {} for an object with nothing sensitive.
func orFalse(marks, value any) any {
	if marks != nil {
		return marks
	}
	if value == nil {
		return false
	}
	return map[string]any{}
}

func (p *Plan) priorState() map[string]any {
	var resources []*priorResource
	for _, r := range p.changes {
		if r.before == nil && !r.hasDependsOn {
			continue
		}
		// A resource being moved exists in prior state at its old address.
		addr := r.addr
		if r.previousAddress != "" {
			addr = mustParseAddress(r.previousAddress)
		}
		values := r.before
		if values == nil {
			values = map[string]any{}
		}
		resources = append(resources, &priorResource{
			addr: addr, provider: r.provider, values: values,
			sensitiveValues: orFalse(r.beforeSensitive, values), dependsOn: r.dependsOn,
		})
	}
	resources = append(resources, p.prior...)
	if len(resources) == 0 {
		return nil
	}

	root := &moduleNode{children: map[string]*moduleNode{}}
	for _, r := range resources {
		n := root
		for i := range r.addr.modulePath {
			key := strings.Join(r.addr.modulePath[:i+1], ".")
			c, ok := n.children[key]
			if !ok {
				c = &moduleNode{address: key, children: map[string]*moduleNode{}}
				n.children[key] = c
			}
			n = c
		}
		n.resources = append(n.resources, r)
	}
	return map[string]any{
		"format_version":    p.formatVersion,
		"terraform_version": p.terraformVersion,
		"values":            map[string]any{"root_module": root.json()},
	}
}

type moduleNode struct {
	address   string
	resources []*priorResource
	children  map[string]*moduleNode
}

func (n *moduleNode) json() map[string]any {
	out := map[string]any{}
	if n.address != "" {
		out["address"] = n.address
	}
	if len(n.resources) > 0 {
		var rs []any
		for _, r := range n.resources {
			sv := r.sensitiveValues
			if sv == nil {
				sv = map[string]any{}
			}
			m := map[string]any{
				"address":          r.addr.String(),
				"mode":             r.addr.mode,
				"type":             r.addr.typ,
				"name":             r.addr.name,
				"provider_name":    r.provider,
				"schema_version":   0,
				"values":           r.values,
				"sensitive_values": sv,
			}
			if r.addr.index != nil {
				m["index"] = r.addr.index
			}
			if len(r.dependsOn) > 0 {
				m["depends_on"] = r.dependsOn
			}
			rs = append(rs, m)
		}
		out["resources"] = rs
	}
	if len(n.children) > 0 {
		keys := make([]string, 0, len(n.children))
		for k := range n.children {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var cs []any
		for _, k := range keys {
			cs = append(cs, n.children[k].json())
		}
		out["child_modules"] = cs
	}
	return out
}

func defaultProvider(typ string) string {
	if typ == "terraform_data" {
		return "terraform.io/builtin/terraform"
	}
	prefix, _, _ := strings.Cut(typ, "_")
	return "registry.terraform.io/hashicorp/" + prefix
}

// address is a parsed resource instance address.
type address struct {
	modulePath []string // e.g. ["module.net[\"a\"]", "module.sg"]
	module     string   // joined modulePath
	mode       string
	typ        string
	name       string
	index      any // int, string or nil
	indexText  string
}

func (a address) String() string {
	var b strings.Builder
	if a.module != "" {
		b.WriteString(a.module)
		b.WriteByte('.')
	}
	if a.mode == "data" {
		b.WriteString("data.")
	}
	b.WriteString(a.typ)
	b.WriteByte('.')
	b.WriteString(a.name)
	b.WriteString(a.indexText)
	return b.String()
}

func mustParseAddress(s string) address {
	a, err := parseAddress(s)
	if err != nil {
		panic(fmt.Sprintf("planfix: %v", err))
	}
	return a
}

// parseAddress splits an address into dot-separated steps, respecting
// brackets and quoted keys, then reads module steps, an optional data.
// prefix, the type, and the name with optional index.
func parseAddress(s string) (address, error) {
	steps, err := splitSteps(s)
	if err != nil {
		return address{}, err
	}
	var a address
	i := 0
	for i+1 < len(steps) && steps[i] == "module" {
		a.modulePath = append(a.modulePath, "module."+steps[i+1])
		i += 2
	}
	a.module = strings.Join(a.modulePath, ".")
	a.mode = "managed"
	if i < len(steps) && steps[i] == "data" {
		a.mode = "data"
		i++
	}
	if len(steps)-i != 2 {
		return address{}, fmt.Errorf("invalid resource address %q", s)
	}
	a.typ = steps[i]
	name, idx, hasIdx := strings.Cut(steps[i+1], "[")
	a.name = name
	if hasIdx {
		idx = strings.TrimSuffix(idx, "]")
		a.indexText = "[" + idx + "]"
		if n, err := strconv.Atoi(idx); err == nil {
			a.index = n
		} else if q, err := strconv.Unquote(idx); err == nil {
			a.index = q
		} else {
			return address{}, fmt.Errorf("invalid index in address %q", s)
		}
	}
	if a.typ == "" || a.name == "" {
		return address{}, fmt.Errorf("invalid resource address %q", s)
	}
	return a, nil
}

func splitSteps(s string) ([]string, error) {
	var steps []string
	var cur strings.Builder
	depth, inQuote := 0, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case inQuote:
			if c == '\\' && i+1 < len(s) {
				cur.WriteByte(c)
				i++
				c = s[i]
			} else if c == '"' {
				inQuote = false
			}
		case c == '"':
			inQuote = true
		case c == '[':
			depth++
		case c == ']':
			depth--
		case c == '.' && depth == 0:
			steps = append(steps, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if inQuote || depth != 0 {
		return nil, fmt.Errorf("unbalanced address %q", s)
	}
	return append(steps, cur.String()), nil
}
