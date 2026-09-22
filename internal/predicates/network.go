package predicates

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"tfreview/internal/plan"
)

// WidensNetworkAccess reports new ingress.
//
// For update and replace it is true when the set of allowed (protocol, port
// range, source) permissions after the change is not contained in the set
// before. For create it is true when any ingress allows a CIDR source
// outside RFC 1918 / ULA private space, including 0.0.0.0/0 and ::/0.
//
// A source that is unknown until apply cannot be shown to be covered or
// private, so it counts as widening. A security group, prefix list or self
// source is not public on create; on update it is covered only by the same
// source or by 0.0.0.0/0 or ::/0 before.
func WidensNetworkAccess(c plan.Change) (bool, string) {
	schema, ok := sgSchemas[c.Type]
	if !ok {
		return false, ""
	}
	r := newReader(c)
	after := schema.perms(r, true)

	var found []string
	switch c.Action {
	case plan.Create:
		for _, p := range after {
			if p.src.public() {
				found = append(found, p.String())
			}
		}
	case plan.Update, plan.Replace:
		before := schema.perms(r, false)
		for _, p := range after {
			if !coveredBy(p, before) {
				found = append(found, p.String())
			}
		}
	default:
		return false, ""
	}
	if len(found) == 0 {
		return false, ""
	}
	return true, "new ingress: " + strings.Join(found, "; ")
}

// sgSchema describes where one resource type keeps its ingress fields.
type sgSchema struct {
	blocks      string // list-of-blocks attribute, or "" for a single root rule
	typeField   string // "type" on aws_security_group_rule; must be "ingress"
	proto       string
	from, to    string
	cidrLists   []string
	cidrFields  []string
	groupLists  []string
	groupFields []string
	prefixLists []string
	prefixField string
	self        string
}

var sgSchemas = map[string]sgSchema{
	"aws_security_group": {
		blocks: "ingress", proto: "protocol", from: "from_port", to: "to_port",
		cidrLists:   []string{"cidr_blocks", "ipv6_cidr_blocks"},
		groupLists:  []string{"security_groups"},
		prefixLists: []string{"prefix_list_ids"},
		self:        "self",
	},
	"aws_security_group_rule": {
		typeField: "type", proto: "protocol", from: "from_port", to: "to_port",
		cidrLists:   []string{"cidr_blocks", "ipv6_cidr_blocks"},
		groupFields: []string{"source_security_group_id"},
		prefixLists: []string{"prefix_list_ids"},
		self:        "self",
	},
	"aws_vpc_security_group_ingress_rule": {
		proto: "ip_protocol", from: "from_port", to: "to_port",
		cidrFields:  []string{"cidr_ipv4", "cidr_ipv6"},
		groupFields: []string{"referenced_security_group_id"},
		prefixField: "prefix_list_id",
	},
}

func (s sgSchema) perms(r *reader, after bool) []perm {
	if s.blocks == "" {
		return s.blockPerms(r, after, nil)
	}
	root := []any{s.blocks}
	if r.unknown(root, after) {
		return []perm{unknownPerm(s.blocks)}
	}
	var out []perm
	for _, i := range r.indices(root, after) {
		block := []any{s.blocks, i}
		if r.unknown(block, after) {
			out = append(out, unknownPerm(plan.DottedPath(block)))
			continue
		}
		out = append(out, s.blockPerms(r, after, block)...)
	}
	return out
}

func (s sgSchema) blockPerms(r *reader, after bool, block []any) []perm {
	at := func(field string) []any { return append(append([]any{}, block...), field) }

	if s.typeField != "" {
		v, st := r.scalar(at(s.typeField), after)
		if st == absent || (st == known && v != "ingress") {
			return nil
		}
	}

	base := perm{where: plan.DottedPath(block), proto: "all", from: 0, to: 65535}
	if v, st := r.scalar(at(s.proto), after); st == known {
		base.proto = normProto(fmt.Sprint(v))
	} else if st == unknownValue {
		base.proto = "all"
	}
	if base.proto != "all" {
		base.from, base.to = 0, 65535
		if v, st := r.scalar(at(s.from), after); st == known {
			if n, ok := number(v, true); ok && n >= 0 {
				base.from = int(n)
			}
		}
		if v, st := r.scalar(at(s.to), after); st == known {
			if n, ok := number(v, true); ok && n >= 0 {
				base.to = int(n)
			}
		}
		if base.from > base.to {
			base.from, base.to = 0, 65535
		}
	}

	var srcs []source
	addScalar := func(field string, kind sourceKind) {
		v, st := r.scalar(at(field), after)
		switch st {
		case known:
			if s, ok := v.(string); ok && s != "" {
				srcs = append(srcs, newSource(kind, s))
			}
		case unknownValue:
			srcs = append(srcs, source{kind: kind, unknown: true})
		}
	}
	addList := func(field string, kind sourceKind) {
		vals, unknownAll := r.list(at(field), after)
		if unknownAll {
			srcs = append(srcs, source{kind: kind, unknown: true})
		}
		for _, v := range vals {
			if v.unknown {
				srcs = append(srcs, source{kind: kind, unknown: true})
			} else if s, ok := v.value.(string); ok && s != "" {
				srcs = append(srcs, newSource(kind, s))
			}
		}
	}
	for _, f := range s.cidrLists {
		addList(f, cidrSource)
	}
	for _, f := range s.cidrFields {
		addScalar(f, cidrSource)
	}
	for _, f := range s.groupLists {
		addList(f, groupSource)
	}
	for _, f := range s.groupFields {
		addScalar(f, groupSource)
	}
	for _, f := range s.prefixLists {
		addList(f, prefixSource)
	}
	if s.prefixField != "" {
		addScalar(s.prefixField, prefixSource)
	}
	if s.self != "" {
		if v, st := r.scalar(at(s.self), after); st == known && v == true {
			srcs = append(srcs, source{kind: selfSource})
		} else if st == unknownValue {
			srcs = append(srcs, source{kind: selfSource, unknown: true})
		}
	}

	out := make([]perm, 0, len(srcs))
	for _, src := range srcs {
		p := base
		p.src = src
		out = append(out, p)
	}
	return out
}

type sourceKind int

const (
	cidrSource sourceKind = iota
	groupSource
	prefixSource
	selfSource
)

type source struct {
	kind    sourceKind
	prefix  netip.Prefix // cidrSource
	id      string       // groupSource, prefixSource
	unknown bool         // value known only after apply, or unparseable
}

func newSource(kind sourceKind, s string) source {
	if kind != cidrSource {
		return source{kind: kind, id: s}
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		// A bare address is a /32 or /128.
		a, aerr := netip.ParseAddr(s)
		if aerr != nil {
			return source{kind: cidrSource, unknown: true, id: s}
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	return source{kind: cidrSource, prefix: p.Masked()}
}

var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// public reports whether a source may admit traffic from outside private
// address space. Only CIDR sources can be public.
func (s source) public() bool {
	if s.kind != cidrSource {
		return false
	}
	if s.unknown {
		return true
	}
	for _, r := range privateRanges {
		if prefixContains(r, s.prefix) {
			return false
		}
	}
	return true
}

func (s source) everything() bool {
	return s.kind == cidrSource && !s.unknown && s.prefix.Bits() == 0
}

func (s source) String() string {
	if s.unknown {
		switch s.kind {
		case groupSource:
			return "security group (known after apply)"
		case prefixSource:
			return "prefix list (known after apply)"
		case selfSource:
			return "self (known after apply)"
		}
		if s.id != "" {
			return fmt.Sprintf("unparseable CIDR %q", s.id)
		}
		return "CIDR (known after apply)"
	}
	switch s.kind {
	case groupSource:
		return "security group " + s.id
	case prefixSource:
		return "prefix list " + s.id
	case selfSource:
		return "self"
	}
	return s.prefix.String()
}

type perm struct {
	where    string // block path, e.g. ingress.0; "" for rule resources
	proto    string // "all", "tcp", "udp", "icmp", "icmpv6" or a protocol number
	from, to int
	src      source
}

func unknownPerm(where string) perm {
	return perm{where: where, proto: "all", from: 0, to: 65535, src: source{kind: cidrSource, unknown: true}}
}

func (p perm) String() string {
	ports := "all ports"
	switch {
	case p.proto == "all":
	case p.from == p.to:
		ports = fmt.Sprintf("port %d", p.from)
	case p.from != 0 || p.to != 65535:
		ports = fmt.Sprintf("ports %d-%d", p.from, p.to)
	}
	proto := p.proto
	if proto == "all" {
		proto = "all protocols"
	}
	s := fmt.Sprintf("%s %s from %s", proto, ports, p.src)
	if p.where != "" {
		s = p.where + ": " + s
	}
	return s
}

func coveredBy(p perm, before []perm) bool {
	if p.src.unknown {
		return false
	}
	for _, b := range before {
		if b.proto != "all" && b.proto != p.proto {
			continue
		}
		if b.proto != "all" && (p.from < b.from || p.to > b.to) {
			continue
		}
		if sourceCovers(b.src, p.src) {
			return true
		}
	}
	return false
}

func sourceCovers(b, a source) bool {
	if b.unknown || a.unknown {
		return false
	}
	if b.everything() {
		return a.kind != cidrSource || a.prefix.Addr().Is4() == b.prefix.Addr().Is4()
	}
	if a.kind != b.kind {
		return false
	}
	switch a.kind {
	case cidrSource:
		return prefixContains(b.prefix, a.prefix)
	case selfSource:
		return true
	}
	return a.id == b.id
}

// prefixContains reports whether outer contains all of inner.
func prefixContains(outer, inner netip.Prefix) bool {
	return outer.Addr().Is4() == inner.Addr().Is4() &&
		outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

func normProto(s string) string {
	switch strings.ToLower(s) {
	case "-1", "all":
		return "all"
	case "6", "tcp":
		return "tcp"
	case "17", "udp":
		return "udp"
	case "1", "icmp":
		return "icmp"
	case "58", "icmpv6":
		return "icmpv6"
	}
	return strings.ToLower(s)
}

// reader reads one side of a change leaf by leaf. It takes structure (which
// paths exist, which are unknown) from Diff, and values only from
// RawBefore/RawAfter, so sensitive values are never read.
type reader struct {
	c       plan.Change
	entries []plan.DiffEntry
	byPath  map[string]plan.DiffEntry
}

func newReader(c plan.Change) *reader {
	r := &reader{c: c, entries: c.Diff(), byPath: map[string]plan.DiffEntry{}}
	for _, e := range r.entries {
		r.byPath[key(e.Segments)] = e
	}
	return r
}

type leafState int

const (
	absent leafState = iota
	known
	unknownValue // unknown until apply, sensitive, or otherwise unreadable
)

func (r *reader) scalar(path []any, after bool) (any, leafState) {
	e, ok := r.byPath[key(path)]
	if !ok || !present(e, after) {
		return nil, absent
	}
	if after && e.Unknown {
		return nil, unknownValue
	}
	var v any
	if after {
		v, ok = r.c.RawAfter(path)
	} else {
		v, ok = r.c.RawBefore(path)
	}
	if !ok {
		return nil, unknownValue
	}
	return v, known
}

// unknown reports whether path itself is a single unknown leaf on that side.
func (r *reader) unknown(path []any, after bool) bool {
	e, ok := r.byPath[key(path)]
	return ok && after && e.Unknown
}

type listValue struct {
	value   any
	unknown bool
}

// list returns the elements of a list attribute. unknownAll is true when
// the whole list is unknown.
func (r *reader) list(path []any, after bool) (vals []listValue, unknownAll bool) {
	if r.unknown(path, after) {
		return nil, true
	}
	for _, i := range r.indices(path, after) {
		v, st := r.scalar(append(append([]any{}, path...), i), after)
		switch st {
		case known:
			vals = append(vals, listValue{value: v})
		case unknownValue:
			vals = append(vals, listValue{unknown: true})
		}
	}
	return vals, false
}

// indices returns the list indices directly under path present on that side.
func (r *reader) indices(path []any, after bool) []int {
	seen := map[int]bool{}
	for _, e := range r.entries {
		if len(e.Segments) <= len(path) || !present(e, after) || !hasPrefix(e.Segments, path) {
			continue
		}
		if i, ok := e.Segments[len(path)].(int); ok {
			seen[i] = true
		}
	}
	out := make([]int, 0, len(seen))
	for i := range seen {
		out = append(out, i)
	}
	sort.Ints(out)
	return out
}

func present(e plan.DiffEntry, after bool) bool {
	if after {
		return e.After != ""
	}
	return e.Before != ""
}

func hasPrefix(segs, prefix []any) bool {
	for i := range prefix {
		if segs[i] != prefix[i] {
			return false
		}
	}
	return true
}

func key(segs []any) string { return fmt.Sprintf("%#v", segs) }
