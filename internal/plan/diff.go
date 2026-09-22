package plan

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// Rendered placeholders for values that are not shown.
const (
	KnownAfterApply = "(known after apply)"
	SensitiveValue  = "(sensitive)"
)

// DiffEntry is one flattened leaf path of a change's Before and After.
//
// Before and After hold rendered values only: JSON literals for scalars,
// "{}" / "[]" for empty containers, KnownAfterApply for unknown values and
// SensitiveValue for anything marked sensitive. An empty string means the
// path is absent on that side. Raw values are deliberately not exposed, so a
// DiffEntry can be logged or rendered without leaking sensitive values.
type DiffEntry struct {
	Path     string // dotted, e.g. ingress.0.cidr_blocks.0; "" for the root
	Segments []any  // the same path as strings and ints

	Before, After string

	// Changed is computed from the raw values: true when the path was added,
	// removed, became unknown, or its value differs.
	Changed bool

	Unknown         bool // After is unknown until apply
	BeforeSensitive bool
	AfterSensitive  bool

	// BeforeNull and AfterNull report a present null value. They are set
	// for sensitive paths too: whether a value exists is not itself secret.
	BeforeNull, AfterNull bool
}

// Sensitive reports whether either side of the entry is sensitive.
func (e DiffEntry) Sensitive() bool { return e.BeforeSensitive || e.AfterSensitive }

type leaf struct {
	segs      []any
	raw       any
	unknown   bool
	sensitive bool
}

// Diff flattens Before and After into leaf paths, sorted by path with list
// indices compared numerically. Unchanged paths are included with
// Changed == false.
func (c Change) Diff() []DiffEntry {
	before := flatten(c.Before, nil, c.BeforeSensitive)
	after := flatten(c.After, c.AfterUnknown, c.AfterSensitive)

	byKey := map[string]*DiffEntry{}
	var entries []*DiffEntry
	get := func(l leaf) *DiffEntry {
		k := pathKey(l.segs)
		if e, ok := byKey[k]; ok {
			return e
		}
		e := &DiffEntry{Path: DottedPath(l.segs), Segments: l.segs}
		byKey[k] = e
		entries = append(entries, e)
		return e
	}

	beforeRaw := map[string]leaf{}
	for _, l := range before {
		e := get(l)
		e.Before = render(l)
		e.BeforeNull = l.raw == nil && !l.unknown
		e.BeforeSensitive = l.sensitive
		beforeRaw[pathKey(l.segs)] = l
	}
	seenAfter := map[string]bool{}
	for _, l := range after {
		k := pathKey(l.segs)
		seenAfter[k] = true
		e := get(l)
		e.After = render(l)
		e.AfterNull = l.raw == nil && !l.unknown
		e.AfterSensitive = l.sensitive
		e.Unknown = l.unknown
		b, ok := beforeRaw[k]
		e.Changed = !ok || l.unknown || !reflect.DeepEqual(b.raw, l.raw)
	}
	for k := range beforeRaw {
		if !seenAfter[k] {
			byKey[k].Changed = true
		}
	}
	// Terraform's markers are not complete: a sensitive value copied into
	// another attribute (terraform_data.output echoing a sensitive input) can
	// arrive unmarked. Mask any string leaf equal to a sensitive leaf's value.
	secrets := map[string]bool{}
	for _, l := range append(before, after...) {
		if s, ok := l.raw.(string); ok && l.sensitive && s != "" {
			secrets[s] = true
		}
	}
	echoes := func(ls []leaf) map[string]bool {
		m := map[string]bool{}
		for _, l := range ls {
			if s, ok := l.raw.(string); ok && secrets[s] {
				m[pathKey(l.segs)] = true
			}
		}
		return m
	}
	echoBefore, echoAfter := echoes(before), echoes(after)

	// A path sensitive on either side is masked on both, as Terraform does,
	// so a value that just became sensitive is not shown in its old form.
	for _, e := range entries {
		k := pathKey(e.Segments)
		marked := e.BeforeSensitive || e.AfterSensitive
		if e.Before != "" && (marked || echoBefore[k]) {
			e.Before = SensitiveValue
		}
		if e.After != "" && (marked || echoAfter[k]) {
			e.After = SensitiveValue
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		return lessPath(entries[i].Segments, entries[j].Segments)
	})
	out := make([]DiffEntry, len(entries))
	for i, e := range entries {
		out[i] = *e
	}
	return out
}

// DottedPath joins path segments with dots.
func DottedPath(segs []any) string {
	parts := make([]string, len(segs))
	for i, s := range segs {
		parts[i] = fmt.Sprint(s)
	}
	return strings.Join(parts, ".")
}

// flatten walks v alongside its unknown and sensitive marker structures and
// returns one leaf per scalar, empty container or marked subtree.
func flatten(v, unknown, sensitive any) []leaf {
	var out []leaf
	var walk func(path []any, v, unk, sens any) int
	walk = func(path []any, v, unk, sens any) int {
		sensHere := sens == true
		if unk == true {
			out = append(out, leaf{segs: clonePath(path), unknown: true, sensitive: sensHere})
			return 1
		}
		n := 0
		switch val := v.(type) {
		case map[string]any:
			for _, k := range unionKeys(val, unk) {
				n += walk(append(path, k), val[k], child(unk, k), child(sens, k))
			}
		case []any:
			for i := 0; i < max(len(val), listLen(unk)); i++ {
				var elem any
				if i < len(val) {
					elem = val[i]
				}
				n += walk(append(path, i), elem, child(unk, i), child(sens, i))
			}
		case nil:
			// An absent value can still have unknown children.
			if m, ok := unk.(map[string]any); ok {
				for _, k := range unionKeys(nil, m) {
					n += walk(append(path, k), nil, m[k], child(sens, k))
				}
			} else if l, ok := unk.([]any); ok {
				for i := range l {
					n += walk(append(path, i), nil, l[i], child(sens, i))
				}
			}
			if n == 0 && len(path) > 0 {
				out = append(out, leaf{segs: clonePath(path), raw: nil, sensitive: sensHere})
				n = 1
			}
			return n
		default:
			out = append(out, leaf{segs: clonePath(path), raw: v, sensitive: sensHere})
			return 1
		}
		if n == 0 && len(path) > 0 {
			out = append(out, leaf{segs: clonePath(path), raw: v, sensitive: sensHere})
			n = 1
		}
		return n
	}
	walk(nil, v, unknown, sensitive)
	return out
}

// child steps into a marker structure; a literal true propagates downwards.
func child(marks any, seg any) any {
	switch m := marks.(type) {
	case bool:
		return m
	case map[string]any:
		if k, ok := seg.(string); ok {
			return m[k]
		}
	case []any:
		if i, ok := toIndex(seg); ok && i >= 0 && i < len(m) {
			return m[i]
		}
	}
	return nil
}

func unionKeys(v map[string]any, unk any) []string {
	seen := map[string]bool{}
	var keys []string
	for k := range v {
		seen[k] = true
		keys = append(keys, k)
	}
	if m, ok := unk.(map[string]any); ok {
		for k := range m {
			if !seen[k] {
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)
	return keys
}

func listLen(v any) int {
	if l, ok := v.([]any); ok {
		return len(l)
	}
	return 0
}

func clonePath(p []any) []any {
	return append([]any{}, p...)
}

func render(l leaf) string {
	switch {
	case l.sensitive:
		return SensitiveValue
	case l.unknown:
		return KnownAfterApply
	}
	switch v := l.raw.(type) {
	case nil:
		return "null"
	case string:
		return strconv.Quote(v)
	case json.Number:
		return v.String()
	case bool:
		return strconv.FormatBool(v)
	case map[string]any:
		return "{}"
	case []any:
		return "[]"
	}
	return fmt.Sprint(l.raw)
}

// pathKey is an unambiguous map key for a path, unlike the dotted form,
// which collides when object keys contain dots.
func pathKey(segs []any) string {
	var b strings.Builder
	for _, s := range segs {
		switch v := s.(type) {
		case int:
			fmt.Fprintf(&b, "[%d]", v)
		default:
			fmt.Fprintf(&b, "[%q]", v)
		}
	}
	return b.String()
}

func lessPath(a, b []any) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		ai, aInt := a[i].(int)
		bi, bInt := b[i].(int)
		switch {
		case aInt && bInt:
			if ai != bi {
				return ai < bi
			}
		case aInt != bInt:
			return aInt
		default:
			as, bs := fmt.Sprint(a[i]), fmt.Sprint(b[i])
			if as != bs {
				return as < bs
			}
		}
	}
	return len(a) < len(b)
}
