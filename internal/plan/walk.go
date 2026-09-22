package plan

import (
	"encoding/json"
	"strconv"
)

// Marked reports whether path is marked in a marker structure such as
// after_unknown, before_sensitive or after_sensitive.
//
// A marker structure is either a literal bool or a nested map/slice that
// mirrors the value it describes, with bools at the leaves. A literal true at
// any ancestor of path (including the root) marks everything beneath it.
// A path that runs past the end of the structure, or into a false or a
// container, is not marked.
//
// Path elements are strings (object keys) or integers (list indices);
// int, int64, float64 and json.Number indices are all accepted.
func Marked(marks any, path []any) bool {
	cur := marks
	for _, seg := range path {
		if b, ok := cur.(bool); ok {
			return b
		}
		switch m := cur.(type) {
		case map[string]any:
			key, ok := seg.(string)
			if !ok {
				return false
			}
			next, ok := m[key]
			if !ok {
				return false
			}
			cur = next
		case []any:
			i, ok := toIndex(seg)
			if !ok || i < 0 || i >= len(m) {
				return false
			}
			cur = m[i]
		default:
			return false
		}
	}
	b, ok := cur.(bool)
	return ok && b
}

// IsUnknown reports whether path in After is unknown until apply.
func (c Change) IsUnknown(path []any) bool { return Marked(c.AfterUnknown, path) }

// IsBeforeSensitive reports whether path in Before is sensitive.
func (c Change) IsBeforeSensitive(path []any) bool { return Marked(c.BeforeSensitive, path) }

// IsAfterSensitive reports whether path in After is sensitive.
func (c Change) IsAfterSensitive(path []any) bool { return Marked(c.AfterSensitive, path) }

func toIndex(seg any) (int, bool) {
	switch v := seg.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		if v != float64(int(v)) {
			return 0, false
		}
		return int(v), true
	case json.Number:
		i, err := strconv.Atoi(string(v))
		return i, err == nil
	}
	return 0, false
}
