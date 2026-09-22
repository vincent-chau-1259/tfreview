package plan

// RawBefore returns the raw value at path in Before. ok is false when the
// path is absent, or when the value is sensitive or contains anything
// sensitive on either side, so a predicate can never read a secret, even by
// asking for its parent block. Numbers are json.Number.
//
// Predicates read attribute values only through RawBefore and RawAfter.
func (c Change) RawBefore(path []any) (any, bool) {
	if c.touchesSensitive(path) {
		return nil, false
	}
	return lookup(c.Before, path)
}

// RawAfter is RawBefore for After. ok is also false when the value, or any
// part of it, is unknown until apply.
func (c Change) RawAfter(path []any) (any, bool) {
	if c.touchesSensitive(path) || Marked(c.AfterUnknown, path) || anyMarkedBelow(c.AfterUnknown, path) {
		return nil, false
	}
	return lookup(c.After, path)
}

func (c Change) touchesSensitive(path []any) bool {
	for _, marks := range []any{c.BeforeSensitive, c.AfterSensitive} {
		if Marked(marks, path) || anyMarkedBelow(marks, path) {
			return true
		}
	}
	return false
}

// anyMarkedBelow reports whether the marker subtree at path contains a true.
func anyMarkedBelow(marks any, path []any) bool {
	cur := marks
	for _, seg := range path {
		cur = child(cur, seg)
	}
	return containsTrue(cur)
}

func containsTrue(marks any) bool {
	switch m := marks.(type) {
	case bool:
		return m
	case map[string]any:
		for _, v := range m {
			if containsTrue(v) {
				return true
			}
		}
	case []any:
		for _, v := range m {
			if containsTrue(v) {
				return true
			}
		}
	}
	return false
}

func lookup(v any, path []any) (any, bool) {
	cur := v
	for _, seg := range path {
		switch m := cur.(type) {
		case map[string]any:
			key, ok := seg.(string)
			if !ok {
				return nil, false
			}
			next, ok := m[key]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			i, ok := toIndex(seg)
			if !ok || i < 0 || i >= len(m) {
				return nil, false
			}
			cur = m[i]
		default:
			return nil, false
		}
	}
	return cur, true
}
