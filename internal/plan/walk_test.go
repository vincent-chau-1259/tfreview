package plan

import (
	"encoding/json"
	"testing"
)

func TestMarked(t *testing.T) {
	nested := map[string]any{
		"password": true,
		"tags":     map[string]any{},
		"ingress": []any{
			map[string]any{"cidr_blocks": []any{false, true}},
			true,
		},
		"flag": false,
	}
	tests := []struct {
		name  string
		marks any
		path  []any
		want  bool
	}{
		{"nil marks", nil, []any{"a"}, false},
		{"root true, root path", true, nil, true},
		{"root true, deep path", true, []any{"a", 0, "b"}, true},
		{"root false", false, []any{"a"}, false},
		{"root false, root path", false, nil, false},
		{"empty object", map[string]any{}, []any{"a"}, false},
		{"container at root path is not marked", nested, nil, false},
		{"leaf true", nested, []any{"password"}, true},
		{"leaf false", nested, []any{"flag"}, false},
		{"below leaf true", nested, []any{"password", "x"}, true},
		{"below leaf false", nested, []any{"flag", "x"}, false},
		{"missing key", nested, []any{"nope"}, false},
		{"empty container", nested, []any{"tags"}, false},
		{"key under empty container", nested, []any{"tags", "env"}, false},
		{"partial container", nested, []any{"ingress"}, false},
		{"list leaf false", nested, []any{"ingress", 0, "cidr_blocks", 0}, false},
		{"list leaf true", nested, []any{"ingress", 0, "cidr_blocks", 1}, true},
		{"list element true", nested, []any{"ingress", 1}, true},
		{"below list element true", nested, []any{"ingress", 1, "from_port"}, true},
		{"index out of range", nested, []any{"ingress", 5}, false},
		{"negative index", nested, []any{"ingress", -1}, false},
		{"string segment into list", nested, []any{"ingress", "0"}, false},
		{"int segment into object", nested, []any{0}, false},
		{"float64 index", nested, []any{"ingress", float64(1)}, true},
		{"json.Number index", nested, []any{"ingress", json.Number("1")}, true},
		{"int64 index", nested, []any{"ingress", int64(1)}, true},
		{"fractional index", nested, []any{"ingress", 0.5}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Marked(tt.marks, tt.path); got != tt.want {
				t.Errorf("Marked(%v, %v) = %v, want %v", tt.marks, tt.path, got, tt.want)
			}
		})
	}
}

func TestChangeMarkerMethods(t *testing.T) {
	c := Change{
		AfterUnknown:    map[string]any{"id": true},
		BeforeSensitive: map[string]any{"old": true},
		AfterSensitive:  true,
	}
	if !c.IsUnknown([]any{"id"}) || c.IsUnknown([]any{"name"}) {
		t.Error("IsUnknown mismatch")
	}
	if !c.IsBeforeSensitive([]any{"old"}) || c.IsBeforeSensitive([]any{"new"}) {
		t.Error("IsBeforeSensitive mismatch")
	}
	if !c.IsAfterSensitive([]any{"anything", 3}) {
		t.Error("IsAfterSensitive: root literal true should mark every path")
	}
}
