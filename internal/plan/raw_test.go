package plan_test

import (
	"encoding/json"
	"testing"

	"tfreview/internal/planfix"
)

func TestRawAccessors(t *testing.T) {
	fix := planfix.New()
	fix.Resource("aws_db_instance.main", "update").
		Before(map[string]any{
			"password":  "old-SECRET",
			"retention": 7,
			"cfg":       []any{map[string]any{"token": "t-SECRET", "port": 1}},
			"note":      nil,
			"flip":      "was-plain",
		}).
		After(map[string]any{
			"password":  "new-SECRET",
			"retention": 1,
			"cfg":       []any{map[string]any{"token": "t2-SECRET", "port": 1}},
			"note":      nil,
			"flip":      "now-SECRET",
		}).
		AfterUnknown(map[string]any{"arn": true}).
		BeforeSensitive(map[string]any{"password": true, "cfg": []any{map[string]any{"token": true}}}).
		AfterSensitive(map[string]any{"password": true, "cfg": []any{map[string]any{"token": true}}, "flip": true})
	c := singleChange(t, fix)

	tests := []struct {
		name     string
		path     []any
		before   any
		beforeOK bool
		after    any
		afterOK  bool
	}{
		{"plain number", []any{"retention"}, json.Number("7"), true, json.Number("1"), true},
		{"nested plain", []any{"cfg", 0, "port"}, json.Number("1"), true, json.Number("1"), true},
		{"present null", []any{"note"}, nil, true, nil, true},
		{"absent", []any{"nope"}, nil, false, nil, false},
		{"unknown after", []any{"arn"}, nil, false, nil, false},
		{"sensitive both sides", []any{"password"}, nil, false, nil, false},
		{"nested sensitive", []any{"cfg", 0, "token"}, nil, false, nil, false},
		{"sensitive on after only hides before too", []any{"flip"}, nil, false, nil, false},
		{"parent of a sensitive leaf", []any{"cfg"}, nil, false, nil, false},
		{"list element holding a sensitive leaf", []any{"cfg", 0}, nil, false, nil, false},
		{"root holds sensitive leaves", nil, nil, false, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, bok := c.RawBefore(tt.path)
			a, aok := c.RawAfter(tt.path)
			if bok != tt.beforeOK || b != tt.before {
				t.Errorf("RawBefore = %v, %v; want %v, %v", b, bok, tt.before, tt.beforeOK)
			}
			if aok != tt.afterOK || a != tt.after {
				t.Errorf("RawAfter = %v, %v; want %v, %v", a, aok, tt.after, tt.afterOK)
			}
		})
	}

	// Every path the diff marks sensitive must be unreadable on both sides.
	for _, e := range c.Diff() {
		if !e.Sensitive() {
			continue
		}
		if v, ok := c.RawBefore(e.Segments); ok {
			t.Errorf("RawBefore(%s) returned %v for a sensitive path", e.Path, v)
		}
		if v, ok := c.RawAfter(e.Segments); ok {
			t.Errorf("RawAfter(%s) returned %v for a sensitive path", e.Path, v)
		}
	}
}

func TestRawRootLiteralSensitive(t *testing.T) {
	fix := planfix.New()
	fix.Resource("aws_db_instance.main", "delete", "create").
		Before(map[string]any{"password": "x-SECRET", "id": "db"}).
		After(map[string]any{"password": "x-SECRET", "id": "db"}).
		BeforeSensitive(true).AfterSensitive(true)
	c := singleChange(t, fix)
	for _, p := range [][]any{nil, {"id"}, {"password"}} {
		if _, ok := c.RawBefore(p); ok {
			t.Errorf("RawBefore(%v) readable under root-literal sensitivity", p)
		}
		if _, ok := c.RawAfter(p); ok {
			t.Errorf("RawAfter(%v) readable under root-literal sensitivity", p)
		}
	}
}
