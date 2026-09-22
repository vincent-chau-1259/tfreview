package plan

import "testing"

func TestMapActions(t *testing.T) {
	tests := []struct {
		actions []string
		want    Action
		cbd     bool
		ok      bool
	}{
		{[]string{"no-op"}, NoOp, false, true},
		{[]string{"create"}, Create, false, true},
		{[]string{"read"}, Read, false, true},
		{[]string{"update"}, Update, false, true},
		{[]string{"delete"}, Delete, false, true},
		{[]string{"forget"}, Forget, false, true},
		{[]string{"delete", "create"}, Replace, false, true},
		{[]string{"create", "delete"}, Replace, true, true},
		{nil, Unknown, false, false},
		{[]string{}, Unknown, false, false},
		{[]string{"teleport"}, Unknown, false, false},
		{[]string{"create", "update"}, Unknown, false, false},
		{[]string{"delete", "delete"}, Unknown, false, false},
		{[]string{"forget", "create"}, Unknown, false, false},
		{[]string{"delete", "create", "update"}, Unknown, false, false},
		{[]string{"Create"}, Unknown, false, false},
	}
	for _, tt := range tests {
		got, cbd, ok := MapActions(tt.actions)
		if got != tt.want || cbd != tt.cbd || ok != tt.ok {
			t.Errorf("MapActions(%q) = %v, %v, %v; want %v, %v, %v",
				tt.actions, got, cbd, ok, tt.want, tt.cbd, tt.ok)
		}
	}
}

func TestActionString(t *testing.T) {
	want := map[Action]string{
		NoOp: "no-op", Create: "create", Read: "read", Update: "update",
		Delete: "delete", Replace: "replace", Forget: "forget", Unknown: "unknown",
		Action(99): "unknown",
	}
	for a, s := range want {
		if a.String() != s {
			t.Errorf("Action(%d).String() = %q, want %q", int(a), a.String(), s)
		}
	}
}
