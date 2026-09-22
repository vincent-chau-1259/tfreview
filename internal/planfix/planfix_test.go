package planfix

import (
	"encoding/json"
	"reflect"
	"testing"
)

func decode(t *testing.T, p *Plan) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(p.JSON(), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestFirstPlanHasNoPriorState(t *testing.T) {
	p := New()
	p.Resource("terraform_data.a")
	if _, ok := decode(t, p)["prior_state"]; ok {
		t.Error("prior_state present on a plan with only creates")
	}
}

func TestPriorStateModulesAndDependsOn(t *testing.T) {
	p := New()
	p.Resource(`module.app["x"].module.db.aws_db_instance.main`, "update").
		Before(map[string]any{"size": "s"}).After(map[string]any{"size": "l"})
	p.Resource("aws_instance.web[0]", "update").
		Before(map[string]any{}).After(map[string]any{}).
		DependsOn(`module.app["x"].module.db.aws_db_instance.main`)
	p.Resource("aws_instance.new", "update").MovedFrom("aws_instance.old").
		Before(map[string]any{}).After(map[string]any{})
	p.PriorResource("aws_lb.front", "aws_instance.web")

	root := decode(t, p)["prior_state"].(map[string]any)["values"].(map[string]any)["root_module"].(map[string]any)

	byAddr := map[string]map[string]any{}
	for _, r := range root["resources"].([]any) {
		m := r.(map[string]any)
		byAddr[m["address"].(string)] = m
	}
	if _, ok := byAddr["aws_instance.old"]; !ok {
		t.Error("moved resource should be in prior_state at its previous address")
	}
	web := byAddr["aws_instance.web[0]"]
	if web == nil || web["index"] != float64(0) {
		t.Fatalf("aws_instance.web[0] missing or wrong index: %v", web)
	}
	if want := []any{`module.app["x"].module.db.aws_db_instance.main`}; !reflect.DeepEqual(web["depends_on"], want) {
		t.Errorf("depends_on = %v, want %v", web["depends_on"], want)
	}
	if want := []any{"aws_instance.web"}; !reflect.DeepEqual(byAddr["aws_lb.front"]["depends_on"], want) {
		t.Errorf("PriorResource depends_on = %v", byAddr["aws_lb.front"]["depends_on"])
	}

	app := root["child_modules"].([]any)[0].(map[string]any)
	if app["address"] != `module.app["x"]` {
		t.Errorf("child module address = %v", app["address"])
	}
	db := app["child_modules"].([]any)[0].(map[string]any)
	if db["address"] != `module.app["x"].module.db` {
		t.Errorf("nested module address = %v", db["address"])
	}
	if got := db["resources"].([]any)[0].(map[string]any)["address"]; got != `module.app["x"].module.db.aws_db_instance.main` {
		t.Errorf("nested resource address = %v", got)
	}
}

func TestParseAddress(t *testing.T) {
	tests := []struct {
		in     string
		module string
		mode   string
		typ    string
		name   string
		index  any
	}{
		{"aws_s3_bucket.b", "", "managed", "aws_s3_bucket", "b", nil},
		{"data.aws_ami.u", "", "data", "aws_ami", "u", nil},
		{"aws_instance.w[3]", "", "managed", "aws_instance", "w", 3},
		{`aws_instance.w["a.b"]`, "", "managed", "aws_instance", "w", "a.b"},
		{`module.m[0].module.n["k"].data.aws_iam_policy_document.p`, `module.m[0].module.n["k"]`, "data", "aws_iam_policy_document", "p", nil},
	}
	for _, tt := range tests {
		a, err := parseAddress(tt.in)
		if err != nil {
			t.Errorf("parseAddress(%q): %v", tt.in, err)
			continue
		}
		if a.module != tt.module || a.mode != tt.mode || a.typ != tt.typ || a.name != tt.name || a.index != tt.index {
			t.Errorf("parseAddress(%q) = %+v", tt.in, a)
		}
		if a.String() != tt.in {
			t.Errorf("round trip %q -> %q", tt.in, a.String())
		}
	}
	for _, bad := range []string{"aws_s3_bucket", "module.m.aws_x", `aws_x.y["open`, "a.b.c"} {
		if _, err := parseAddress(bad); err == nil {
			t.Errorf("parseAddress(%q) should fail", bad)
		}
	}
}
