package predicates

import (
	"testing"

	"tfreview/internal/planfix"
)

// ing builds an aws_security_group ingress block.
func ing(proto string, from, to int, cidrs ...string) map[string]any {
	var v4, v6 []any
	for _, c := range cidrs {
		if len(c) > 0 && (c[0] == ':' || containsColon(c)) {
			v6 = append(v6, c)
		} else {
			v4 = append(v4, c)
		}
	}
	return map[string]any{
		"protocol": proto, "from_port": from, "to_port": to,
		"cidr_blocks": orEmptyList(v4), "ipv6_cidr_blocks": orEmptyList(v6),
		"security_groups": []any{}, "prefix_list_ids": []any{}, "self": false,
	}
}

func containsColon(s string) bool {
	for _, r := range s {
		if r == ':' {
			return true
		}
	}
	return false
}

func orEmptyList(l []any) []any {
	if l == nil {
		return []any{}
	}
	return l
}

func withSG(block map[string]any, groups ...any) map[string]any {
	block["security_groups"] = groups
	return block
}

func sg(action string, before, after []any) func(*planfix.Plan) {
	return func(p *planfix.Plan) {
		r := p.Resource("aws_security_group.web", acts(action)...)
		if before != nil {
			r.Before(map[string]any{"name": "web", "ingress": before})
		}
		if after != nil {
			r.After(map[string]any{"name": "web", "ingress": after})
		}
	}
}

// acts expands "delete-create" into a replace's two actions.
func acts(a string) []string {
	if a == "delete-create" {
		return []string{"delete", "create"}
	}
	return []string{a}
}

func blocks(b ...map[string]any) []any {
	out := make([]any, len(b))
	for i := range b {
		out[i] = b[i]
	}
	return out
}

func TestWidensNetworkAccessSecurityGroup(t *testing.T) {
	runPredicate(t, WidensNetworkAccess, []predCase{
		// CIDR containment
		{"narrower cidr is not widening", sg("update",
			blocks(ing("tcp", 443, 443, "10.0.0.0/8")),
			blocks(ing("tcp", 443, 443, "10.1.0.0/16"))), false, nil},
		{"broader cidr is widening", sg("update",
			blocks(ing("tcp", 443, 443, "10.1.0.0/16")),
			blocks(ing("tcp", 443, 443, "10.0.0.0/8"))), true, []string{"ingress.0: tcp port 443 from 10.0.0.0/8"}},
		{"harmless-looking: 10.0.0.0/8 to 0.0.0.0/0", sg("update",
			blocks(ing("tcp", 22, 22, "10.0.0.0/8")),
			blocks(ing("tcp", 22, 22, "0.0.0.0/0"))), true, []string{"tcp port 22 from 0.0.0.0/0"}},
		{"disjoint cidr is widening", sg("update",
			blocks(ing("tcp", 443, 443, "10.0.0.0/16")),
			blocks(ing("tcp", 443, 443, "10.1.0.0/16"))), true, nil},
		{"unmasked cidr is normalised", sg("update",
			blocks(ing("tcp", 443, 443, "10.0.0.0/16")),
			blocks(ing("tcp", 443, 443, "10.0.5.7/16"))), false, nil},
		{"cidr covered by a second before block", sg("update",
			blocks(ing("tcp", 443, 443, "10.0.0.0/16"), ing("tcp", 443, 443, "192.168.0.0/16")),
			blocks(ing("tcp", 443, 443, "192.168.1.0/24"))), false, nil},

		// port ranges
		{"narrower port range", sg("update",
			blocks(ing("tcp", 0, 1024, "10.0.0.0/8")),
			blocks(ing("tcp", 80, 443, "10.0.0.0/8"))), false, nil},
		{"wider port range", sg("update",
			blocks(ing("tcp", 80, 443, "10.0.0.0/8")),
			blocks(ing("tcp", 80, 8080, "10.0.0.0/8"))), true, []string{"ports 80-8080"}},
		{"different protocol", sg("update",
			blocks(ing("tcp", 53, 53, "10.0.0.0/8")),
			blocks(ing("udp", 53, 53, "10.0.0.0/8"))), true, []string{"udp port 53"}},
		{"protocol numbers normalise", sg("update",
			blocks(ing("tcp", 53, 53, "10.0.0.0/8")),
			blocks(ing("6", 53, 53, "10.0.0.0/8"))), false, nil},
		{"all traffic before covers anything", sg("update",
			blocks(ing("-1", 0, 0, "10.0.0.0/8")),
			blocks(ing("udp", 1, 65535, "10.2.0.0/16"))), false, nil},
		{"all traffic after is widening", sg("update",
			blocks(ing("tcp", 0, 65535, "10.0.0.0/8")),
			blocks(ing("-1", 0, 0, "10.0.0.0/8"))), true, []string{"all protocols all ports from 10.0.0.0/8"}},

		// addition and removal
		{"rule removed is not widening", sg("update",
			blocks(ing("tcp", 443, 443, "10.0.0.0/8"), ing("tcp", 22, 22, "10.0.0.0/8")),
			blocks(ing("tcp", 443, 443, "10.0.0.0/8"))), false, nil},
		{"all rules removed is not widening", sg("update",
			blocks(ing("tcp", 443, 443, "10.0.0.0/8")), blocks()), false, nil},
		{"rule added is widening", sg("update",
			blocks(ing("tcp", 443, 443, "10.0.0.0/8")),
			blocks(ing("tcp", 443, 443, "10.0.0.0/8"), ing("tcp", 22, 22, "10.0.0.0/8"))), true, []string{"ingress.1: tcp port 22"}},
		{"reordered rules are not widening", sg("update",
			blocks(ing("tcp", 443, 443, "10.0.0.0/8"), ing("tcp", 22, 22, "10.1.0.0/16")),
			blocks(ing("tcp", 22, 22, "10.1.0.0/16"), ing("tcp", 443, 443, "10.0.0.0/8"))), false, nil},
		{"source added to an existing rule", sg("update",
			blocks(ing("tcp", 443, 443, "10.0.0.0/8")),
			blocks(ing("tcp", 443, 443, "10.0.0.0/8", "203.0.113.0/24"))), true, []string{"203.0.113.0/24"}},
		{"replace compares like update", sg("delete-create",
			blocks(ing("tcp", 443, 443, "10.0.0.0/8")),
			blocks(ing("tcp", 443, 443, "0.0.0.0/0"))), true, nil},

		// create with no before
		{"create with private cidr", sg("create", nil,
			blocks(ing("tcp", 443, 443, "10.0.0.0/8", "172.16.0.0/12", "192.168.10.0/24"))), false, nil},
		{"create with public cidr", sg("create", nil,
			blocks(ing("tcp", 443, 443, "203.0.113.0/24"))), true, []string{"203.0.113.0/24"}},
		{"create with 0.0.0.0/0", sg("create", nil, blocks(ing("tcp", 22, 22, "0.0.0.0/0"))), true, []string{"0.0.0.0/0"}},
		{"create with cidr straddling private space", sg("create", nil, blocks(ing("tcp", 22, 22, "10.0.0.0/7"))), true, nil},
		{"create with no ingress", sg("create", nil, blocks()), false, nil},

		// IPv6
		{"create with ::/0", sg("create", nil, blocks(ing("tcp", 443, 443, "::/0"))), true, []string{"::/0"}},
		{"create with ULA", sg("create", nil, blocks(ing("tcp", 443, 443, "fd00:1::/64"))), false, nil},
		{"create with global unicast v6", sg("create", nil, blocks(ing("tcp", 443, 443, "2001:db8::/32"))), true, nil},
		{"v6 narrowing", sg("update",
			blocks(ing("tcp", 443, 443, "2001:db8::/32")),
			blocks(ing("tcp", 443, 443, "2001:db8:1::/48"))), false, nil},
		{"v6 source not covered by v4 0.0.0.0/0", sg("update",
			blocks(ing("tcp", 443, 443, "0.0.0.0/0")),
			blocks(ing("tcp", 443, 443, "0.0.0.0/0", "::/0"))), true, []string{"::/0"}},

		// security group as source
		{"create with security group source only", sg("create", nil,
			blocks(withSG(ing("tcp", 5432, 5432), "sg-app"))), false, nil},
		{"same security group source", sg("update",
			blocks(withSG(ing("tcp", 5432, 5432), "sg-app")),
			blocks(withSG(ing("tcp", 5432, 5432), "sg-app"))), false, nil},
		{"new security group source", sg("update",
			blocks(withSG(ing("tcp", 5432, 5432), "sg-app")),
			blocks(withSG(ing("tcp", 5432, 5432), "sg-app", "sg-other"))), true, []string{"security group sg-other"}},
		{"security group source replaced by cidr", sg("update",
			blocks(withSG(ing("tcp", 5432, 5432), "sg-app")),
			blocks(ing("tcp", 5432, 5432, "10.0.0.0/8"))), true, []string{"10.0.0.0/8"}},
		{"security group covered by 0.0.0.0/0 before", sg("update",
			blocks(ing("tcp", 5432, 5432, "0.0.0.0/0")),
			blocks(withSG(ing("tcp", 5432, 5432), "sg-app"))), false, nil},

		// unknown values
		{"unknown security group on create is not public", func(p *planfix.Plan) {
			b := ing("tcp", 5432, 5432)
			delete(b, "security_groups")
			p.Resource("aws_security_group.web", "create").
				After(map[string]any{"ingress": blocks(b)}).
				AfterUnknown(map[string]any{"ingress": []any{map[string]any{"security_groups": true}}})
		}, false, nil},
		{"unknown security group on update is widening", func(p *planfix.Plan) {
			b := ing("tcp", 5432, 5432)
			delete(b, "security_groups")
			p.Resource("aws_security_group.web", "update").
				Before(map[string]any{"ingress": blocks(withSG(ing("tcp", 5432, 5432), "sg-app"))}).
				After(map[string]any{"ingress": blocks(b)}).
				AfterUnknown(map[string]any{"ingress": []any{map[string]any{"security_groups": true}}})
		}, true, []string{"security group (known after apply)"}},
		{"unknown cidr on create is widening", func(p *planfix.Plan) {
			b := ing("tcp", 443, 443)
			b["cidr_blocks"] = []any{nil}
			p.Resource("aws_security_group.web", "create").
				After(map[string]any{"ingress": blocks(b)}).
				AfterUnknown(map[string]any{"ingress": []any{map[string]any{"cidr_blocks": []any{true}}}})
		}, true, []string{"CIDR (known after apply)"}},
		{"whole ingress unknown", func(p *planfix.Plan) {
			p.Resource("aws_security_group.web", "update").
				Before(map[string]any{"ingress": blocks(ing("tcp", 443, 443, "10.0.0.0/8"))}).
				After(map[string]any{}).
				AfterUnknown(map[string]any{"ingress": true})
		}, true, []string{"ingress: all protocols all ports from CIDR (known after apply)"}},
	})
}

func TestWidensNetworkAccessRuleResources(t *testing.T) {
	rule := func(action string, before, after map[string]any) func(*planfix.Plan) {
		return func(p *planfix.Plan) {
			r := p.Resource("aws_security_group_rule.r", acts(action)...)
			if before != nil {
				r.Before(before)
			}
			if after != nil {
				r.After(after)
			}
		}
	}
	sgr := func(typ string, from, to int, cidrs ...any) map[string]any {
		return map[string]any{
			"type": typ, "protocol": "tcp", "from_port": from, "to_port": to,
			"cidr_blocks": orEmptyList(cidrs), "ipv6_cidr_blocks": []any{}, "prefix_list_ids": []any{},
			"source_security_group_id": nil, "self": false,
		}
	}
	vpc := func(action string, before, after map[string]any) func(*planfix.Plan) {
		return func(p *planfix.Plan) {
			r := p.Resource("aws_vpc_security_group_ingress_rule.r", acts(action)...)
			if before != nil {
				r.Before(before)
			}
			if after != nil {
				r.After(after)
			}
		}
	}
	vr := func(proto string, from, to any, kv ...any) map[string]any {
		m := map[string]any{"ip_protocol": proto, "from_port": from, "to_port": to,
			"cidr_ipv4": nil, "cidr_ipv6": nil, "referenced_security_group_id": nil, "prefix_list_id": nil}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	runPredicate(t, WidensNetworkAccess, []predCase{
		{"sg rule create public", rule("create", nil, sgr("ingress", 22, 22, "0.0.0.0/0")), true, []string{"tcp port 22 from 0.0.0.0/0"}},
		{"sg rule create private", rule("create", nil, sgr("ingress", 22, 22, "10.0.0.0/8")), false, nil},
		{"sg rule egress is ignored", rule("create", nil, sgr("egress", 0, 65535, "0.0.0.0/0")), false, nil},
		{"sg rule widened on replace", rule("delete-create",
			sgr("ingress", 443, 443, "10.0.0.0/8"), sgr("ingress", 443, 443, "0.0.0.0/0")), true, nil},
		{"sg rule egress to ingress", rule("delete-create",
			sgr("egress", 443, 443, "0.0.0.0/0"), sgr("ingress", 443, 443, "0.0.0.0/0")), true, nil},
		{"sg rule with source security group", rule("create", nil, func() map[string]any {
			m := sgr("ingress", 5432, 5432)
			m["source_security_group_id"] = "sg-app"
			return m
		}()), false, nil},
		{"sg rule self", rule("update", sgr("ingress", 80, 80, "10.0.0.0/8"), func() map[string]any {
			m := sgr("ingress", 80, 80, "10.0.0.0/8")
			m["self"] = true
			return m
		}()), true, []string{"from self"}},

		{"vpc rule create ipv4 public", vpc("create", nil, vr("tcp", 443, 443, "cidr_ipv4", "0.0.0.0/0")), true, []string{"0.0.0.0/0"}},
		{"vpc rule create ipv6 public", vpc("create", nil, vr("tcp", 443, 443, "cidr_ipv6", "::/0")), true, []string{"::/0"}},
		{"vpc rule create private", vpc("create", nil, vr("tcp", 443, 443, "cidr_ipv4", "192.168.0.0/16")), false, nil},
		{"vpc rule all protocols with null ports", vpc("update",
			vr("tcp", 443, 443, "cidr_ipv4", "10.0.0.0/8"), vr("-1", nil, nil, "cidr_ipv4", "10.0.0.0/8")),
			true, []string{"all protocols all ports"}},
		{"vpc rule referenced group", vpc("create", nil, vr("tcp", 443, 443, "referenced_security_group_id", "sg-1")), false, nil},
		{"vpc rule prefix list changed", vpc("update",
			vr("tcp", 443, 443, "prefix_list_id", "pl-1"), vr("tcp", 443, 443, "prefix_list_id", "pl-2")),
			true, []string{"prefix list pl-2"}},
		{"vpc rule narrowed port", vpc("update",
			vr("tcp", 0, 1024, "cidr_ipv4", "10.0.0.0/8"), vr("tcp", 443, 443, "cidr_ipv4", "10.0.0.0/8")), false, nil},
		{"other types are ignored", func(p *planfix.Plan) {
			p.Resource("aws_network_acl_rule.r", "create").After(map[string]any{"cidr_block": "0.0.0.0/0"})
		}, false, nil},
		{"delete is not widening", rule("delete", sgr("ingress", 22, 22, "0.0.0.0/0"), nil), false, nil},
	})
}
